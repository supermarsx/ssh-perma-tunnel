//! Inline-host wiring for the read-only HTTP/JSON status API, including
//! the optional TLS / mTLS path.
//!
//! Closes the deferred gate described in `.orchestration/logs/t4-Bwire.md`:
//! the original integration shipped a plain-HTTP-only path that hard-rejected
//! `[status_api.tls].enabled = true` and `auth.mode = "mtls"` with an
//! `InvalidConfig` error. This module replaces that gate with a real
//! `tokio_rustls`-based acceptor that consumes the `rustls::ServerConfig`
//! already built by [`spt_status_api::build_server_config`] and the
//! `PeerIdentity` request-extension contract already defined in
//! [`spt_status_api::auth`].
//!
//! ## Entry points
//!
//! * [`launch`] — single async function called from every call site
//!   (`cli_dispatch::tunnel_run`, `scm_dispatch::run_orchestrator_under_scm`,
//!   `cli::status_ops::serve`). Branches on `cfg.status_api.tls.enabled`:
//!     * **Plain HTTP** (existing behavior) — delegates to
//!       [`spt_status_api::StatusApiServer::start`] so the wire format is
//!       byte-identical to the t4-Bwire shipped path.
//!     * **TLS / mTLS** (new path) — binds the listener, builds the rustls
//!       config, wraps in a `TlsAcceptor`, and spawns an accept loop that
//!       performs the handshake, extracts the verified client-cert subject
//!       DN via `x509-parser`, threads it into the request as a
//!       [`PeerIdentity`] extension, and serves the router via
//!       `hyper_util::server::conn::auto`.
//!
//! ## Why this lives in `spt-bin` and not `spt-status-api`
//!
//! `spt-status-api`'s public API exposes the rustls `ServerConfig` builder
//! and the `PeerIdentity` extension shape but does not consume them — by
//! design, so the crate stays decoupled from a specific hyper version.
//! The supervisor integration layer (this module) bridges those two
//! contracts. See `.orchestration/logs/t4-e5.md` "Deviations" §2 and §3.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use spt_config::{StatusApiAuthMode, StatusApiConfig};
use spt_core::{Error, Result};
use spt_secrets::Resolver;
use spt_status_api::{
    AppState, AuthContext, PeerIdentity, RateLimitConfig, RateLimiter, StateSnapshotSource,
    StatusApiHandle, StatusApiServer,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// Aggregate handle returned by [`launch`]. The plain variant simply forwards
/// to the existing inline handle; the TLS variant owns its own accept loop +
/// shutdown channel.
pub enum SptStatusApiHandle {
    /// Plain-HTTP path — re-uses [`spt_status_api::StatusApiHandle`].
    Plain(StatusApiHandle),
    /// TLS / mTLS path — accept loop spawned by this module.
    Tls {
        /// Bound socket address (post-`port = 0` resolution).
        bound_addr: SocketAddr,
        /// Channel used to signal the accept loop to stop.
        shutdown_tx: Option<oneshot::Sender<()>>,
        /// `JoinHandle` of the accept loop task.
        join: Option<JoinHandle<()>>,
    },
}

impl SptStatusApiHandle {
    /// Address the server is actually listening on.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Plain(h) => h.local_addr(),
            Self::Tls { bound_addr, .. } => *bound_addr,
        }
    }

    /// Signal graceful shutdown and await the server task.
    pub async fn shutdown(self) {
        match self {
            Self::Plain(h) => h.shutdown().await,
            Self::Tls {
                mut shutdown_tx,
                mut join,
                ..
            } => {
                if let Some(tx) = shutdown_tx.take() {
                    let _ = tx.send(());
                }
                if let Some(j) = join.take() {
                    let _ = j.await;
                }
            }
        }
    }
}

/// Bring up the inline status-api host, choosing plain HTTP or TLS based
/// on configuration. Replaces the legacy `ensure_tls_not_requested` gate.
///
/// Errors:
/// * `InvalidConfig` if `auth.mode = "mtls"` is set without
///   `[status_api.tls].enabled = true` (mTLS without TLS is nonsense).
/// * `InvalidConfig` if the TCP bind fails, the cert/key load fails, or
///   the rustls config fails to assemble.
pub async fn launch(
    cfg: &StatusApiConfig,
    source: Arc<dyn StateSnapshotSource>,
    resolver: &Resolver,
) -> Result<SptStatusApiHandle> {
    // Sanity gate: mTLS requires TLS.
    if !cfg.tls.enabled && matches!(cfg.auth.mode, StatusApiAuthMode::MutualTls { .. }) {
        return Err(Error::InvalidConfig(
            "status_api: auth.mode = \"mtls\" requires tls.enabled = true".into(),
        ));
    }

    if !cfg.tls.enabled {
        // Plain HTTP — delegate to the existing helper. Behavior identical to
        // the path shipped by t4-Bwire so existing
        // `auth.mode = "none" | "bearer" | "basic"` deployments are byte-stable.
        let handle = StatusApiServer::start(cfg, source, resolver).await?;
        return Ok(SptStatusApiHandle::Plain(handle));
    }

    launch_tls(cfg, source, resolver).await
}

/// TLS / mTLS branch of [`launch`]. Builds the rustls config, binds, and
/// spawns the accept loop.
async fn launch_tls(
    cfg: &StatusApiConfig,
    source: Arc<dyn StateSnapshotSource>,
    resolver: &Resolver,
) -> Result<SptStatusApiHandle> {
    // Install the rustls crypto provider — idempotent across the process.
    // The supervisor may already have done this for other rustls users
    // (spt-ssh3, spt-remote-config). `install_default` returns `Err` if a
    // provider is already installed; we don't care which one wins.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Build the rustls ServerConfig.
    let server_cfg =
        spt_status_api::build_server_config(&cfg.tls, &cfg.auth.mode).map_err(map_tls_err)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    // Auth + rate-limit machinery (mirrors `StatusApiServer::start`).
    let auth_ctx = Arc::new(AuthContext::from_config(&cfg.auth, resolver)?);
    let limiter = RateLimiter::new(RateLimitConfig::from_rps(cfg.rate_limit_rps));
    let state = AppState::new(source, cfg.expose_metrics);
    let router = StatusApiServer::router(state, auth_ctx, limiter);

    // Bind the TCP listener.
    let listener = TcpListener::bind(cfg.bind).await.map_err(|e| {
        Error::InvalidConfig(format!("status_api: bind to {} failed: {e}", cfg.bind))
    })?;
    let bound_addr = listener
        .local_addr()
        .map_err(|e| Error::InvalidConfig(format!("status_api: local_addr: {e}")))?;

    let mtls = matches!(cfg.auth.mode, StatusApiAuthMode::MutualTls { .. });
    info!(addr = %bound_addr, mtls = mtls, "status-api listening (TLS)");

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        accept_loop(listener, acceptor, router, mtls, &mut shutdown_rx).await;
    });

    Ok(SptStatusApiHandle::Tls {
        bound_addr,
        shutdown_tx: Some(shutdown_tx),
        join: Some(join),
    })
}

/// Per-connection accept loop. Exits when `shutdown_rx` resolves. Spawned
/// connection tasks are detached — they observe their own connection close
/// when the TLS layer drops the socket on shutdown.
async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: axum::Router,
    mtls: bool,
    shutdown_rx: &mut oneshot::Receiver<()>,
) {
    use axum::extract::Request;
    use hyper::body::Incoming;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;
    use tower::ServiceExt;

    // Convert into a `MakeService` so each connection gets a freshly-cloned
    // `Router` service (matches `axum::serve`'s default model and the pattern
    // already used in `spt-remote-config::testing::AxumHttpsServer`).
    let mut make_svc = router.into_make_service();

    loop {
        tokio::select! {
            _ = &mut *shutdown_rx => {
                debug!("status-api TLS accept loop: shutdown received");
                break;
            }
            accept = listener.accept() => {
                let (tcp, peer) = match accept {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "status-api TLS accept failed");
                        continue;
                    }
                };
                // Obtain a per-connection service from the MakeService. The
                // `()`-call cannot fail (axum's IntoMakeService<Router> is
                // infallible), so the match-on-Infallible pattern below is
                // exhaustive.
                let svc: axum::Router = match <axum::routing::IntoMakeService<axum::Router>
                    as tower::Service<()>>::call(&mut make_svc, ())
                    .await
                {
                    Ok(s) => s,
                    Err(never) => match never {},
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(tcp).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(peer = %peer, error = %e, "status-api TLS handshake failed");
                            return;
                        }
                    };

                    // Extract verified peer identity (if any). The TLS layer
                    // (WebPkiClientVerifier) has already enforced presence +
                    // CA trust when `mtls` is set; the auth layer then matches
                    // the subject DN against the allow-list.
                    let peer_id = {
                        let (_io, conn) = tls_stream.get_ref();
                        extract_peer_identity(conn)
                    };

                    if mtls && peer_id.is_none() {
                        // Defense-in-depth: WebPkiClientVerifier should already
                        // have rejected this handshake.
                        warn!(peer = %peer, "status-api mTLS: no peer certificate after handshake");
                        return;
                    }

                    // Per-connection wrapper: convert hyper's Incoming body
                    // into axum's body type and insert the PeerIdentity
                    // extension before delegating to the Router.
                    let svc_for_conn = svc.map_request(move |req: hyper::Request<Incoming>| {
                        let mut axum_req: Request = req.map(axum::body::Body::new);
                        if let Some(id) = peer_id.clone() {
                            axum_req.extensions_mut().insert(id);
                        }
                        axum_req
                    });

                    let io = TokioIo::new(tls_stream);
                    if let Err(e) = Builder::new(TokioExecutor::new())
                        .serve_connection(io, TowerToHyperService::new(svc_for_conn))
                        .await
                    {
                        debug!(peer = %peer, error = %e, "status-api TLS connection ended");
                    }
                });
            }
        }
    }
}

/// Pull the verified client certificate (if any) out of the rustls
/// `ServerConnection` and parse the Subject DN via `x509-parser`. Returns
/// `None` for connections without a client cert (server-only TLS) and for
/// handshakes whose leaf certificate fails to parse.
fn extract_peer_identity(conn: &rustls::ServerConnection) -> Option<PeerIdentity> {
    use x509_parser::prelude::*;

    let certs = conn.peer_certificates()?;
    let leaf = certs.first()?;
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).ok()?;
    let subject_dn = parsed.subject().to_string();
    Some(PeerIdentity { subject_dn })
}

/// Translate the typed [`spt_status_api::TlsConfigError`] into the
/// supervisor's `InvalidConfig` flavour with the file path attached.
fn map_tls_err(e: spt_status_api::TlsConfigError) -> Error {
    Error::InvalidConfig(format!("status_api TLS: {e}"))
}

// ---------------------------------------------------------------------------
// Convenience adapter: callers in cli_dispatch / scm_dispatch / status_ops
// pass `Arc<dyn StateSnapshotSource>`. We re-export the FileSnapshotSource
// builder here so each call site doesn't have to reach back into
// `cli::status_ops`. The actual type lives in `cli::status_ops` for backwards
// compatibility with t4-Bwire wiring.
// ---------------------------------------------------------------------------

/// Build the file-backed snapshot source over `state_dir`.
#[must_use]
pub fn file_snapshot_source(state_dir: PathBuf) -> Arc<dyn StateSnapshotSource> {
    Arc::new(crate::cli::status_ops::FileSnapshotSource::new(state_dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_config::{StatusApiAuthConfig, StatusApiAuthMode, StatusApiTlsConfig};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    fn empty_resolver() -> Resolver {
        // The Resolver is only consulted for Bearer / Basic modes; for the
        // tests below we never reach that branch, so an empty-backend resolver
        // suffices.
        Resolver::new(Vec::new())
    }

    fn cfg_with_auth(tls_enabled: bool, auth: StatusApiAuthMode) -> StatusApiConfig {
        StatusApiConfig {
            enabled: true,
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            read_only: true,
            expose_metrics: true,
            rate_limit_rps: 1.0,
            tls: StatusApiTlsConfig {
                enabled: tls_enabled,
                cert_file: PathBuf::new(),
                key_file: PathBuf::new(),
            },
            auth: StatusApiAuthConfig { mode: auth },
        }
    }

    #[tokio::test]
    async fn mtls_without_tls_rejected() {
        let cfg = cfg_with_auth(
            false,
            StatusApiAuthMode::MutualTls {
                ca_bundle: PathBuf::from("/no/such/ca.pem"),
                allowed_subjects: vec!["CN=prom".into()],
            },
        );
        let src: Arc<dyn StateSnapshotSource> = Arc::new(spt_status_api::InMemorySource::new());
        let result = launch(&cfg, src, &empty_resolver()).await;
        let err = match result {
            Ok(_) => panic!("expected InvalidConfig error, got Ok"),
            Err(e) => e,
        };
        match err {
            Error::InvalidConfig(msg) => {
                assert!(msg.contains("mtls"), "msg={msg}");
                assert!(msg.contains("tls.enabled"), "msg={msg}");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bad_cert_file_cites_path() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = StatusApiConfig {
            tls: StatusApiTlsConfig {
                enabled: true,
                cert_file: PathBuf::from("/no/such/cert.pem"),
                key_file: PathBuf::from("/no/such/key.pem"),
            },
            ..cfg_with_auth(true, StatusApiAuthMode::None)
        };
        let src: Arc<dyn StateSnapshotSource> = Arc::new(spt_status_api::InMemorySource::new());
        let result = launch(&cfg, src, &empty_resolver()).await;
        let err = match result {
            Ok(_) => panic!("expected InvalidConfig error, got Ok"),
            Err(e) => e,
        };
        match err {
            Error::InvalidConfig(msg) => {
                assert!(msg.contains("cert.pem"), "expected path in msg, got: {msg}");
            }
            other => panic!("expected InvalidConfig with cert path, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // End-to-end integration tests.
    //
    // Each test mints fresh certs via `rcgen` (workspace dev-dep, also used by
    // `spt-status-api`'s own handshake test), spawns the inline status-api
    // host via `launch`, connects with a `tokio-rustls` client + minimal
    // HTTP/1.1 request, and inspects the response. We never depend on
    // `reqwest` here — the workspace doesn't want to pull additional client
    // crates into spt-bin's dev-deps.
    // -----------------------------------------------------------------------

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    struct TestCa {
        cert: rcgen::Certificate,
        key_pair: rcgen::KeyPair,
    }

    impl TestCa {
        fn new() -> Self {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "spt-test-ca");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let key_pair = rcgen::KeyPair::generate().unwrap();
            let cert = params.self_signed(&key_pair).unwrap();
            Self { cert, key_pair }
        }
        fn pem(&self) -> String {
            self.cert.pem()
        }
    }

    fn make_server_cert(ca: &TestCa) -> (rcgen::Certificate, rcgen::KeyPair) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key_pair, &ca.cert, &ca.key_pair).unwrap();
        (cert, key_pair)
    }

    fn make_client_cert(ca: &TestCa, cn: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key_pair, &ca.cert, &ca.key_pair).unwrap();
        (cert, key_pair)
    }

    fn write_pair(
        tmp: &tempfile::TempDir,
        prefix: &str,
        cert: &rcgen::Certificate,
        key: &rcgen::KeyPair,
    ) -> (PathBuf, PathBuf) {
        let cert_path = tmp.path().join(format!("{prefix}.cert.pem"));
        let key_path = tmp.path().join(format!("{prefix}.key.pem"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    async fn http_get_via_tls(
        connector: &TlsConnector,
        addr: SocketAddr,
        host: &str,
        path: &str,
    ) -> (u16, String) {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let dns = ServerName::try_from(host.to_string()).unwrap();
        let mut tls = connector.connect(dns, tcp).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = tls.read_to_end(&mut buf).await;
        parse_http_response(&buf)
    }

    fn parse_http_response(buf: &[u8]) -> (u16, String) {
        let text = String::from_utf8_lossy(buf).to_string();
        // Parse status line: "HTTP/1.1 200 OK\r\n..."
        let status: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    fn plain_client_for_ca(ca_pem: &str) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        let mut reader = std::io::Cursor::new(ca_pem.as_bytes());
        for der in rustls_pemfile::certs(&mut reader) {
            roots.add(der.unwrap()).unwrap();
        }
        let cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(cfg))
    }

    fn mtls_client(
        ca_pem: &str,
        client_cert: &rcgen::Certificate,
        client_key: &rcgen::KeyPair,
    ) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        let mut reader = std::io::Cursor::new(ca_pem.as_bytes());
        for der in rustls_pemfile::certs(&mut reader) {
            roots.add(der.unwrap()).unwrap();
        }
        let cert_chain: Vec<CertificateDer<'static>> = vec![client_cert.der().clone()];
        let key_pem = client_key.serialize_pem();
        let mut key_reader = std::io::Cursor::new(key_pem.as_bytes());
        let key_der: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
            .unwrap()
            .unwrap();
        let cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(cert_chain, key_der)
            .unwrap();
        TlsConnector::from(Arc::new(cfg))
    }

    #[tokio::test]
    async fn plain_http_health_still_works() {
        // Regression: the non-TLS path must continue to function identically.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = cfg_with_auth(false, StatusApiAuthMode::None);
        let src: Arc<dyn StateSnapshotSource> = Arc::new(spt_status_api::InMemorySource::new());
        let handle = launch(&cfg, src, &empty_resolver()).await.unwrap();
        let addr = handle.local_addr();

        // Plain HTTP GET.
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tcp.read_to_end(&mut buf).await;
        let (status, _body) = parse_http_response(&buf);
        assert_eq!(status, 200, "plain HTTP /v1/health expected 200");

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn tls_health_returns_200() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = tempfile::tempdir().unwrap();
        let ca = TestCa::new();
        let (srv_cert, srv_key) = make_server_cert(&ca);
        let (cert_path, key_path) = write_pair(&tmp, "srv", &srv_cert, &srv_key);

        let cfg = StatusApiConfig {
            tls: StatusApiTlsConfig {
                enabled: true,
                cert_file: cert_path,
                key_file: key_path,
            },
            ..cfg_with_auth(true, StatusApiAuthMode::None)
        };
        let src: Arc<dyn StateSnapshotSource> = Arc::new(spt_status_api::InMemorySource::new());
        let handle = launch(&cfg, src, &empty_resolver()).await.unwrap();
        let addr = handle.local_addr();

        let connector = plain_client_for_ca(&ca.pem());
        let (status, _body) = http_get_via_tls(&connector, addr, "localhost", "/v1/health").await;
        assert_eq!(status, 200, "TLS /v1/health expected 200");

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn mtls_allowed_subject_returns_200() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = tempfile::tempdir().unwrap();
        let ca = TestCa::new();
        let (srv_cert, srv_key) = make_server_cert(&ca);
        let (cert_path, key_path) = write_pair(&tmp, "srv", &srv_cert, &srv_key);
        let ca_path = tmp.path().join("ca.pem");
        std::fs::write(&ca_path, ca.pem()).unwrap();

        // Client cert with CN that we'll add to the allow-list. The
        // x509-parser DN string for `CN=prom.internal` typically renders as
        // `CN=prom.internal`. We assert via a round-trip below.
        let (cli_cert, cli_key) = make_client_cert(&ca, "prom.internal");
        let dn = extract_peer_identity_from_der(cli_cert.der().as_ref())
            .expect("cert parses")
            .subject_dn;

        let cfg = StatusApiConfig {
            tls: StatusApiTlsConfig {
                enabled: true,
                cert_file: cert_path,
                key_file: key_path,
            },
            auth: StatusApiAuthConfig {
                mode: StatusApiAuthMode::MutualTls {
                    ca_bundle: ca_path,
                    allowed_subjects: vec![dn],
                },
            },
            ..cfg_with_auth(true, StatusApiAuthMode::None)
        };
        let src: Arc<dyn StateSnapshotSource> = Arc::new(spt_status_api::InMemorySource::new());
        let handle = launch(&cfg, src, &empty_resolver()).await.unwrap();
        let addr = handle.local_addr();

        let connector = mtls_client(&ca.pem(), &cli_cert, &cli_key);
        let (status, _body) = http_get_via_tls(&connector, addr, "localhost", "/v1/health").await;
        assert_eq!(
            status, 200,
            "mTLS /v1/health expected 200 for allowed subject"
        );

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn mtls_unknown_subject_rejected() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = tempfile::tempdir().unwrap();
        let ca = TestCa::new();
        let (srv_cert, srv_key) = make_server_cert(&ca);
        let (cert_path, key_path) = write_pair(&tmp, "srv", &srv_cert, &srv_key);
        let ca_path = tmp.path().join("ca.pem");
        std::fs::write(&ca_path, ca.pem()).unwrap();

        // Client cert whose CN is NOT in the allow-list — TLS handshake
        // succeeds (CA-signed) but the auth layer must return 403.
        let (cli_cert, cli_key) = make_client_cert(&ca, "interloper");

        let cfg = StatusApiConfig {
            tls: StatusApiTlsConfig {
                enabled: true,
                cert_file: cert_path,
                key_file: key_path,
            },
            auth: StatusApiAuthConfig {
                mode: StatusApiAuthMode::MutualTls {
                    ca_bundle: ca_path,
                    // Different CN -> mismatch.
                    allowed_subjects: vec!["CN=prom.internal".into()],
                },
            },
            ..cfg_with_auth(true, StatusApiAuthMode::None)
        };
        let src: Arc<dyn StateSnapshotSource> = Arc::new(spt_status_api::InMemorySource::new());
        let handle = launch(&cfg, src, &empty_resolver()).await.unwrap();
        let addr = handle.local_addr();

        let connector = mtls_client(&ca.pem(), &cli_cert, &cli_key);
        let (status, _body) = http_get_via_tls(&connector, addr, "localhost", "/v1/health").await;
        assert!(
            status == 403 || status == 401,
            "mTLS rejected subject expected 401/403, got {status}"
        );

        handle.shutdown().await;
    }

    /// Helper that mirrors the runtime `extract_peer_identity` path but takes
    /// raw DER — useful for asserting what `subject_dn` rendering the test
    /// machinery will produce for an rcgen-minted cert.
    fn extract_peer_identity_from_der(der: &[u8]) -> Option<PeerIdentity> {
        use x509_parser::prelude::*;
        let (_, parsed) = X509Certificate::from_der(der).ok()?;
        Some(PeerIdentity {
            subject_dn: parsed.subject().to_string(),
        })
    }
}
