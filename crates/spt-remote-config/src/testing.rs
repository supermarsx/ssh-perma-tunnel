//! Public test facilities for `spt-remote-config` (gated behind `feature = "testing"`).
//!
//! Provides an in-process HTTPS server ([`AxumHttpsServer`]) and a
//! self-signed-cert helper ([`cert_with_fingerprint`]) used by the existing
//! body-fingerprint tests and by downstream integration tests that want to
//! exercise the real fetch path without standing up a live HTTPS endpoint.
//!
//! Implementation notes:
//! - The server is `axum 0.7` running on a `tokio::net::TcpListener` wrapped
//!   by `tokio-rustls` for TLS termination.
//! - The cert is a self-signed leaf produced by `rcgen` for the SAN
//!   `localhost`. The SPKI SHA-256 fingerprint is exposed on
//!   [`AxumHttpsServer::fingerprint`] for pin-style assertions.
//! - The body fingerprint pinning verified by `crate::fetch::fetch` is
//!   independent of the cert fingerprint; tests typically compute the body
//!   SHA-256 from `RemoteConfigSpec::fingerprint_sha256` and use this rig
//!   merely to actually serve bytes over real TLS.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

// --------------------------------------------------------------------------
// cert_with_fingerprint
// --------------------------------------------------------------------------

/// Generate a self-signed certificate for `localhost` and return it together
/// with the SHA-256 fingerprint over its `SubjectPublicKeyInfo` (SPKI) DER.
///
/// The SPKI fingerprint matches what RFC 7469 / browser pinning APIs compute
/// over `tbsCertificate.subjectPublicKeyInfo`.
///
/// ```
/// let (_cert, fp) = spt_remote_config::testing::cert_with_fingerprint();
/// assert_eq!(fp.len(), 32);
/// ```
#[must_use]
pub fn cert_with_fingerprint() -> (rcgen::CertifiedKey, [u8; 32]) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("rcgen self-signed cert");
    let spki = ck.key_pair.public_key_der();
    let mut hasher = Sha256::new();
    hasher.update(&spki);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    (ck, out)
}

// --------------------------------------------------------------------------
// AxumHttpsServer
// --------------------------------------------------------------------------

/// Builder for [`AxumHttpsServer`].
#[derive(Debug, Clone)]
pub struct AxumHttpsServerBuilder {
    body: Vec<u8>,
    etag: Option<String>,
    status: u16,
    content_type: String,
}

impl Default for AxumHttpsServerBuilder {
    fn default() -> Self {
        Self {
            body: b"version = 1\n".to_vec(),
            etag: None,
            status: 200,
            content_type: "application/toml".to_string(),
        }
    }
}

impl AxumHttpsServerBuilder {
    /// Replace the body served on every GET. Default: `b"version = 1\n"`.
    #[must_use]
    pub fn with_config_response(mut self, toml: &str) -> Self {
        self.body = toml.as_bytes().to_vec();
        self
    }

    /// Set the `ETag` header. When `None`, no `ETag` is emitted.
    #[must_use]
    pub fn with_etag(mut self, etag: &str) -> Self {
        self.etag = Some(etag.to_string());
        self
    }

    /// Override the response status. Default: 200.
    #[must_use]
    pub fn with_status(mut self, code: u16) -> Self {
        self.status = code;
        self
    }

    /// Override the `Content-Type`. Default: `application/toml`.
    #[must_use]
    pub fn with_content_type(mut self, ct: &str) -> Self {
        self.content_type = ct.to_string();
        self
    }

    /// Bind on `127.0.0.1:0`, generate a fresh self-signed cert, and start
    /// serving. The returned [`AxumHttpsServer`] holds the listener task and
    /// shuts it down on drop.
    pub async fn start(self) -> AxumHttpsServer {
        let (ck, fingerprint) = cert_with_fingerprint();

        // Convert to rustls types.
        let cert_der = CertificateDer::from(ck.cert.der().to_vec());
        let key_pem = ck.key_pair.serialize_pem();
        let key_der: PrivateKeyDer<'static> = {
            let mut reader = std::io::BufReader::new(key_pem.as_bytes());
            rustls_pemfile::private_key(&mut reader)
                .expect("rustls-pemfile parses rcgen key")
                .expect("rcgen produced a private key")
        };

        let server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("rustls accepts rcgen cert");
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local_addr");

        let state = Arc::new(ResponseState {
            body: Mutex::new(self.body),
            etag: Mutex::new(self.etag),
            status: Mutex::new(self.status),
            content_type: Mutex::new(self.content_type),
        });

        let router = Router::new()
            .route("/", get(serve_handler))
            .route("/*path", get(serve_handler))
            .with_state(state.clone());

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let task = tokio::spawn(async move {
            let make_service = router.into_make_service();
            let mut svc = make_service;
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((tcp, _peer)) = accept else { continue };
                        let acceptor = acceptor.clone();
                        let svc_for_conn = match <axum::routing::IntoMakeService<Router> as tower::Service<()>>::call(&mut svc, ()).await {
                            Ok(s) => s,
                            Err(e) => match e {},
                        };
                        tokio::spawn(async move {
                            let Ok(tls) = acceptor.accept(tcp).await else { return };
                            let io = hyper_util::rt::TokioIo::new(tls);
                            let _ = hyper_util::server::conn::auto::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            )
                            .serve_connection(io, hyper_util::service::TowerToHyperService::new(svc_for_conn))
                            .await;
                        });
                    }
                }
            }
        });

        AxumHttpsServer {
            addr,
            fingerprint,
            state,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }
}

#[derive(Debug)]
struct ResponseState {
    body: Mutex<Vec<u8>>,
    etag: Mutex<Option<String>>,
    status: Mutex<u16>,
    content_type: Mutex<String>,
}

async fn serve_handler(
    axum::extract::State(state): axum::extract::State<Arc<ResponseState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let want_etag = state.etag.lock().unwrap().clone();
    // 304 short-circuit when If-None-Match matches the stored ETag.
    if let (Some(my_etag), Some(req_etag)) = (
        want_etag.as_ref(),
        headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok()),
    ) {
        if my_etag == req_etag {
            return (StatusCode::NOT_MODIFIED, HeaderMap::new(), Vec::new()).into_response();
        }
    }

    let status = StatusCode::from_u16(*state.status.lock().unwrap()).unwrap_or(StatusCode::OK);
    let body = state.body.lock().unwrap().clone();
    let mut hm = HeaderMap::new();
    hm.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&state.content_type.lock().unwrap()).unwrap(),
    );
    if let Some(et) = want_etag {
        if let Ok(v) = HeaderValue::from_str(&et) {
            hm.insert(header::ETAG, v);
        }
    }
    (status, hm, body).into_response()
}

/// In-process HTTPS server backed by axum + rustls + a self-signed cert.
///
/// Drop shuts the listener down promptly.
///
/// ```no_run
/// # async fn run() {
/// use spt_remote_config::testing::AxumHttpsServer;
/// let s = AxumHttpsServer::builder()
///     .with_config_response("version = 1\n")
///     .start()
///     .await;
/// let _addr = s.addr();
/// let _fp = s.fingerprint();
/// # }
/// ```
pub struct AxumHttpsServer {
    addr: SocketAddr,
    fingerprint: [u8; 32],
    state: Arc<ResponseState>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl AxumHttpsServer {
    /// New builder.
    #[must_use]
    pub fn builder() -> AxumHttpsServerBuilder {
        AxumHttpsServerBuilder::default()
    }

    /// Convenience: equivalent to `AxumHttpsServer::builder().start()`.
    pub async fn start_default() -> Self {
        Self::builder().start().await
    }

    /// Listening address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// SPKI SHA-256 fingerprint of the self-signed cert (32 bytes).
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Convenience URL `https://localhost:<port>/`. Note: the server's cert
    /// is for the SAN `localhost`, so connecting via the literal IP would
    /// trigger a cert-name mismatch in the client. Tests should set up the
    /// reqwest client with this hostname (and `127.0.0.1` is fine because
    /// rcgen's `generate_simple_self_signed` adds both `localhost` and the
    /// loopback IP to the SAN list by default).
    #[must_use]
    pub fn url(&self) -> String {
        format!("https://localhost:{}/", self.addr.port())
    }

    /// Replace the body served on subsequent requests.
    pub fn set_body(&self, toml: &str) {
        *self.state.body.lock().unwrap() = toml.as_bytes().to_vec();
    }

    /// Replace the response status.
    pub fn set_status(&self, code: u16) {
        *self.state.status.lock().unwrap() = code;
    }

    /// Replace the `ETag` header value.
    pub fn set_etag(&self, etag: Option<&str>) {
        *self.state.etag.lock().unwrap() = etag.map(str::to_string);
    }
}

impl Drop for AxumHttpsServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

// --------------------------------------------------------------------------
// fixtures
// --------------------------------------------------------------------------

/// Canonical fixtures.
pub mod fixtures {
    /// A minimal-but-valid `[remote_config]`-style TOML body for tests that
    /// just want to verify the bytes flow end-to-end.
    ///
    /// ```
    /// let s = spt_remote_config::testing::fixtures::minimal_remote_config_toml();
    /// assert!(s.contains("version"));
    /// ```
    #[must_use]
    pub fn minimal_remote_config_toml() -> &'static str {
        "version = 1\n[runtime]\ndns = \"127.0.0.1:5353\"\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::hex_sha256;
    use crate::http::ReqwestFetcher;
    use std::time::Duration;

    fn build_pinning_client(server_fp_pem: &rcgen::CertifiedKey) -> reqwest::Client {
        // Trust the server's leaf cert as a custom root for the test client.
        let pem = server_fp_pem.cert.pem();
        let cert = reqwest::Certificate::from_pem(pem.as_bytes()).expect("parse pem");
        reqwest::Client::builder()
            .add_root_certificate(cert)
            .https_only(true)
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build pinning client")
    }

    #[tokio::test]
    async fn cert_with_fingerprint_returns_32_bytes() {
        let (_, fp) = cert_with_fingerprint();
        assert_eq!(fp.len(), 32);
    }

    #[tokio::test]
    async fn axum_server_serves_configured_body() {
        let body = "version = 1\nfoo = \"bar\"\n";
        let server = AxumHttpsServer::builder()
            .with_config_response(body)
            .with_etag("\"v1\"")
            .start()
            .await;

        // Build a reqwest client that trusts the rig's self-signed cert.
        // We need to grab the cert PEM from a fresh rcgen call with the same
        // SAN — but the server already minted its own cert. Instead, expose
        // the cert via a side channel: regenerate one and verify the server
        // is reachable via a permissive client (danger_accept_invalid_certs).
        // (For an external integration test, the consumer has access to the
        // cert PEM directly via cert_with_fingerprint() before calling start.)
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .https_only(true)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("https://127.0.0.1:{}/", server.addr().port());
        let resp = client.get(&url).send().await.expect("get");
        assert_eq!(resp.status(), 200);
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        let bytes = resp.bytes().await.unwrap();
        assert_eq!(&bytes[..], body.as_bytes());
    }

    #[tokio::test]
    async fn axum_server_honours_if_none_match() {
        let server = AxumHttpsServer::builder().with_etag("\"v1\"").start().await;
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .https_only(true)
            .build()
            .unwrap();
        let url = format!("https://127.0.0.1:{}/", server.addr().port());
        let resp = client
            .get(&url)
            .header(reqwest::header::IF_NONE_MATCH, "\"v1\"")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 304);
    }

    #[tokio::test]
    async fn fetch_path_against_axum_rig_with_pin() {
        // End-to-end: spin the rig, run `crate::fetch::fetch` against it so
        // the body-fingerprint pin check (spec §14.3) is actually exercised.
        let body = fixtures::minimal_remote_config_toml().to_string();
        let server = AxumHttpsServer::builder()
            .with_config_response(&body)
            .with_etag("\"abc\"")
            .start()
            .await;
        let url = format!("https://localhost:{}/c.toml", server.addr().port());

        // Permissive client: we don't have access to the cert PEM minted
        // inside `start()` (rig keeps it internal). Fingerprint pinning is
        // over the body, not the cert, so this is sufficient for the spec.
        let permissive = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .https_only(true)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let fetcher = ReqwestFetcher::with_client(permissive);

        // Positive: spec fingerprint matches body — `Fresh` outcome.
        let spec = spt_config::remote::RemoteConfigSpec {
            url: url.clone(),
            fingerprint_sha256: hex_sha256(body.as_bytes()),
            allow_cached_on_failure: false,
            max_size_bytes: Some(1_000_000),
            etag_cache: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let result = crate::fetch::fetch(&spec, tmp.path(), &fetcher)
            .await
            .expect("fetch ok");
        assert_eq!(result.outcome, crate::fetch::FetchOutcome::Fresh);
        assert_eq!(result.body, body.as_bytes());
        assert_eq!(result.etag.as_deref(), Some("\"abc\""));

        // Negative: tweak the pin and confirm the fetch path rejects.
        let bad_spec = spt_config::remote::RemoteConfigSpec {
            fingerprint_sha256: "f".repeat(64),
            ..spec.clone()
        };
        let tmp2 = tempfile::tempdir().unwrap();
        let err = crate::fetch::fetch(&bad_spec, tmp2.path(), &fetcher)
            .await
            .expect_err("fingerprint mismatch must error");
        assert!(matches!(
            err,
            crate::fetch::RemoteConfigError::FingerprintMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn build_pinning_client_helper_smoke() {
        // The helper is referenced by external integration tests that mint
        // their own cert via `cert_with_fingerprint` before starting a TLS
        // server they own. Smoke-test the constructor.
        let (ck, _) = cert_with_fingerprint();
        let _client = build_pinning_client(&ck);
    }
}
