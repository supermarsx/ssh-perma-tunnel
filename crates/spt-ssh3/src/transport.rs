//! QUIC + HTTP/3 + Extended-CONNECT bootstrap for the SSH3 session.
//!
//! Flow (per draft-michel-remote-terminal-http3-00 §3 and the
//! francoismichel/ssh3 prototype):
//!
//! 1. Build a [`quinn::Endpoint::client`] bound to `0.0.0.0:0` (or `[::]:0`),
//!    install the rustls config from [`crate::tls::build_client_config`], and
//!    set ALPN = `h3`.
//! 2. Connect to the endpoint host/port; read the negotiated TLS certificate.
//! 3. Construct an [`h3-quinn`] connection on top.
//! 4. Issue an HTTP/3 **Extended CONNECT** request with `:method = CONNECT`,
//!    `:protocol = ssh3`, `:scheme = https`, `:authority = host:port`,
//!    `:path = url_path`, plus `Authorization: <Bearer|Basic> ...`.
//! 5. Require `:status` to be `2xx`; otherwise fail with [`Error::AuthFailed`]
//!    (401/403) or [`Error::RuntimeFailure`] (other).
//!
//! After the CONNECT 200 the bidi stream of that request is the SSH3 control
//! channel. Wiring the per-forward channel framing on top is delegated to
//! `session.rs` / `forward.rs` (see partial-real status notes there).
//!
//! # `:protocol = ssh3` — raw HTTP/3 bootstrap path
//!
//! RFC 9220 (Extended CONNECT over HTTP/3) defines the `:protocol`
//! pseudo-header as the wire mechanism for upgrading a CONNECT into a
//! protocol-specific bidi stream. The `francoismichel/ssh3` Go reference
//! server expects `:protocol = ssh3` exactly — no other identifier matches.
//!
//! The `h3` crate at the version we are pinned to (`=0.0.8`) exposes
//! Extended CONNECT support via a *closed* `h3::ext::Protocol` enum whose
//! only variants are `WEB_TRANSPORT` and `CONNECT_UDP` (see
//! `~/.cargo/registry/src/.../h3-0.0.8/src/ext.rs:9-31`). There is no
//! public constructor for an arbitrary `:protocol` string and no way to
//! attach the pseudo-header to an outbound `Request` via
//! `http::Request::extensions_mut` that h3 0.0.8 will honor. The work to
//! make `Protocol` an open type landed only after the 0.0.8 cut; bumping
//! past `=0.0.8` cascades a `quinn` major-version change that breaks our
//! MSRV-1.83 floor and is therefore explicitly forbidden by the project
//! quality bar.
//!
//! **We bypass `h3` for the Extended-CONNECT bootstrap.** See
//! `crate::h3_raw` for the minimal QPACK + HTTP/3-HEADERS implementation
//! that emits the `:protocol = ssh3` pseudo-header natively over a raw
//! `quinn::Connection` bidi stream. The `h3` client driver still runs on
//! the same QUIC connection so that the peer's HTTP/3 stack sees a normal
//! client control stream + SETTINGS handshake; we only take over the
//! request stream itself.
//!
//! For belt-and-suspenders interop with any pre-existing responder that
//! was keyed on the prior `X-Ssh3-Protocol` mirror, the raw path *also*
//! emits that custom header alongside the pseudo-header. The
//! [`build_connect_request`] function below still exists and is the
//! authoritative source for the request shape (consumed by the test
//! `build_connect_request_has_protocol_extension_and_bearer` so the header
//! contract is pinned in two places).
//!
//! The unit test
//! `extended_connect_raw_emits_protocol_ssh3_pseudo_header_to_a_fake_server`
//! in this module spins up a quinn server, accepts the bootstrap bidi,
//! decodes the QPACK-encoded HEADERS frame on the wire, and asserts the
//! decoded `:protocol` pseudo-header value is exactly `ssh3`.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderValue, Method, Request, Uri};
use quinn::{ClientConfig as QuinnClientConfig, Endpoint, TransportConfig};
use spt_auth::AuthConfig;
use spt_core::{DnsResolution, Error, Result};
use tracing::{info, warn};

use crate::auth_header::build_authorization_header_for;
use crate::config::Ssh3Config;
use crate::tls::build_client_config;

/// Outcome of a successful Extended CONNECT bootstrap.
///
/// The QUIC connection and the h3 driver/SendRequest are owned by the live
/// session; consumers in `session.rs` can move them into the
/// [`crate::session::Ssh3Session`] for later use.
pub struct BootstrappedSession {
    /// Live QUIC connection (still open after CONNECT 200).
    pub connection: quinn::Connection,
    /// HTTP status code returned for the CONNECT.
    pub status: u16,
    /// Server identification string, if any (`Server` header value).
    pub peer_version: Option<String>,
    /// Negotiated TLS protocol description (suite name, ALPN, etc.).
    pub negotiated: Option<String>,
    /// Control-stream send half (SSH3 control frames travel here).
    pub control_send: quinn::SendStream,
    /// Control-stream recv half.
    pub control_recv: quinn::RecvStream,
    /// Peer-advertised settings (from the first frame on the control stream).
    pub peer_settings: crate::frame::Ssh3Settings,
    /// Driver task handle for the h3 connection (so the session can `.abort()`
    /// on close).
    pub h3_driver: tokio::task::JoinHandle<()>,
}

/// Resolve the endpoint host:port to a `SocketAddr`, honoring the configured
/// DNS resolution policy.
///
/// [`DnsResolution::PerAttempt`] (default) resolves fresh via the OS resolver —
/// byte-for-byte the prior behaviour. [`DnsResolution::Once`] resolves once per
/// `(host, port)` through the shared [`spt_core::dns`] cache and pins the
/// result across reconnects.
fn resolve_addr(host: &str, port: u16, policy: DnsResolution) -> Result<SocketAddr> {
    let addrs = spt_core::resolve_dns(host, port, policy)
        .map_err(|e| Error::DnsFailed(format!("ssh3 resolve `{host}:{port}`: {e}")))?;
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| Error::DnsFailed(format!("ssh3: no addresses resolved for `{host}`")))
}

/// Build a [`quinn::Endpoint`] suitable for an outbound QUIC connection.
fn build_quinn_endpoint(remote: SocketAddr, cfg: &Ssh3Config) -> Result<Endpoint> {
    let bind: SocketAddr = if remote.is_ipv6() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    };
    let mut endpoint = Endpoint::client(bind)
        .map_err(|e| Error::RuntimeFailure(format!("ssh3: bind QUIC client socket: {e}")))?;

    let tls = build_client_config(&cfg.tls)?;
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| Error::RuntimeFailure(format!("ssh3: rustls→quic config: {e}")))?;
    let mut client_cfg = QuinnClientConfig::new(Arc::new(quic_tls));

    let mut transport = TransportConfig::default();
    if cfg.keepalive_secs > 0 {
        transport.keep_alive_interval(Some(Duration::from_secs(u64::from(cfg.keepalive_secs))));
    }
    // Optional max-idle-timeout. Left at the quinn default when unset
    // (behaviour-preserving). A value that cannot be represented as a quinn
    // `IdleTimeout` (overflow) is a config error.
    if let Some(secs) = cfg.idle_timeout_secs {
        let dur = Duration::from_secs(u64::from(secs));
        let idle = quinn::IdleTimeout::try_from(dur).map_err(|e| {
            Error::InvalidConfig(format!("ssh3: idle_timeout_secs={secs} out of range: {e}"))
        })?;
        transport.max_idle_timeout(Some(idle));
    }
    // Optional cap on concurrent peer-opened bidi streams. Left at the quinn
    // default when unset (behaviour-preserving).
    if let Some(max) = cfg.max_streams {
        transport.max_concurrent_bidi_streams(quinn::VarInt::from(max));
    }
    // Datagrams gate the UDP-forward substrate. Today they are implicitly
    // enabled by quinn's defaults; make the disable case explicit while leaving
    // the enabled case on the quinn default (behaviour-preserving). Setting the
    // receive buffer to `None` advertises (via transport params) that we will
    // not accept datagrams, so the peer's `max_datagram_size()` resolves to
    // `None` and UDP forwards surface `UnsupportedPlatform`.
    if !cfg.enable_datagrams {
        transport.datagram_receive_buffer_size(None);
    }
    client_cfg.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

/// Construct the HTTP/3 Extended CONNECT [`Request`] for the SSH3 session.
///
/// **Historical / reference path.** Since the
/// raw HTTP/3 bootstrap (`crate::h3_raw`) landed, the live wire request is
/// emitted by `crate::h3_raw::extended_connect_raw` — not by feeding
/// this `Request` to `h3::client::SendRequest::send_request`. This helper
/// is retained because:
///
/// * The unit tests
///   `build_connect_request_has_protocol_extension_and_bearer`,
///   `build_connect_request_basic_auth`,
///   `build_connect_request_publickey_path_produces_bearer_jwt`, and
///   `build_connect_request_pins_spt_user_agent` use it to pin the
///   authorization-header derivation, user-agent shape, and URI building
///   that `extended_connect_raw` also relies on.
/// * The `x-ssh3-protocol` header it emits documents (and tests) the
///   backward-compat X-header that the raw path now ships alongside the
///   `:protocol = ssh3` pseudo-header.
pub fn build_connect_request(
    host: &str,
    port: u16,
    url_path: &str,
    auth: &AuthConfig,
) -> Result<Request<()>> {
    let auth_header = build_authorization_header_for(auth, host, port, url_path)?;
    let authority = format!("{host}:{port}");
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query(url_path)
        .build()
        .map_err(|e| Error::InvalidConfig(format!("ssh3 build CONNECT URI: {e}")))?;
    let mut req = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&auth_header)
                .map_err(|e| Error::InvalidConfig(format!("ssh3 auth header: {e}")))?,
        )
        .header(
            http::header::USER_AGENT,
            HeaderValue::from_static(concat!("spt/", env!("CARGO_PKG_VERSION"))),
        )
        .body(())
        .map_err(|e| Error::InvalidConfig(format!("ssh3 build CONNECT request: {e}")))?;
    // Extended CONNECT: the `:protocol` pseudo-header travels via extensions.
    // GAP: h3 0.0.8's `Protocol` is a closed enum (only "webtransport" and
    // "connect-udp"); it has no public constructor for the SSH3 reference
    // server's required `:protocol = ssh3` pseudo-header. To carry SSH3
    // semantics on the wire we ship a parallel `X-Ssh3-Protocol` header
    // that the francoismichel/ssh3 reference can be patched to honor, and
    // we keep `:method = CONNECT` plus the `:authority` / `:path`
    // pseudo-headers per RFC 9220. A future h3 release with arbitrary
    // protocol-string support — or our own raw HTTP/3 framing — is the
    // correct fix. Tracked as TODO(spec-clarify) in the README.
    req.headers_mut()
        .insert("x-ssh3-protocol", HeaderValue::from_static("ssh3"));
    Ok(req)
}

/// Format the canonical negotiated-crypto token string for an ssh3 session.
///
/// Contract (shared with the consumer-side parser in `spt-status-api`):
/// space-separated `key=value` tokens, the `transport=` token first, absent
/// params omitted, values contain no spaces.
///
/// ssh3 surfaces exactly: `transport=ssh3 tls_version=TLS1.3 alpn=<alpn> sni=<host>`.
///
/// `cipher_suite` and `kex_group` are INTENTIONALLY absent — they are NOT
/// reachable through quinn 0.11's public API. quinn only surfaces
/// [`quinn::Connection::handshake_data`] → [`quinn::crypto::rustls::HandshakeData`],
/// whose only fields are `protocol` (ALPN) and `server_name`. The underlying
/// rustls `Connection` — which *does* expose `negotiated_cipher_suite()` and
/// `negotiated_key_exchange_group()` — is never handed out by quinn, so those
/// values cannot be read here. They are left unset by design; this is a quinn
/// API limitation, not a crypto-provider choice (no provider change is made).
/// `tls_version=TLS1.3` is a safe constant: QUIC mandates TLS 1.3 (RFC 9001).
fn format_ssh3_negotiated(alpn: Option<&str>, sni: &str) -> String {
    let mut s = String::from("transport=ssh3 tls_version=TLS1.3");
    if let Some(alpn) = alpn.filter(|a| !a.is_empty()) {
        s.push_str(" alpn=");
        s.push_str(alpn);
    }
    s.push_str(" sni=");
    s.push_str(sni);
    s
}

/// Establish a QUIC + HTTP/3 + Extended-CONNECT session against the SSH3 peer.
///
/// On success, returns the bootstrapped session metadata. On failure, returns
/// the most informative error variant (DNS / Trust / Auth / Runtime).
pub async fn bootstrap(
    host: &str,
    port: u16,
    cfg: &Ssh3Config,
    auth: &AuthConfig,
) -> Result<BootstrappedSession> {
    let remote = resolve_addr(host, port, cfg.dns)?;
    let endpoint = build_quinn_endpoint(remote, cfg)?;

    let server_name = cfg.sni.clone().unwrap_or_else(|| host.to_string());
    let connecting = endpoint
        .connect(remote, &server_name)
        .map_err(|e| Error::RuntimeFailure(format!("ssh3: quinn::connect: {e}")))?;
    let connection = connecting.await.map_err(map_connection_error)?;
    info!(
        target: "spt_ssh3::transport",
        endpoint = %format!("{host}:{port}"),
        remote = %remote,
        server_name = %server_name,
        "ssh3 QUIC connection established"
    );

    // Read the reachable TLS parameters from quinn's handshake data. quinn 0.11
    // only surfaces `HandshakeData { protocol (ALPN), server_name }` — the rustls
    // `Connection` (and thus `negotiated_cipher_suite()` /
    // `negotiated_key_exchange_group()`) is never exposed by quinn, so
    // cipher_suite/kex_group are unavailable BY DESIGN (see
    // `format_ssh3_negotiated`). `HandshakeData.server_name` is always `None` for
    // outgoing connections, so we use the SNI/host computed above. No
    // crypto-provider change is involved.
    let alpn = connection
        .handshake_data()
        .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|hd| hd.protocol)
        .map(|p| String::from_utf8_lossy(&p).into_owned());
    info!(
        target: "spt::crypto_negotiated",
        transport = "ssh3",
        tls_version = "TLS1.3",
        alpn = %alpn.as_deref().unwrap_or(""),
        sni = %server_name,
        "negotiated ssh3 crypto"
    );

    // Spin up the h3 client driver on a clone of the QUIC connection. We do
    // NOT use it to issue the Extended-CONNECT request — h3 0.0.8 cannot
    // emit `:protocol = ssh3` (see module docs). The driver's job here is
    // to send the HTTP/3 client control stream + SETTINGS frame so the
    // peer's HTTP/3 stack is satisfied. The CONNECT itself goes via
    // [`h3_raw::extended_connect_raw`] on a separate raw bidi stream.
    let h3_conn = h3_quinn::Connection::new(connection.clone());
    let (driver, send_request) = h3::client::new(h3_conn)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3: h3 client init: {e}")))?;
    // CRITICAL: the h3 layer is vestigial for spt after the CONNECT handshake —
    // the CONNECT itself goes via [`h3_raw`] on a raw bidi and every forward
    // rides a raw QUIC stream, so the `h3::client` machinery is never used to
    // issue a request. Two h3 behaviours would otherwise tear the QUIC
    // connection down out from under our raw streams, and BOTH must be
    // suppressed for the connection's lifetime:
    //
    //  1. `h3::client::SendRequest` closes the connection with `H3_NO_ERROR`
    //     the moment its last clone drops (documented on the type) — so we must
    //     keep `send_request` alive.
    //  2. Driving `driver.poll_close` to completion makes the h3 `Connection`
    //     gracefully close the QUIC connection (observed as `LocallyClosed`).
    //     This races against an *idle* client: a forward that opens a raw bidi
    //     promptly wins, but a client that merely waits for the server to
    //     open back-channels (e.g. a `remote`/`remote_uds` forward) loses and
    //     the connection self-closes. We therefore must NOT poll the driver to
    //     completion — we just hold both `driver` and `send_request` alive,
    //     parked on `pending()`, until `Ssh3Session::close()` aborts the task.
    //     Our raw QUIC streams operate independently of the unpolled h3 driver.
    let driver_task = tokio::spawn(async move {
        // Hold BOTH alive (dropping either closes the QUIC connection) without
        // driving the driver to completion. Parked on `pending()` until
        // `Ssh3Session::close()` aborts the task.
        let _keep_alive = (send_request, driver);
        std::future::pending::<()>().await;
    });
    // C1: from here on, ANY early `?` return or cancellation of this future must
    // abort the parked driver task and release the QUIC connection. The guard
    // does exactly that on drop; it is disarmed only on the successful `Ok` path
    // below, where ownership transfers into the returned `BootstrappedSession`.
    let guard = BootstrapGuard::new(driver_task, connection.clone());

    let auth_header =
        crate::auth_header::build_authorization_header_for(auth, host, port, &cfg.url_path)?;
    let user_agent = concat!("spt/", env!("CARGO_PKG_VERSION"));
    let raw = crate::h3_raw::extended_connect_raw(
        &connection,
        host,
        port,
        &cfg.url_path,
        &auth_header,
        user_agent,
        cfg.protocol_token_value(),
    )
    .await
    .map_err(|e| match e {
        Error::AuthFailed(_) | Error::RuntimeFailure(_) | Error::TrustFailed(_) => e,
        other => Error::RuntimeFailure(format!("ssh3: raw CONNECT: {other}")),
    })?;
    let status = raw.status;
    let peer_version = raw.peer_version;
    // The raw CONNECT bidi is discarded immediately — spt's wire contract
    // uses a separate dedicated control bidi (see [`open_control_stream`]).
    drop(raw.send);
    drop(raw.recv);
    if !(200..300).contains(&status) {
        // `guard` drops here → aborts the driver task + closes the connection.
        warn!(
            target: "spt_ssh3::transport",
            endpoint = %format!("{host}:{port}"),
            status,
            "ssh3 CONNECT refused by peer"
        );
        let body = format!("ssh3: CONNECT returned HTTP {status}");
        return Err(if matches!(status, 401 | 403) {
            Error::AuthFailed(body)
        } else {
            Error::RuntimeFailure(body)
        });
    }
    // Canonical negotiated-crypto token string (consumed by spt-status-api's
    // `NegotiatedCrypto::parse`). cipher_suite/kex_group are omitted: unavailable
    // via quinn 0.11's public API (see `format_ssh3_negotiated`).
    let negotiated = Some(format_ssh3_negotiated(alpn.as_deref(), &server_name));

    // Open the SSH3 control bidi stream and exchange `Settings` frames. We
    // run on a fresh raw QUIC stream (bypassing h3) — the spt↔spt
    // channel-framing contract is documented in `forward.rs`.
    let (control_send, control_recv, peer_settings) =
        open_control_stream(&connection, default_local_settings()).await?;

    info!(
        target: "spt_ssh3::transport",
        endpoint = %format!("{host}:{port}"),
        status,
        peer_version = ?peer_version,
        direct_tcp = peer_settings.direct_tcp,
        remote_tcp = peer_settings.remote_tcp,
        udp_datagrams = peer_settings.udp_datagrams,
        max_forwards = ?peer_settings.max_forwards,
        "ssh3 CONNECT + control-stream handshake complete"
    );

    // SUCCESS: transfer ownership of the driver handle + connection into the
    // session and disarm the guard so it no longer aborts/closes them.
    let h3_driver = guard.disarm();
    Ok(BootstrappedSession {
        connection,
        status,
        peer_version,
        negotiated,
        control_send,
        control_recv,
        peer_settings,
        h3_driver,
    })
}

/// Default capabilities advertised by the spt client.
fn default_local_settings() -> crate::frame::Ssh3Settings {
    crate::frame::Ssh3Settings {
        direct_tcp: true,
        remote_tcp: true,
        udp_datagrams: true,
        agent_forwarding: false,
        max_forwards: Some(64),
        version: Some(concat!("spt-ssh3/", env!("CARGO_PKG_VERSION")).to_string()),
        extras: Vec::new(),
    }
}

/// Open the SSH3 control bidi stream and exchange
/// [`crate::frame::Ssh3FrameKind::Settings`]
/// frames with the peer.
///
/// **spt↔spt convention**: the client (whichever side calls `open_bi`) is the
/// initiator and writes its own settings first; the responder reads, replies,
/// and the initiator reads. See `forward.rs` for the broader wire contract.
pub async fn open_control_stream(
    connection: &quinn::Connection,
    local: crate::frame::Ssh3Settings,
) -> Result<(
    quinn::SendStream,
    quinn::RecvStream,
    crate::frame::Ssh3Settings,
)> {
    use crate::frame::{Ssh3Frame, Ssh3FrameKind};
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3 open control stream: {e}")))?;
    let our = Ssh3Frame::new(Ssh3FrameKind::Settings, local.encode_payload());
    our.write_async(&mut send).await?;
    // Read peer's settings (first frame on the stream) within a generous
    // timeout — a non-SSH3 peer would never answer.
    let frame = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        Ssh3Frame::read_async(&mut recv),
    )
    .await
    .map_err(|_| {
        Error::RuntimeFailure("ssh3 control: timeout waiting for peer settings".into())
    })??;
    if frame.kind != Ssh3FrameKind::Settings {
        return Err(Error::RuntimeFailure(format!(
            "ssh3 control: expected Settings, got {:?}",
            frame.kind
        )));
    }
    let peer = crate::frame::Ssh3Settings::decode_payload(frame.payload)?;
    Ok((send, recv, peer))
}

/// Server-side counterpart to [`open_control_stream`] — accept the first
/// inbound bidi stream as the SSH3 control stream and respond. Used by the
/// test harness "fake server".
pub async fn accept_control_stream(
    connection: &quinn::Connection,
    local: crate::frame::Ssh3Settings,
) -> Result<(
    quinn::SendStream,
    quinn::RecvStream,
    crate::frame::Ssh3Settings,
)> {
    use crate::frame::{Ssh3Frame, Ssh3FrameKind};
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3 accept control stream: {e}")))?;
    let frame = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        Ssh3Frame::read_async(&mut recv),
    )
    .await
    .map_err(|_| {
        Error::RuntimeFailure("ssh3 control: timeout waiting for client settings".into())
    })??;
    if frame.kind != Ssh3FrameKind::Settings {
        return Err(Error::RuntimeFailure(format!(
            "ssh3 control: expected Settings, got {:?}",
            frame.kind
        )));
    }
    let peer = crate::frame::Ssh3Settings::decode_payload(frame.payload)?;
    let ours = Ssh3Frame::new(Ssh3FrameKind::Settings, local.encode_payload());
    ours.write_async(&mut send).await?;
    Ok((send, recv, peer))
}

/// Abort-on-drop RAII guard for the parked h3 driver task and the QUIC
/// connection during [`bootstrap`].
///
/// The h3 driver task is parked on `std::future::pending()` holding clones of
/// the [`quinn::Connection`] (via `send_request` + `driver`); it can ONLY be
/// stopped by `.abort()`. Until [`Self::disarm`] is called — on the successful
/// bootstrap path, when ownership of the handle + connection moves into the
/// returned [`BootstrappedSession`] — dropping this guard aborts the driver
/// task and closes the connection.
///
/// This closes **C1**: every early `?` return between the spawn and the `Ok`
/// arm, *and* any cancellation of `bootstrap().await` (a health-probe timeout
/// cancelling `preflight_connect`, or a `Shutdown`/`Failover` `select!`
/// cancelling `connect()`), drops the guard and therefore aborts the otherwise
/// unreapable task and releases the QUIC connection + UDP socket/FD. Without it
/// the parked task would live forever, leaking one task + connection + FD per
/// failed/cancelled attempt — recurring every keepalive/backoff cycle.
struct BootstrapGuard {
    driver: Option<tokio::task::JoinHandle<()>>,
    connection: Option<quinn::Connection>,
}

impl BootstrapGuard {
    fn new(driver: tokio::task::JoinHandle<()>, connection: quinn::Connection) -> Self {
        Self {
            driver: Some(driver),
            connection: Some(connection),
        }
    }

    /// Disarm the guard on the successful path and return the driver handle.
    /// Ownership of both the handle and the connection now belongs to the live
    /// [`BootstrappedSession`]; the extra connection clone the guard held is
    /// dropped *without* closing, and the guard's `Drop` becomes a no-op.
    fn disarm(mut self) -> tokio::task::JoinHandle<()> {
        // Drop the guard's extra connection clone WITHOUT closing — the session
        // owns the real connection now.
        let _ = self.connection.take();
        self.driver.take().expect("BootstrapGuard disarmed twice")
    }
}

impl Drop for BootstrapGuard {
    fn drop(&mut self) {
        if let Some(h) = self.driver.take() {
            // Aborting an already-finished handle is a harmless no-op.
            h.abort();
        }
        if let Some(c) = self.connection.take() {
            // Best-effort: closing an already-closed connection is a no-op.
            c.close(0u32.into(), b"spt-ssh3: bootstrap aborted");
        }
    }
}

fn map_connection_error(e: quinn::ConnectionError) -> Error {
    use quinn::ConnectionError;
    match e {
        ConnectionError::TransportError(te) => {
            // rustls cert errors flow through here as "the cryptographic
            // handshake failed"; map to TrustFailed when recognizable.
            let msg = format!("{te}");
            if msg.contains("CertificateError")
                || msg.contains("UnknownCA")
                || msg.contains("BadCertificate")
                || msg.contains("certificate")
                || msg.contains("HandshakeFailure")
                || msg.contains("ssh3 SPKI pin")
                || msg.contains("SPKI pin")
            {
                Error::TrustFailed(format!("ssh3 TLS: {msg}"))
            } else {
                Error::RuntimeFailure(format!("ssh3 transport: {msg}"))
            }
        }
        ConnectionError::ConnectionClosed(c) => {
            Error::RuntimeFailure(format!("ssh3 closed by peer: {c}"))
        }
        ConnectionError::ApplicationClosed(c) => {
            Error::RuntimeFailure(format!("ssh3 app-closed: {c}"))
        }
        ConnectionError::Reset => Error::RuntimeFailure("ssh3 connection reset".into()),
        ConnectionError::TimedOut => Error::RuntimeFailure("ssh3 connection timed out".into()),
        ConnectionError::VersionMismatch => {
            Error::RuntimeFailure("ssh3 QUIC version mismatch".into())
        }
        ConnectionError::LocallyClosed => Error::RuntimeFailure("ssh3 locally closed".into()),
        ConnectionError::CidsExhausted => Error::RuntimeFailure("ssh3 CIDs exhausted".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_auth::{AuthConfig, AuthMethod, SecretRef};

    #[test]
    fn format_ssh3_negotiated_includes_transport_and_tls_version() {
        let s = format_ssh3_negotiated(Some("h3"), "example.com");
        assert_eq!(
            s,
            "transport=ssh3 tls_version=TLS1.3 alpn=h3 sni=example.com"
        );
        // Canonical contract: `transport=` token first, `tls_version` constant.
        assert!(s.starts_with("transport=ssh3 tls_version=TLS1.3"));
    }

    #[test]
    fn format_ssh3_negotiated_omits_absent_alpn() {
        let s = format_ssh3_negotiated(None, "h.example");
        assert_eq!(s, "transport=ssh3 tls_version=TLS1.3 sni=h.example");
        assert!(!s.contains("alpn="));
        assert!(s.starts_with("transport=ssh3 tls_version=TLS1.3"));
    }

    #[test]
    fn format_ssh3_negotiated_omits_empty_alpn() {
        // An empty ALPN string is treated as absent (no `alpn=` token).
        let s = format_ssh3_negotiated(Some(""), "h.example");
        assert!(!s.contains("alpn="));
        assert_eq!(s, "transport=ssh3 tls_version=TLS1.3 sni=h.example");
    }

    #[test]
    fn build_connect_request_has_protocol_extension_and_bearer() {
        std::env::set_var("SPT_TEST_TRANSPORT_TOK", "tok-xyz");
        let auth = AuthConfig::new(
            "u",
            vec![AuthMethod::Bearer {
                token: SecretRef::parse("env:SPT_TEST_TRANSPORT_TOK").unwrap(),
            }],
        );
        let req = build_connect_request("example.com", 443, "/ssh3", &auth).unwrap();
        assert_eq!(req.method(), &Method::CONNECT);
        assert_eq!(req.uri().host(), Some("example.com"));
        assert_eq!(req.uri().port_u16(), Some(443));
        assert_eq!(req.uri().path(), "/ssh3");
        assert_eq!(req.uri().scheme_str(), Some("https"));
        let auth_h = req.headers().get(http::header::AUTHORIZATION).unwrap();
        assert_eq!(auth_h, "Bearer tok-xyz");
        // SSH3 protocol marker (carried as a custom header — see GAP note).
        assert_eq!(req.headers().get("x-ssh3-protocol").unwrap(), "ssh3");
        std::env::remove_var("SPT_TEST_TRANSPORT_TOK");
    }

    #[test]
    fn x_ssh3_protocol_header_is_byte_exact_value() {
        // Pin the header VALUE to the exact bytes `ssh3` (no quoting, no
        // whitespace, lowercase). The francoismichel/ssh3 reference does a
        // literal string compare against the `:protocol` pseudo-header value,
        // and the X-Ssh3-Protocol header mirror is matched the same way.
        std::env::set_var("SPT_TEST_TRANSPORT_TOK_BV", "t");
        let auth = AuthConfig::new(
            "u",
            vec![AuthMethod::Bearer {
                token: SecretRef::parse("env:SPT_TEST_TRANSPORT_TOK_BV").unwrap(),
            }],
        );
        let req = build_connect_request("h.example", 8443, "/ssh3", &auth).unwrap();
        let v = req
            .headers()
            .get("x-ssh3-protocol")
            .expect("X-Ssh3-Protocol header present");
        // as_bytes() returns the raw header value with NO interpretation.
        assert_eq!(v.as_bytes(), b"ssh3");
        // Exactly 4 bytes — guards against accidental leading/trailing
        // whitespace or BOM injection.
        assert_eq!(v.as_bytes().len(), 4);
        std::env::remove_var("SPT_TEST_TRANSPORT_TOK_BV");
    }

    #[test]
    fn x_ssh3_protocol_header_name_is_byte_exact() {
        // Pin the header NAME to the exact lowercase bytes `x-ssh3-protocol`.
        // HTTP header names are case-insensitive on the wire but `http::HeaderName`
        // normalizes to lowercase; we assert the canonical byte form so any
        // future rename (e.g., `Spt-Ssh3-Protocol`) requires touching this test
        // and therefore is impossible to do silently.
        std::env::set_var("SPT_TEST_TRANSPORT_TOK_BN", "t");
        let auth = AuthConfig::new(
            "u",
            vec![AuthMethod::Bearer {
                token: SecretRef::parse("env:SPT_TEST_TRANSPORT_TOK_BN").unwrap(),
            }],
        );
        let req = build_connect_request("h.example", 8443, "/ssh3", &auth).unwrap();
        let (name, _value) = req
            .headers()
            .iter()
            .find(|(n, _)| n.as_str().eq_ignore_ascii_case("x-ssh3-protocol"))
            .expect("header iter contains X-Ssh3-Protocol");
        assert_eq!(name.as_str().as_bytes(), b"x-ssh3-protocol");
        assert_eq!(name.as_str().len(), 15);
        std::env::remove_var("SPT_TEST_TRANSPORT_TOK_BN");
    }

    #[test]
    fn build_connect_request_basic_auth() {
        std::env::set_var("SPT_TEST_TRANSPORT_PWD", "pw");
        let auth = AuthConfig::new(
            "u",
            vec![AuthMethod::Basic {
                username: "alice".into(),
                password: SecretRef::parse("env:SPT_TEST_TRANSPORT_PWD").unwrap(),
            }],
        );
        let req = build_connect_request("h", 7777, "/", &auth).unwrap();
        let h = req.headers().get(http::header::AUTHORIZATION).unwrap();
        assert!(h.to_str().unwrap().starts_with("Basic "));
        std::env::remove_var("SPT_TEST_TRANSPORT_PWD");
    }

    #[test]
    fn build_connect_request_pins_spt_user_agent() {
        std::env::set_var("SPT_TEST_TRANSPORT_UA", "tok");
        let auth = AuthConfig::new(
            "u",
            vec![AuthMethod::Bearer {
                token: SecretRef::parse("env:SPT_TEST_TRANSPORT_UA").unwrap(),
            }],
        );
        let req = build_connect_request("h", 8443, "/ssh3", &auth).unwrap();
        let ua = req
            .headers()
            .get(http::header::USER_AGENT)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ua.starts_with("spt/"));
        std::env::remove_var("SPT_TEST_TRANSPORT_UA");
    }

    #[test]
    fn build_connect_request_publickey_path_produces_bearer_jwt() {
        use spt_key::algorithm::KeyAlgorithm;
        use spt_key::io as key_io;
        let kp = key_io::generate(KeyAlgorithm::Ed25519).unwrap();
        let path = std::env::temp_dir().join(format!(
            "spt-ssh3-transport-pk-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        key_io::save_encrypted(&kp, &path, None).unwrap();
        let auth = AuthConfig::new(
            "alice",
            vec![AuthMethod::PublicKey {
                identity_file: path.clone(),
                passphrase: None,
                allow_ssh_rsa_sha1: false,
            }],
        );
        let req = build_connect_request("h.example", 7443, "/ssh3", &auth).unwrap();
        let auth_h = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth_h.starts_with("Bearer "));
        let jwt = &auth_h["Bearer ".len()..];
        assert_eq!(jwt.matches('.').count(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn build_connect_request_rejects_bad_url_path() {
        std::env::set_var("SPT_TEST_TRANSPORT_BAD", "t");
        let auth = AuthConfig::new(
            "u",
            vec![AuthMethod::Bearer {
                token: SecretRef::parse("env:SPT_TEST_TRANSPORT_BAD").unwrap(),
            }],
        );
        let err = build_connect_request("h", 443, "/bad path", &auth).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
        std::env::remove_var("SPT_TEST_TRANSPORT_BAD");
    }

    #[test]
    fn resolve_addr_loopback_succeeds() {
        let addr = resolve_addr("127.0.0.1", 7443, DnsResolution::PerAttempt).unwrap();
        assert_eq!(addr.port(), 7443);
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn resolve_addr_unresolvable_errors() {
        let err =
            resolve_addr("nope.invalid.example.invalid", 1, DnsResolution::PerAttempt).unwrap_err();
        assert!(matches!(err, Error::DnsFailed(_)));
    }

    #[test]
    fn resolve_addr_once_pins_loopback() {
        // `Once` resolves then pins; repeated calls return the same address.
        let a = resolve_addr("127.0.0.1", 7444, DnsResolution::Once).unwrap();
        let b = resolve_addr("127.0.0.1", 7444, DnsResolution::Once).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.port(), 7444);
    }

    #[test]
    fn map_connection_error_reset_is_runtime() {
        let e = map_connection_error(quinn::ConnectionError::Reset);
        assert!(matches!(e, Error::RuntimeFailure(_)));
    }

    #[test]
    fn map_connection_error_timed_out_is_runtime() {
        let e = map_connection_error(quinn::ConnectionError::TimedOut);
        assert!(matches!(e, Error::RuntimeFailure(_)));
    }

    #[test]
    fn map_connection_error_version_mismatch_is_runtime() {
        let e = map_connection_error(quinn::ConnectionError::VersionMismatch);
        assert!(matches!(e, Error::RuntimeFailure(_)));
    }

    #[test]
    fn map_connection_error_locally_closed_is_runtime() {
        let e = map_connection_error(quinn::ConnectionError::LocallyClosed);
        assert!(matches!(e, Error::RuntimeFailure(_)));
    }

    #[test]
    fn map_connection_error_cids_exhausted_is_runtime() {
        let e = map_connection_error(quinn::ConnectionError::CidsExhausted);
        assert!(matches!(e, Error::RuntimeFailure(_)));
    }

    #[test]
    fn default_local_settings_advertises_expected_caps() {
        let s = default_local_settings();
        assert!(s.direct_tcp);
        assert!(s.remote_tcp);
        assert!(s.udp_datagrams);
        assert!(!s.agent_forwarding);
        assert_eq!(s.max_forwards, Some(64));
        assert!(s.version.as_deref().unwrap().starts_with("spt-ssh3/"));
    }

    #[tokio::test]
    async fn build_quinn_endpoint_constructs_for_v4_remote() {
        let cfg = crate::config::Ssh3Config {
            acknowledge_experimental: true,
            tls: crate::config::Ssh3TlsConfig {
                allow_self_signed: true,
                ..Default::default()
            },
            keepalive_secs: 25,
            ..Default::default()
        };
        let remote: SocketAddr = "127.0.0.1:7443".parse().unwrap();
        let ep = build_quinn_endpoint(remote, &cfg).unwrap();
        let local = ep.local_addr().unwrap();
        assert!(local.is_ipv4());
    }

    #[tokio::test]
    async fn build_quinn_endpoint_applies_new_knobs() {
        // Idle-timeout + max-streams + datagram-disable must construct cleanly
        // (the values are not externally observable on a client `Endpoint`, so
        // we assert the builder accepts them without error — the wire effect is
        // covered by the loopback e2e test).
        let cfg = crate::config::Ssh3Config {
            acknowledge_experimental: true,
            tls: crate::config::Ssh3TlsConfig {
                allow_self_signed: true,
                pin: spt_trust::TlsPin {
                    spki_sha256: vec![[0u8; 32]],
                },
                ..Default::default()
            },
            idle_timeout_secs: Some(30),
            max_streams: Some(16),
            enable_datagrams: false,
            keepalive_secs: 25,
            ..Default::default()
        };
        let remote: SocketAddr = "127.0.0.1:7443".parse().unwrap();
        let ep = build_quinn_endpoint(remote, &cfg).unwrap();
        assert!(ep.local_addr().unwrap().is_ipv4());
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn extended_connect_raw_honors_custom_protocol_token() {
        use crate::h3_raw::{
            build_headers_frame, extended_connect_raw, qpack_decode, qpack_encode, read_frame_typed,
        };
        use crate::testing::test_support::connected_pair_public;

        let (client_conn, server_conn) = connected_pair_public().await;
        let (drop_tx, drop_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (mut s_send, mut s_recv) = server_conn
                .accept_bi()
                .await
                .expect("accept bootstrap bidi");
            let payload = read_frame_typed(&mut s_recv, 0x01)
                .await
                .expect("read HEADERS");
            let fields = qpack_decode(&payload).expect("qpack decode");
            let resp_qpack = qpack_encode(&[(b":status", b"200")]);
            s_send
                .write_all(&build_headers_frame(&resp_qpack))
                .await
                .expect("write response");
            s_send.finish().expect("finish");
            let _ = drop_rx.await;
            drop(server_conn);
            fields
        });

        let outcome = extended_connect_raw(
            &client_conn,
            "h.test",
            8443,
            "/ssh3",
            "Bearer t",
            "spt/test",
            "ssh3-next",
        )
        .await
        .expect("connect");
        assert_eq!(outcome.status, 200);
        let _ = drop_tx.send(());
        let fields = server.await.expect("server task");
        let proto = fields
            .iter()
            .find(|(n, _)| n == b":protocol")
            .map(|(_, v)| v.clone())
            .expect(":protocol present");
        assert_eq!(proto, b"ssh3-next");
        let xproto = fields
            .iter()
            .find(|(n, _)| n == b"x-ssh3-protocol")
            .map(|(_, v)| v.clone())
            .expect("x-ssh3-protocol present");
        assert_eq!(xproto, b"ssh3-next");
    }

    /// SECURITY (O3): `extended_connect_raw` must reject any value containing
    /// CR/LF/NUL/control bytes BEFORE it opens a stream or encodes the
    /// request. Each crafted field below must produce an `Err` (the validation
    /// short-circuits before `open_bi`, so a live server is unnecessary — we
    /// just need a connected client handle).
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn extended_connect_raw_rejects_control_char_injection() {
        use crate::h3_raw::extended_connect_raw;
        use crate::testing::test_support::connected_pair_public;

        let (client_conn, _server_conn) = connected_pair_public().await;

        // host (→ :authority) with CRLF.
        assert!(
            extended_connect_raw(
                &client_conn,
                "h.test\r\nevil: 1",
                8443,
                "/ssh3",
                "Bearer t",
                "spt/test",
                "ssh3",
            )
            .await
            .is_err(),
            "CRLF in host must be rejected"
        );

        // url_path (→ :path) with CRLF.
        assert!(
            extended_connect_raw(
                &client_conn,
                "h.test",
                8443,
                "/x\r\nevil: 1",
                "Bearer t",
                "spt/test",
                "ssh3",
            )
            .await
            .is_err(),
            "CRLF in url_path must be rejected"
        );

        // auth_header (→ authorization) with an injected header — models a
        // crafted Bearer/OIDC token smuggling a second header.
        assert!(
            extended_connect_raw(
                &client_conn,
                "h.test",
                8443,
                "/ssh3",
                "Bearer abc\r\nx-admin: 1",
                "spt/test",
                "ssh3",
            )
            .await
            .is_err(),
            "CRLF in authorization must be rejected"
        );

        // user-agent with NUL.
        assert!(
            extended_connect_raw(
                &client_conn,
                "h.test",
                8443,
                "/ssh3",
                "Bearer t",
                "spt\0/x",
                "ssh3",
            )
            .await
            .is_err(),
            "NUL in user-agent must be rejected"
        );

        // protocol_token with a control byte.
        assert!(
            extended_connect_raw(
                &client_conn,
                "h.test",
                8443,
                "/ssh3",
                "Bearer t",
                "spt/test",
                "ssh3\x1b",
            )
            .await
            .is_err(),
            "control byte in protocol_token must be rejected"
        );
    }

    #[tokio::test]
    async fn build_quinn_endpoint_constructs_for_v6_remote() {
        let cfg = crate::config::Ssh3Config {
            acknowledge_experimental: true,
            tls: crate::config::Ssh3TlsConfig {
                allow_self_signed: true,
                ..Default::default()
            },
            keepalive_secs: 0,
            ..Default::default()
        };
        let remote: SocketAddr = "[::1]:7443".parse().unwrap();
        if let Ok(ep) = build_quinn_endpoint(remote, &cfg) {
            let local = ep.local_addr().unwrap();
            assert!(local.is_ipv6());
        }
    }

    /// End-to-end wire test: spin up a quinn server, have the client call
    /// [`crate::h3_raw::extended_connect_raw`], accept the first bidi on the
    /// server, parse the HTTP/3 HEADERS frame off the wire, QPACK-decode it,
    /// and assert that **the `:protocol` pseudo-header is present with the
    /// byte-exact value `ssh3`**. This pins the post-fix invariant the
    /// francoismichel/ssh3 reference server requires per RFC 9220 / RFC 8441.
    ///
    /// The server then writes back a HEADERS frame containing
    /// `:status = 200` (indexed against static table index 25) so the client
    /// side completes cleanly and returns its [`crate::h3_raw::RawConnectOutcome`].
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn extended_connect_raw_emits_protocol_ssh3_pseudo_header_to_a_fake_server() {
        use crate::h3_raw::{
            build_headers_frame, extended_connect_raw, qpack_decode, qpack_encode, read_frame_typed,
        };
        use crate::testing::test_support::connected_pair_public;

        let (client_conn, server_conn) = connected_pair_public().await;

        // Server task: accept the bootstrap bidi, read HEADERS, decode,
        // write back a `:status = 200` HEADERS frame, then HOLD the
        // connection open until told to drop. If the task returns the
        // `server_conn` it owns goes out of scope and the QUIC connection
        // closes — that races against the client's response read.
        let (drop_tx, drop_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (mut s_send, mut s_recv) = server_conn
                .accept_bi()
                .await
                .expect("accept bootstrap bidi");
            let payload = read_frame_typed(&mut s_recv, 0x01)
                .await
                .expect("read HEADERS");
            let fields = qpack_decode(&payload).expect("qpack decode");
            let resp_qpack = qpack_encode(&[(b":status", b"200"), (b"server", b"fake")]);
            let frame = build_headers_frame(&resp_qpack);
            s_send
                .write_all(&frame)
                .await
                .expect("write response HEADERS");
            s_send.finish().expect("finish response send");
            // Stay alive until the test releases us — keeps the QUIC
            // connection open so the client side can finish reading.
            let _ = drop_rx.await;
            drop(server_conn);
            fields
        });

        // Client side: issue the raw Extended-CONNECT.
        let outcome = extended_connect_raw(
            &client_conn,
            "example.test",
            8443,
            "/ssh3",
            "Bearer tok-pin",
            "spt/test",
            "ssh3",
        )
        .await
        .expect("extended_connect_raw");
        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.peer_version.as_deref(), Some("fake"));

        let _ = drop_tx.send(());
        let fields = server.await.expect("server task");
        // Locate the `:protocol` pseudo-header by name.
        let protocol = fields
            .iter()
            .find(|(n, _)| n == b":protocol")
            .map(|(_, v)| v.clone())
            .expect("`:protocol` pseudo-header MUST be present on the wire");
        assert_eq!(
            protocol, b"ssh3",
            "`:protocol` pseudo-header MUST be byte-exact `ssh3`",
        );
        // The :method, :scheme, :authority, :path pseudo-headers must also
        // make it across so the peer treats this as a proper Extended CONNECT.
        let by_name = |k: &[u8]| {
            fields
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(by_name(b":method"), b"CONNECT");
        assert_eq!(by_name(b":scheme"), b"https");
        assert_eq!(by_name(b":authority"), b"example.test:8443");
        assert_eq!(by_name(b":path"), b"/ssh3");
        // Backward-compat X-header still ships alongside the pseudo-header.
        assert_eq!(by_name(b"x-ssh3-protocol"), b"ssh3");
        // Authorization travels through QPACK literal-name-ref (static idx 84).
        assert_eq!(by_name(b"authorization"), b"Bearer tok-pin");
    }

    // -------------------------------------------------------------------------
    // C1 — BootstrapGuard + bootstrap leak coverage.
    // -------------------------------------------------------------------------

    /// A future-drop sentinel: flips an `AtomicBool` when the future holding it
    /// is dropped. Spawned into a `pending()`-parked task that mirrors the real
    /// h3 driver — the ONLY way the sentinel flips is `JoinHandle::abort()`
    /// causing the task's future to be dropped.
    #[cfg(feature = "testing")]
    fn parked_task_with_drop_flag() -> (
        tokio::task::JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            struct Sentinel(Arc<AtomicBool>);
            impl Drop for Sentinel {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            // Construct the sentinel BEFORE parking and signal readiness, so the
            // task is guaranteed to have been polled (and the sentinel created)
            // before the test aborts it — otherwise an abort-before-first-poll
            // would drop a future whose sentinel was never constructed.
            let _s = Sentinel(f);
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        (handle, flag, ready_rx)
    }

    /// Dropping an armed `BootstrapGuard` (the early-return / cancellation path)
    /// MUST abort the parked driver task AND close the QUIC connection. This is
    /// the exact mechanism that closes C1.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bootstrap_guard_drop_aborts_driver_and_closes_connection() {
        use crate::testing::test_support::connected_pair_public;
        use std::sync::atomic::Ordering;

        let (client, server) = connected_pair_public().await;
        let (handle, dropped, ready_rx) = parked_task_with_drop_flag();
        ready_rx.await.expect("driver task started");
        assert!(!handle.is_finished());

        let guard = BootstrapGuard::new(handle, client.clone());
        drop(guard); // simulate an early `?` return / cancellation.

        // The guard's explicit close propagates to the peer promptly.
        tokio::time::timeout(Duration::from_secs(5), server.closed())
            .await
            .expect("peer must observe the connection close after guard drop");

        // The parked driver task's future must have been dropped (aborted).
        let mut flipped = false;
        for _ in 0..100 {
            if dropped.load(Ordering::SeqCst) {
                flipped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(flipped, "driver task future must be dropped (task aborted)");
        drop(client);
    }

    /// Disarming the guard on the success path MUST NOT abort the driver task or
    /// close the connection — ownership transfers to the live session.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn bootstrap_guard_disarm_preserves_driver_and_connection() {
        use crate::testing::test_support::connected_pair_public;

        let (client, server) = connected_pair_public().await;
        let (handle, _flag, ready_rx) = parked_task_with_drop_flag();
        ready_rx.await.expect("driver task started");

        let guard = BootstrapGuard::new(handle, client.clone());
        let h = guard.disarm();

        // Driver still parked; connection NOT closed (the test still holds a
        // live `client` handle and the guard's close never fired).
        assert!(!h.is_finished(), "disarm must not abort the driver task");
        let closed = tokio::time::timeout(Duration::from_millis(400), server.closed()).await;
        assert!(closed.is_err(), "disarm must not close the connection");

        h.abort();
        drop(client);
    }

    /// Build a self-signed, ALPN-`h3` QUIC server endpoint on loopback that the
    /// real [`bootstrap`] client config (allow-self-signed, empty pin) accepts.
    /// Returns the bound port and the server `Endpoint`.
    #[cfg(feature = "testing")]
    fn fake_server_endpoint() -> (u16, quinn::Endpoint) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem().into_bytes();
        let key_pem = cert.key_pair.serialize_pem().into_bytes();
        let server_cfg = crate::tls::build_server_config(&cert_pem, &key_pem).unwrap();

        let probe = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);
        let endpoint = quinn::Endpoint::server(server_cfg, listen).unwrap();
        (listen.port(), endpoint)
    }

    #[cfg(feature = "testing")]
    fn leak_test_client_config() -> Ssh3Config {
        Ssh3Config {
            sni: Some("localhost".into()),
            acknowledge_experimental: true,
            tls: crate::config::Ssh3TlsConfig {
                allow_self_signed: true,
                ..crate::config::Ssh3TlsConfig::default()
            },
            ..Ssh3Config::default()
        }
    }

    #[cfg(feature = "testing")]
    fn leak_test_auth() -> AuthConfig {
        std::env::set_var("SPT_SSH3_LEAK_TOK", "tok");
        AuthConfig::new(
            "alice",
            vec![AuthMethod::Bearer {
                token: SecretRef::parse("env:SPT_SSH3_LEAK_TOK").unwrap(),
            }],
        )
    }

    /// Serialises the leak tests that mutate the process-global
    /// `SPT_SSH3_LEAK_TOK` env var (set by `leak_test_auth`, removed at each
    /// test's end). Without this, one test's `remove_var` can fire while the
    /// other's `bootstrap` is resolving `env:SPT_SSH3_LEAK_TOK`, so that
    /// bootstrap errors early instead of parking mid-handshake — the exact
    /// flake seen on parallel `cargo test -p spt-ssh3`. Held across the awaited
    /// `bootstrap` call so the token stays resolvable for the whole flow.
    #[cfg(feature = "testing")]
    fn leak_env_lock() -> &'static std::sync::Mutex<()> {
        static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// End-to-end C1: when `bootstrap` fails AFTER spawning the parked driver
    /// (here: the peer accepts the CONNECT bidi but finishes it without a
    /// response, so `extended_connect_raw` errors), the guard aborts the driver
    /// and closes the connection — the peer observes the close promptly instead
    /// of the connection lingering on a leaked task.
    #[cfg(feature = "testing")]
    #[tokio::test]
    // The env-lock guard is intentionally held across the awaited `bootstrap`
    // so a sibling test's `SPT_SSH3_LEAK_TOK` mutation cannot race our token
    // resolution (repo idiom: cf. `cli/mod.rs` + `audit.rs`).
    #[allow(clippy::await_holding_lock)]
    async fn bootstrap_error_after_spawn_does_not_leak_driver_or_connection() {
        let _env = leak_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (port, endpoint) = fake_server_endpoint();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let incoming = endpoint.accept().await.expect("incoming");
            let conn = incoming.await.expect("server handshake");
            // Mirror the real server's h3 control stream so the client h3 layer
            // is satisfied; hold it for the connection's lifetime.
            let _ctrl = crate::h3_raw::write_server_control_stream(&conn).await.ok();
            // Accept the CONNECT bidi, read the HEADERS request, then finish the
            // send half WITHOUT a response → client `extended_connect_raw` errors.
            if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let _ = crate::h3_raw::read_frame_typed(&mut recv, 0x01).await;
                let _ = send.finish();
            }
            // Hold the connection and wait until the client side closes it.
            conn.closed().await;
            let _ = closed_tx.send(());
            // Keep the endpoint alive until the test releases us.
            endpoint
        });

        let cfg = leak_test_client_config();
        let auth = leak_test_auth();
        let res = tokio::time::timeout(
            Duration::from_secs(15),
            bootstrap("127.0.0.1", port, &cfg, &auth),
        )
        .await
        .expect("bootstrap must not hang");
        assert!(
            res.is_err(),
            "bootstrap should fail on the missing response"
        );

        // The guard's abort+close must make the peer observe the close quickly;
        // a leaked driver task would hold a connection clone open instead.
        tokio::time::timeout(Duration::from_secs(5), closed_rx)
            .await
            .expect("peer must observe connection close after failed bootstrap (no leak)")
            .expect("server signalled close");

        let _ = server.await;
        std::env::remove_var("SPT_SSH3_LEAK_TOK");
    }

    /// End-to-end C1 (cancellation): the peer accepts the connection but never
    /// answers the CONNECT, so `bootstrap` is parked mid-handshake. Cancelling
    /// `bootstrap().await` (modeled by a tight `timeout`) drops the guard, which
    /// aborts the parked driver and closes the connection — the peer observes
    /// the close promptly. This is the health-probe / Shutdown-Failover cancel
    /// scenario.
    #[cfg(feature = "testing")]
    #[tokio::test]
    // See the sibling test: the env-lock guard is intentionally held across the
    // awaited `bootstrap` to serialise `SPT_SSH3_LEAK_TOK` access.
    #[allow(clippy::await_holding_lock)]
    async fn bootstrap_cancellation_does_not_leak_driver_or_connection() {
        let _env = leak_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (port, endpoint) = fake_server_endpoint();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let incoming = endpoint.accept().await.expect("incoming");
            let conn = incoming.await.expect("server handshake");
            let _ctrl = crate::h3_raw::write_server_control_stream(&conn).await.ok();
            // Deliberately never accept the CONNECT bidi → the client parks on
            // its response read until cancelled.
            conn.closed().await;
            let _ = closed_tx.send(());
            endpoint
        });

        let cfg = leak_test_client_config();
        let auth = leak_test_auth();
        // Cancel bootstrap mid-handshake by dropping the future when the timeout
        // elapses.
        let cancelled = tokio::time::timeout(
            Duration::from_millis(800),
            bootstrap("127.0.0.1", port, &cfg, &auth),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "bootstrap should still be in-flight (cancelled)"
        );

        tokio::time::timeout(Duration::from_secs(5), closed_rx)
            .await
            .expect("peer must observe connection close after cancelled bootstrap (no leak)")
            .expect("server signalled close");

        let _ = server.await;
        std::env::remove_var("SPT_SSH3_LEAK_TOK");
    }
}
