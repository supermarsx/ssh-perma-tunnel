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
//! [`crate::h3_raw`] for the minimal QPACK + HTTP/3-HEADERS implementation
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

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderValue, Method, Request, Uri};
use quinn::{ClientConfig as QuinnClientConfig, Endpoint, TransportConfig};
use spt_auth::AuthConfig;
use spt_core::{Error, Result};

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

/// Resolve the endpoint host:port to a `SocketAddr`.
fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| Error::DnsFailed(format!("ssh3 resolve `{host}:{port}`: {e}")))?
        .collect();
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
    client_cfg.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

/// Construct the HTTP/3 Extended CONNECT [`Request`] for the SSH3 session.
///
/// **Historical / reference path.** Since the
/// [raw HTTP/3 bootstrap](crate::h3_raw) landed, the live wire request is
/// emitted by [`crate::h3_raw::extended_connect_raw`] — not by feeding
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
    let remote = resolve_addr(host, port)?;
    let endpoint = build_quinn_endpoint(remote, cfg)?;

    let server_name = cfg.sni.clone().unwrap_or_else(|| host.to_string());
    let connecting = endpoint
        .connect(remote, &server_name)
        .map_err(|e| Error::RuntimeFailure(format!("ssh3: quinn::connect: {e}")))?;
    let connection = connecting.await.map_err(map_connection_error)?;

    // Spin up the h3 client driver on a clone of the QUIC connection. We do
    // NOT use it to issue the Extended-CONNECT request — h3 0.0.8 cannot
    // emit `:protocol = ssh3` (see module docs). The driver's job here is
    // to send the HTTP/3 client control stream + SETTINGS frame so the
    // peer's HTTP/3 stack is satisfied. The CONNECT itself goes via
    // [`h3_raw::extended_connect_raw`] on a separate raw bidi stream.
    let h3_conn = h3_quinn::Connection::new(connection.clone());
    let (mut driver, _send_request) = h3::client::new(h3_conn)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3: h3 client init: {e}")))?;
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

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
        driver_task.abort();
        let body = format!("ssh3: CONNECT returned HTTP {status}");
        return Err(if matches!(status, 401 | 403) {
            Error::AuthFailed(body)
        } else {
            Error::RuntimeFailure(body)
        });
    }
    let negotiated = Some("TLS1.3 + QUIC + h3 (raw bootstrap)".to_string());

    // Open the SSH3 control bidi stream and exchange `Settings` frames. We
    // run on a fresh raw QUIC stream (bypassing h3) — the spt↔spt
    // channel-framing contract is documented in `forward.rs`.
    let (control_send, control_recv, peer_settings) =
        open_control_stream(&connection, default_local_settings()).await?;

    Ok(BootstrappedSession {
        connection,
        status,
        peer_version,
        negotiated,
        control_send,
        control_recv,
        peer_settings,
        h3_driver: driver_task,
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
        let addr = resolve_addr("127.0.0.1", 7443).unwrap();
        assert_eq!(addr.port(), 7443);
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn resolve_addr_unresolvable_errors() {
        let err = resolve_addr("nope.invalid.example.invalid", 1).unwrap_err();
        assert!(matches!(err, Error::DnsFailed(_)));
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
}
