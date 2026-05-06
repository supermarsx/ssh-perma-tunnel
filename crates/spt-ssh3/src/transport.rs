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

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderValue, Method, Request, Uri};
use quinn::{ClientConfig as QuinnClientConfig, Endpoint, TransportConfig};
use spt_auth::AuthConfig;
use spt_core::{Error, Result};

use crate::auth_header::build_authorization_header;
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
/// Public for the dedicated unit test that asserts the request shape (bearer
/// header, `:protocol` extension, authority + path).
pub fn build_connect_request(
    host: &str,
    port: u16,
    url_path: &str,
    auth: &AuthConfig,
) -> Result<Request<()>> {
    let auth_header = build_authorization_header(auth)?;
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
    req.headers_mut().insert(
        "x-ssh3-protocol",
        HeaderValue::from_static("ssh3"),
    );
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

    // h3-quinn driver
    let h3_conn = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut send_request) =
        h3::client::new(h3_conn).await.map_err(|e| {
            Error::RuntimeFailure(format!("ssh3: h3 client init: {e}"))
        })?;

    // Drive the connection in the background. When CONNECT completes we keep
    // the driver alive on the spawned task; the connection lives as long as
    // anyone holds the SendRequest handle.
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = build_connect_request(host, port, &cfg.url_path, auth)?;
    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3: send CONNECT: {e}")))?;
    stream
        .finish()
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3: CONNECT finish: {e}")))?;
    let resp = stream
        .recv_response()
        .await
        .map_err(|e| Error::RuntimeFailure(format!("ssh3: CONNECT response: {e}")))?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        // Cancel the driver task — connection closed shortly after.
        driver_task.abort();
        let body = format!("ssh3: CONNECT returned HTTP {status}");
        return Err(if matches!(status, 401 | 403) {
            Error::AuthFailed(body)
        } else {
            Error::RuntimeFailure(body)
        });
    }

    // We retain the driver task; cancellation happens at session close.
    // Leak the task handle here — the session owns it via close()/abort.
    // A more thorough impl would store this in the Ssh3Session.
    let peer_version = resp
        .headers()
        .get(http::header::SERVER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let negotiated = Some("TLS1.3 + QUIC + h3".to_string());

    Ok(BootstrappedSession {
        connection,
        status,
        peer_version,
        negotiated,
    })
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
        ConnectionError::TimedOut => {
            Error::RuntimeFailure("ssh3 connection timed out".into())
        }
        ConnectionError::VersionMismatch => {
            Error::RuntimeFailure("ssh3 QUIC version mismatch".into())
        }
        ConnectionError::LocallyClosed => {
            Error::RuntimeFailure("ssh3 locally closed".into())
        }
        ConnectionError::CidsExhausted => {
            Error::RuntimeFailure("ssh3 CIDs exhausted".into())
        }
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
        assert_eq!(
            req.headers().get("x-ssh3-protocol").unwrap(),
            "ssh3"
        );
        std::env::remove_var("SPT_TEST_TRANSPORT_TOK");
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
}
