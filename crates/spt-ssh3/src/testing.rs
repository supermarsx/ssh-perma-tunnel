//! Test fixtures for [`spt_ssh3`] consumers.
//!
//! The reusable harness here mirrors the bring-up performed by the
//! `tests/two_endpoints.rs` integration test: a self-signed-cert QUIC
//! endpoint pair on `127.0.0.1:0`, a control-stream handshake, and the bits
//! needed to drive an [`Ssh3Session`] without going through HTTP/3.
//!
//! Helpers shipped:
//!
//! * [`Ssh3TestServer::start_pair`] — bring up a connected client+server pair
//!   and hand back ([`ClientCfg`], [`ServerHandle`]).
//! * [`fixtures::default_test_config`] — an [`Ssh3Config`] with
//!   `acknowledge_experimental = true` and `allow_self_signed = true`.
//! * [`ServerHandle`] — RAII shutdown handle.
//!
//! All of this lives behind `#[cfg(any(test, feature = "testing"))]`.

use crate::config::{Ssh3Config, Ssh3TlsConfig};

#[cfg(feature = "testing")]
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "testing")]
use spt_protocol::SessionInfo;

#[cfg(feature = "testing")]
use crate::{
    frame::Ssh3Settings,
    session::Ssh3Session,
    transport::{accept_control_stream, open_control_stream},
};

/// Fixtures: pre-built canonical configurations for tests.
pub mod fixtures {
    use super::{Ssh3Config, Ssh3TlsConfig};

    /// A permissive [`Ssh3Config`] suitable for in-process tests.
    ///
    /// `acknowledge_experimental = true` and `tls.allow_self_signed = true`
    /// so [`Ssh3Config::validate`] passes. A dummy SPKI pin satisfies the
    /// load-time requirement that self-signed mode must still anchor on
    /// either a pin set or a `ca_file` (security audit fix #4).
    /// `keepalive_secs` is the upstream default.
    ///
    /// ```
    /// use spt_ssh3::testing::fixtures::default_test_config;
    /// let c = default_test_config();
    /// assert!(c.acknowledge_experimental);
    /// c.validate().unwrap();
    /// ```
    #[must_use]
    pub fn default_test_config() -> Ssh3Config {
        Ssh3Config {
            acknowledge_experimental: true,
            tls: Ssh3TlsConfig {
                allow_self_signed: true,
                pin: spt_trust::TlsPin {
                    spki_sha256: vec![[0u8; 32]],
                },
                ..Ssh3TlsConfig::default()
            },
            ..Ssh3Config::default()
        }
    }
}

/// Thin re-export shim over the hand-rolled QPACK/h3 decoders so the
/// out-of-crate fuzz harness (`tests/fuzz_h3.rs`) can drive the
/// `pub(crate)` decode entry points directly. These are decode-only and
/// take/return plain byte slices — no production logic lives here.
///
/// Exposed deliberately narrow: the three wire-decode functions the
/// offensive audit flagged as top fuzz targets (`qpack_decode`,
/// `read_literal_string`, `read_prefix_int`). The frame decoder
/// (`Ssh3Frame::decode`) is already `pub` via [`crate::frame`].
#[doc(hidden)]
pub mod fuzz {
    use spt_core::Result;

    /// See [`crate::h3_raw::qpack_decode`].
    #[allow(clippy::type_complexity)]
    pub fn qpack_decode(buf: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        crate::h3_raw::qpack_decode(buf)
    }

    /// See [`crate::h3_raw::read_literal_string`].
    pub fn read_literal_string(buf: &[u8]) -> Result<(Vec<u8>, usize)> {
        crate::h3_raw::read_literal_string(buf)
    }

    /// See [`crate::h3_raw::read_prefix_int`].
    pub fn read_prefix_int(buf: &[u8], n: u8) -> Result<(u64, usize)> {
        crate::h3_raw::read_prefix_int(buf, n)
    }
}

// -----------------------------------------------------------------------------
// QUIC plumbing — only compiled when the `testing` feature pulls rcgen in.
// -----------------------------------------------------------------------------

#[cfg(feature = "testing")]
fn install_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(feature = "testing")]
fn make_quic_pair() -> (quinn::ServerConfig, quinn::ClientConfig) {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    install_ring();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("rcgen generate_simple_self_signed");
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let mut server = quinn::ServerConfig::with_single_cert(vec![cert_der.clone()], key_der)
        .expect("with_single_cert");
    let mut tcfg = quinn::TransportConfig::default();
    tcfg.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    server.transport_config(Arc::new(tcfg));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("add root");
    let rustls_client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let quic_client_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client).expect("quic crypto");
    let mut client = quinn::ClientConfig::new(Arc::new(quic_client_crypto));
    let mut tcfg2 = quinn::TransportConfig::default();
    tcfg2.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    client.transport_config(Arc::new(tcfg2));

    (server, client)
}

/// Crate-internal helper exposing [`connected_pair`] for in-crate tests that
/// need a raw self-signed QUIC connection pair without going through
/// [`Ssh3TestServer`]. Gated on the `testing` feature for the same reasons
/// as the rest of this module (pulls in `rcgen`).
#[cfg(feature = "testing")]
pub mod test_support {
    /// Bring up a connected pair of `quinn::Connection`s on loopback with a
    /// self-signed certificate. Returns `(client_conn, server_conn)`.
    pub async fn connected_pair_public() -> (quinn::Connection, quinn::Connection) {
        super::connected_pair().await
    }
}

#[cfg(feature = "testing")]
async fn connected_pair() -> (quinn::Connection, quinn::Connection) {
    let (server_cfg, client_cfg) = make_quic_pair();
    let server_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server_endpoint = quinn::Endpoint::server(server_cfg, server_addr).expect("server");
    let server_addr = server_endpoint.local_addr().expect("local_addr");
    let mut client_endpoint =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint");
    client_endpoint.set_default_client_config(client_cfg);
    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.expect("incoming");
        incoming.await.expect("await connection")
    });
    let client_conn = client_endpoint
        .connect(server_addr, "localhost")
        .expect("connect")
        .await
        .expect("await client conn");
    let server_conn = server_handle.await.expect("server task");
    (client_conn, server_conn)
}

#[cfg(feature = "testing")]
fn local_settings() -> Ssh3Settings {
    Ssh3Settings {
        direct_tcp: true,
        remote_tcp: true,
        udp_datagrams: true,
        agent_forwarding: false,
        max_forwards: Some(8),
        version: Some("test/0.1".into()),
        extras: vec![],
    }
}

#[cfg(feature = "testing")]
fn dummy_info(side: &str) -> SessionInfo {
    SessionInfo {
        backend: "ssh3".into(),
        peer_version: Some(side.to_string()),
        negotiated: Some("test".into()),
        established_at: 0,
    }
}

/// Configuration handed back to the test from [`Ssh3TestServer::start_pair`]:
/// a connect-ready [`Ssh3Config`] and the live client-side [`Ssh3Session`].
#[cfg(feature = "testing")]
pub struct ClientCfg {
    /// Validated [`Ssh3Config`] suitable for an in-process self-signed pair.
    pub config: Ssh3Config,
    /// Already-bootstrapped client [`Ssh3Session`], boxed as a
    /// [`spt_protocol::TunnelSession`] for the convenience of generic tests.
    pub session: Box<dyn spt_protocol::TunnelSession>,
    /// Server-side address (loopback, ephemeral port).
    pub server_addr: SocketAddr,
    /// Client-side QUIC connection retained so the test can issue further
    /// streams or inspect the underlying transport.
    pub client_conn: quinn::Connection,
}

/// RAII handle to the server side of a [`Ssh3TestServer::start_pair`] call.
/// Dropping the handle closes the server-side QUIC connection.
#[cfg(feature = "testing")]
pub struct ServerHandle {
    /// The raw server-side [`quinn::Connection`] — exposed so tests can drive
    /// the spt-ssh3 frame layer directly (read `DirectTcpRequest`, etc.).
    pub conn: quinn::Connection,
    /// Server-side control-stream send half from the handshake.
    pub send: quinn::SendStream,
    /// Server-side control-stream recv half from the handshake.
    pub recv: quinn::RecvStream,
    /// Peer settings advertised by the client.
    pub peer_settings: Ssh3Settings,
}

#[cfg(feature = "testing")]
impl ServerHandle {
    /// Close the server-side QUIC connection.
    pub fn shutdown(self) {
        self.conn.close(0u32.into(), b"test shutdown");
    }
}

#[cfg(feature = "testing")]
impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"drop");
    }
}

/// Builder for an in-process two-endpoint SSH3 test rig.
///
/// ```no_run
/// # async fn ex() {
/// use spt_ssh3::testing::Ssh3TestServer;
/// let (client, server) = Ssh3TestServer::new().start_pair().await.unwrap();
/// drop(server);
/// drop(client);
/// # }
/// ```
#[cfg(feature = "testing")]
pub struct Ssh3TestServer {
    settings: Ssh3Settings,
}

#[cfg(feature = "testing")]
impl Default for Ssh3TestServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "testing")]
impl Ssh3TestServer {
    /// Default settings: TCP forwards + UDP datagrams enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            settings: local_settings(),
        }
    }

    /// Override the [`Ssh3Settings`] advertised by both sides during the
    /// control-stream handshake.
    #[must_use]
    pub fn with_settings(mut self, settings: Ssh3Settings) -> Self {
        self.settings = settings;
        self
    }

    /// Bring up a connected pair. Returns a configured client (with an
    /// already-handshaked [`Ssh3Session`]) and a server handle whose drop
    /// closes the QUIC connection.
    pub async fn start_pair(self) -> std::io::Result<(ClientCfg, ServerHandle)> {
        let (client_conn, server_conn) = connected_pair().await;
        let server_addr = client_conn.remote_address();

        // Drive the SSH3 control-stream handshake; both sides advertise the
        // same settings so the negotiated peer-settings are symmetric.
        let cs_settings = self.settings.clone();
        let sv_settings = self.settings.clone();
        let (cs, sv) = tokio::join!(
            open_control_stream(&client_conn, cs_settings),
            accept_control_stream(&server_conn, sv_settings),
        );
        let (c_send, c_recv, c_peer) =
            cs.map_err(|e| std::io::Error::other(format!("client handshake: {e}")))?;
        let (s_send, s_recv, s_peer) =
            sv.map_err(|e| std::io::Error::other(format!("server handshake: {e}")))?;

        let session: Box<dyn spt_protocol::TunnelSession> = Box::new(Ssh3Session::from_parts(
            client_conn.clone(),
            c_send,
            c_recv,
            c_peer,
            dummy_info("client"),
            None,
        ));

        Ok((
            ClientCfg {
                config: fixtures::default_test_config(),
                session,
                server_addr,
                client_conn,
            },
            ServerHandle {
                conn: server_conn,
                send: s_send,
                recv: s_recv,
                peer_settings: s_peer,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_default_test_config_validates() {
        fixtures::default_test_config().validate().unwrap();
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn start_pair_brings_up_client_and_server() {
        let (client, server) = Ssh3TestServer::new().start_pair().await.unwrap();
        assert!(client.server_addr.ip().is_loopback());
        assert_eq!(client.session.session_info().backend, "ssh3");
        // Advertised settings round-trip.
        assert!(server.peer_settings.direct_tcp);
        server.shutdown();
    }
}
