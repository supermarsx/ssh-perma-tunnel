//! Full-stack end-to-end SSH3 forward test (Target-A, spt↔spt).
//!
//! Unlike `two_endpoints.rs` (which drives both ends via `from_parts`,
//! bypassing HTTP/3), this test exercises the **entire client stack**:
//!
//! * A real [`quinn::Endpoint::server`] on loopback runs
//!   [`spt_ssh3::Ssh3Server::run`] as the responder.
//! * The client opens a real [`spt_ssh3::Ssh3Session`] via the full
//!   [`spt_ssh3::bootstrap`] path — QUIC + TLS 1.3 + the hand-rolled HTTP/3
//!   Extended-CONNECT (`:protocol = ssh3`) bootstrap + control-stream Settings
//!   exchange.
//! * A local-TCP forward is opened and bytes are pumped through an echo target,
//!   asserting round-trip.
//!
//! It also covers [`spt_ssh3::Ssh3Session::preflight_connect`] (A3): `Ok` once a
//! live server is up, `Err` against a dead endpoint.
//!
//! Requires the `testing` feature (rcgen + the server module).

#![cfg(all(not(miri), feature = "testing"))]
#![allow(clippy::manual_let_else, clippy::ignored_unit_patterns)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_core::BindAddr;
use spt_protocol::endpoint::{Endpoint, TargetAddr};
use spt_protocol::forward::{BindConflictPolicy, ForwardRateLimits, LocalForwardSpec};
use spt_protocol::{TunnelProtocol, TunnelSession};
use spt_ssh3::{Ssh3Config, Ssh3Protocol, Ssh3Server, Ssh3ServerAcl, Ssh3TlsConfig};
use spt_trust::TlsPin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn install_ring() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Generate a self-signed cert for `localhost`, returning the quinn
/// `ServerConfig` and the SHA-256 SPKI pin of the cert so the client can pin it.
fn server_config_and_pin() -> (quinn::ServerConfig, [u8; 32]) {
    install_ring();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let pin = TlsPin::spki_sha256_of(&cert_der).unwrap();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    // Build the rustls server config directly so we can advertise ALPN `h3`
    // — the client (`build_client_config`) advertises `["h3"]` and the QUIC
    // handshake fails with "no known protocol" if the server omits it.
    let mut rustls_server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    rustls_server.alpn_protocols = vec![b"h3".to_vec()];
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server).unwrap();
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    let mut tcfg = quinn::TransportConfig::default();
    tcfg.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    server.transport_config(Arc::new(tcfg));
    (server, pin)
}

/// Stand up a loopback `Ssh3Server` and return its bound address + the SPKI pin
/// to trust. The server runs one connection's worth of `Ssh3Server::run`,
/// resolving every forward open to `echo_target`.
fn start_server(echo_target: TargetAddr) -> (SocketAddr, [u8; 32]) {
    let (server_cfg, pin) = server_config_and_pin();
    let endpoint = quinn::Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = endpoint.local_addr().unwrap();

    tokio::spawn(async move {
        // Serve as many connections as arrive (the test opens 1-2).
        while let Some(incoming) = endpoint.accept().await {
            let target = echo_target.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else {
                    return;
                };
                let acl = Ssh3ServerAcl::fixed_target(target);
                let _ = Ssh3Server::new().run(conn, acl).await;
            });
        }
    });

    (addr, pin)
}

/// Spawn a TCP echo server, returning its address.
async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

fn client_config(pin: [u8; 32]) -> Ssh3Config {
    let cfg = Ssh3Config {
        // SNI must be a DNS name the cert covers; the cert SANs `localhost`.
        sni: Some("localhost".into()),
        acknowledge_experimental: true,
        tls: Ssh3TlsConfig {
            allow_self_signed: true,
            pin: TlsPin {
                spki_sha256: vec![pin],
            },
            ..Ssh3TlsConfig::default()
        },
        ..Ssh3Config::default()
    };
    cfg.validate().expect("client config validates");
    cfg
}

fn dummy_auth() -> AuthConfig {
    std::env::set_var("SPT_SSH3_E2E_TOK", "tok");
    AuthConfig::new(
        "alice",
        vec![AuthMethod::Bearer {
            token: SecretRef::parse("env:SPT_SSH3_E2E_TOK").unwrap(),
        }],
    )
}

#[tokio::test]
async fn full_stack_local_tcp_forward_round_trips() {
    let echo_addr = start_echo().await;
    let echo_target = TargetAddr::new(echo_addr.ip().to_string(), echo_addr.port());
    let (server_addr, pin) = start_server(echo_target);

    let cfg = client_config(pin);
    let proto = Ssh3Protocol::new(cfg);
    let endpoint = Endpoint::new("127.0.0.1", server_addr.port());

    let mut session: Box<dyn TunnelSession> = proto
        .connect(&endpoint, &dummy_auth())
        .await
        .expect("ssh3 bootstrap (QUIC+TLS+CONNECT) should succeed against loopback server");
    assert_eq!(session.session_info().backend, "ssh3");

    // Open a local-TCP forward bound to an ephemeral local port.
    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listen_addr = probe.local_addr().unwrap();
    drop(probe);
    let spec = LocalForwardSpec {
        name: "e2e-tcp".into(),
        listen: BindAddr::Tcp(listen_addr),
        target: TargetAddr::new("ignored-by-acl", 1),
        max_connections: None,
        limits: ForwardRateLimits::default(),
        idle_timeout: None,
        on_bind_conflict: BindConflictPolicy::default(),
        required: false,
    };
    let _handle = session
        .open_local_forward(&spec)
        .await
        .expect("open forward");

    // Pump bytes through the forward → server → echo target → back.
    let mut sock = TcpStream::connect(listen_addr).await.unwrap();
    let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 251) as u8).collect();
    sock.write_all(&payload).await.unwrap();
    sock.shutdown().await.unwrap();
    let mut got = Vec::with_capacity(payload.len());
    tokio::time::timeout(Duration::from_secs(10), sock.read_to_end(&mut got))
        .await
        .expect("read_to_end timed out")
        .unwrap();
    assert_eq!(got, payload, "round-trip mismatch");

    let _ = Box::new(session).close().await;
}

#[tokio::test]
async fn preflight_connect_ok_against_live_server() {
    let echo_addr = start_echo().await;
    let echo_target = TargetAddr::new(echo_addr.ip().to_string(), echo_addr.port());
    let (server_addr, pin) = start_server(echo_target);

    let cfg = client_config(pin);
    let proto = Ssh3Protocol::new(cfg);
    let endpoint = Endpoint::new("127.0.0.1", server_addr.port());

    let mut session = proto
        .connect(&endpoint, &dummy_auth())
        .await
        .expect("initial connect");

    // A fresh side-dial must succeed against the same live server.
    session
        .preflight_connect()
        .await
        .expect("preflight_connect should succeed against a live server");

    let _ = Box::new(session).close().await;
}

#[tokio::test]
async fn preflight_connect_err_against_dead_endpoint() {
    // Bring a server up, connect, then take the server down before preflight.
    let echo_addr = start_echo().await;
    let echo_target = TargetAddr::new(echo_addr.ip().to_string(), echo_addr.port());

    // Bind a server endpoint we fully control so we can drop it.
    let (server_cfg, pin) = server_config_and_pin();
    let endpoint = quinn::Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        if let Some(incoming) = endpoint.accept().await {
            if let Ok(conn) = incoming.await {
                let acl = Ssh3ServerAcl::fixed_target(echo_target);
                let _ = Ssh3Server::new().run(conn, acl).await;
            }
        }
        // Endpoint dropped here → port closes.
        endpoint.close(0u32.into(), b"down");
    });

    let cfg = client_config(pin);
    let proto = Ssh3Protocol::new(cfg);
    let endpoint_desc = Endpoint::new("127.0.0.1", addr.port());
    let mut session = proto
        .connect(&endpoint_desc, &dummy_auth())
        .await
        .expect("initial connect");

    // Close the live session and let the server task finish + drop its endpoint.
    server_task.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Preflight now redials the (dead) endpoint and must error.
    let res = session.preflight_connect().await;
    assert!(
        res.is_err(),
        "preflight_connect against a downed server must Err, got {res:?}"
    );
    let _ = Box::new(session).close().await;
}

/// M6: the server-side handshake must not hang on a half-open peer. A client
/// that completes the QUIC handshake but never opens the CONNECT bidi must
/// cause `Ssh3Server::run` to return an error once the (short, test-configured)
/// handshake timeout elapses — not pin the task forever.
#[tokio::test]
async fn server_handshake_times_out_on_stalled_peer() {
    install_ring();
    // Self-contained quinn pair (server + trusting client over one cert).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let mut rustls_server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    rustls_server.alpn_protocols = vec![b"h3".to_vec()];
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server).unwrap();
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    let mut tcfg = quinn::TransportConfig::default();
    tcfg.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    server_cfg.transport_config(Arc::new(tcfg));

    let server_endpoint =
        quinn::Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    // Server: accept one connection and run the responder with a short
    // handshake deadline.
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let acl = Ssh3ServerAcl::fixed_target(TargetAddr::new("127.0.0.1".to_string(), 9));
        Ssh3Server::new()
            .with_handshake_timeout(Duration::from_millis(200))
            .run(conn, acl)
            .await
    });

    // Client: complete the QUIC handshake, then do NOTHING (never open the
    // CONNECT bidi).
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut rustls_client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    rustls_client.alpn_protocols = vec![b"h3".to_vec()];
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client).unwrap();
    let mut client_endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client)));
    let client_conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // The server must return an error promptly (handshake timeout), not hang.
    let outcome = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must finish (handshake timeout), not hang")
        .expect("server task should not panic");
    assert!(
        outcome.is_err(),
        "stalled CONNECT must make the server handshake time out, got {outcome:?}"
    );

    // Keep the client connection alive until here so QUIC stays up during the
    // server's handshake wait.
    drop(client_conn);
}
