//! Full-stack end-to-end SSH3 **unix-domain-socket** forward tests (Target-A,
//! spt↔spt). `cfg(unix)` only — binding/connecting `AF_UNIX` sockets is
//! Unix-only, so the whole file compiles to nothing on Windows.
//!
//! Mirrors `e2e_forward.rs`'s server bring-up: a real
//! [`quinn::Endpoint::server`] runs [`spt_ssh3::Ssh3Server::run`] as the
//! responder and the client opens a real [`spt_ssh3::Ssh3Session`] via the full
//! [`spt_ssh3::bootstrap`] path (QUIC + TLS 1.3 + HTTP/3 Extended-CONNECT +
//! control Settings).
//!
//! * `local_uds_forward_round_trips` — the client binds a unix listener; the
//!   server `UnixStream::connect`s an echo unix socket; bytes round-trip.
//! * `remote_uds_forward_round_trips` — the server binds a unix listener; the
//!   client connects its accepted connections back to a local echo unix
//!   socket; bytes round-trip.
//!
//! Requires the `testing` feature (rcgen + the server module).

#![cfg(all(unix, not(miri), feature = "testing"))]
#![allow(clippy::manual_let_else, clippy::ignored_unit_patterns)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_protocol::endpoint::{Endpoint, TargetAddr};
use spt_protocol::forward::{ForwardRateLimits, RemoteUdsForwardSpec, UdsForwardSpec};
use spt_protocol::{TunnelProtocol, TunnelSession};
use spt_ssh3::{Ssh3Config, Ssh3Protocol, Ssh3Server, Ssh3ServerAcl, Ssh3TlsConfig};
use spt_trust::TlsPin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

fn install_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn server_config_and_pin() -> (quinn::ServerConfig, [u8; 32]) {
    install_ring();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let pin = TlsPin::spki_sha256_of(&cert_der).unwrap();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

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

/// Stand up a loopback `Ssh3Server`. The ACL resolves every (TCP) open to a
/// dummy target; UDS opens dial the client-supplied path directly, so the
/// resolver is irrelevant for the UDS path.
fn start_server() -> (SocketAddr, [u8; 32]) {
    let (server_cfg, pin) = server_config_and_pin();
    let endpoint = quinn::Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = endpoint.local_addr().unwrap();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else {
                    return;
                };
                let acl = Ssh3ServerAcl::fixed_target(TargetAddr::new("127.0.0.1", 9));
                let _ = Ssh3Server::new().run(conn, acl).await;
            });
        }
    });

    (addr, pin)
}

/// Spawn a unix-socket echo server bound at `path`. (`UnixListener::bind` is
/// synchronous, so this is not `async`; it just spawns the accept loop.)
fn start_uds_echo(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).unwrap();
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
}

fn client_config(pin: [u8; 32]) -> Ssh3Config {
    let cfg = Ssh3Config {
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
    std::env::set_var("SPT_SSH3_UDS_TOK", "tok");
    AuthConfig::new(
        "alice",
        vec![AuthMethod::Bearer {
            token: SecretRef::parse("env:SPT_SSH3_UDS_TOK").unwrap(),
        }],
    )
}

async fn connect(server_addr: SocketAddr, pin: [u8; 32]) -> Box<dyn TunnelSession> {
    let proto = Ssh3Protocol::new(client_config(pin));
    let endpoint = Endpoint::new("127.0.0.1", server_addr.port());
    proto
        .connect(&endpoint, &dummy_auth())
        .await
        .expect("ssh3 bootstrap should succeed against loopback server")
}

/// Unique per-test socket path under the OS temp dir.
fn sock_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let uniq = format!(
        "spt-ssh3-uds-{tag}-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    p.push(uniq);
    p
}

#[tokio::test]
async fn local_uds_forward_round_trips() {
    let echo_path = sock_path("echo-local");
    start_uds_echo(&echo_path);

    let (server_addr, pin) = start_server();
    let mut session = connect(server_addr, pin).await;
    assert_eq!(session.session_info().backend, "ssh3");

    // Client binds this listen socket; the server connects to `echo_path`.
    let listen_path = sock_path("local-listen");
    let spec = UdsForwardSpec {
        name: "e2e-local-uds".into(),
        listen_path: listen_path.clone(),
        remote_socket_path: echo_path.to_string_lossy().into_owned(),
        limits: ForwardRateLimits::default(),
        required: false,
    };
    let _handle = session
        .open_uds_forward(&spec)
        .await
        .expect("open local uds forward");

    // Drive a client through the local unix listener → server → echo → back.
    let mut sock = UnixStream::connect(&listen_path).await.unwrap();
    let payload: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
    sock.write_all(&payload).await.unwrap();
    sock.shutdown().await.unwrap();
    let mut got = Vec::with_capacity(payload.len());
    tokio::time::timeout(Duration::from_secs(10), sock.read_to_end(&mut got))
        .await
        .expect("read_to_end timed out")
        .unwrap();
    assert_eq!(got, payload, "local-uds round-trip mismatch");

    let _ = std::fs::remove_file(&listen_path);
    let _ = std::fs::remove_file(&echo_path);
    let _ = Box::new(session).close().await;
}

#[tokio::test]
async fn remote_uds_forward_round_trips() {
    // Local echo the client back-channels accepted remote connections to.
    let local_echo = sock_path("echo-remote");
    start_uds_echo(&local_echo);

    let (server_addr, pin) = start_server();
    let mut session = connect(server_addr, pin).await;

    // Ask the server to bind this remote listen path; accepted connections are
    // bridged back to our local echo socket.
    let remote_listen = sock_path("remote-listen");
    let spec = RemoteUdsForwardSpec {
        name: "e2e-remote-uds".into(),
        remote_socket_path: remote_listen.to_string_lossy().into_owned(),
        local_socket_path: local_echo.clone(),
        limits: ForwardRateLimits::default(),
        idle_timeout: None,
        required: false,
    };
    let _handle = session
        .open_remote_uds(&spec)
        .await
        .expect("open remote uds forward");

    // A "remote" client connects to the server-bound listen socket (in this
    // single-process loopback test the server's listener is in our own fs).
    let mut sock = UnixStream::connect(&remote_listen).await.unwrap();
    let payload: Vec<u8> = (0..16 * 1024).map(|i| (i % 241) as u8).collect();
    sock.write_all(&payload).await.unwrap();
    sock.shutdown().await.unwrap();
    let mut got = Vec::with_capacity(payload.len());
    tokio::time::timeout(Duration::from_secs(10), sock.read_to_end(&mut got))
        .await
        .expect("read_to_end timed out")
        .unwrap();
    assert_eq!(got, payload, "remote-uds round-trip mismatch");

    let _ = std::fs::remove_file(&remote_listen);
    let _ = std::fs::remove_file(&local_echo);
    let _ = Box::new(session).close().await;
}
