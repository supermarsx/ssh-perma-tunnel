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

/// Unique per-test socket path, kept SHORT.
///
/// macOS caps `sun_path` at ~104 bytes and its `std::env::temp_dir()`
/// (`/var/folders/…/T/`) is long enough that the old verbose name tipped over
/// the limit (flaky `bind` failures, aarch64-apple-darwin only). Bind under
/// `/tmp` (short, present on all unix) with a compact name to stay well within
/// the limit; fall back to `temp_dir()` only if `/tmp` is unavailable.
fn sock_path(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let mut p = PathBuf::from("/tmp");
    if !p.is_dir() {
        p = std::env::temp_dir();
    }
    p.push(format!(
        "s3{tag}{}-{}.sock",
        std::process::id() % 100_000,
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
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

/// Large (multi-MiB) local-UDS transfer round-trips BYTE-EXACT. Reads
/// concurrently with writing so the echo pipeline can't deadlock on flow
/// control. Guards large-transfer integrity on the ssh3 UDS byte-pipe.
#[tokio::test]
async fn local_uds_forward_large_payload_round_trips() {
    let echo_path = sock_path("echo-large");
    start_uds_echo(&echo_path);

    let (server_addr, pin) = start_server();
    let mut session = connect(server_addr, pin).await;

    let listen_path = sock_path("large-listen");
    let spec = UdsForwardSpec {
        name: "e2e-large-uds".into(),
        listen_path: listen_path.clone(),
        remote_socket_path: echo_path.to_string_lossy().into_owned(),
        limits: ForwardRateLimits::default(),
        required: false,
    };
    let _handle = session
        .open_uds_forward(&spec)
        .await
        .expect("open local uds forward");

    let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let sock = UnixStream::connect(&listen_path).await.unwrap();
    let (mut r, mut w) = sock.into_split();
    let to_write = payload.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&to_write).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut got = Vec::with_capacity(payload.len());
    tokio::time::timeout(Duration::from_secs(30), r.read_to_end(&mut got))
        .await
        .expect("read_to_end timed out")
        .unwrap();
    writer.await.unwrap();
    assert_eq!(got.len(), payload.len(), "large-uds length mismatch");
    assert_eq!(got, payload, "large-uds byte mismatch");

    let _ = std::fs::remove_file(&listen_path);
    let _ = std::fs::remove_file(&echo_path);
    let _ = Box::new(session).close().await;
}

/// Half-close/EOF propagation over a local-UDS forward: the client half-closes
/// its write side and the server target replies only *after* seeing that EOF.
/// Proves the client→server FIN propagates through the UDS bridge and the
/// server→client half stays open for the late reply.
#[tokio::test]
async fn local_uds_forward_half_close_client_first() {
    // Responder: read to EOF, then echo back with a suffix marker and close.
    let resp_path = sock_path("aftereof");
    let _ = std::fs::remove_file(&resp_path);
    let listener = UnixListener::bind(&resp_path).unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = sock.split();
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap(); // completes only on client FIN
        w.write_all(&got).await.unwrap();
        w.write_all(b"|POST-EOF").await.unwrap();
        w.shutdown().await.unwrap();
    });

    let (server_addr, pin) = start_server();
    let mut session = connect(server_addr, pin).await;

    let listen_path = sock_path("hc-listen");
    let spec = UdsForwardSpec {
        name: "e2e-hc-uds".into(),
        listen_path: listen_path.clone(),
        remote_socket_path: resp_path.to_string_lossy().into_owned(),
        limits: ForwardRateLimits::default(),
        required: false,
    };
    let _handle = session
        .open_uds_forward(&spec)
        .await
        .expect("open local uds forward");

    let sock = UnixStream::connect(&listen_path).await.unwrap();
    let (mut r, mut w) = sock.into_split();
    w.write_all(b"REQUEST").await.unwrap();
    w.shutdown().await.unwrap(); // half-close
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), r.read_to_end(&mut got))
        .await
        .expect("late reply never arrived — UDS half-close broke the read half")
        .unwrap();
    assert_eq!(
        got, b"REQUEST|POST-EOF",
        "UDS server reply after client half-close was lost/truncated"
    );

    let _ = std::fs::remove_file(&listen_path);
    let _ = std::fs::remove_file(&resp_path);
    let _ = Box::new(session).close().await;
}
