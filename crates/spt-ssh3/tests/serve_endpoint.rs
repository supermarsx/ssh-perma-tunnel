//! End-to-end test of the `spt_ssh3::serve` accept loop — the engine behind
//! the `spt ssh3-serve` subcommand.
//!
//! Unlike `e2e_forward.rs` (which calls `Ssh3Server::run` directly against one
//! hand-bound connection), this exercises the full
//! [`spt_ssh3::serve`] path: it builds a server config from PEM via
//! [`spt_ssh3::tls::build_server_config`], hands it to `serve` (which owns the
//! `quinn::Endpoint` bind + accept loop), connects a real
//! [`spt_ssh3::Ssh3Session`] client through the bootstrap path, opens a
//! local-TCP forward, round-trips bytes, then resolves the shutdown future and
//! asserts `serve` returns cleanly.

#![cfg(all(not(miri), feature = "testing"))]
#![allow(clippy::manual_let_else)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_core::BindAddr;
use spt_protocol::endpoint::{Endpoint, TargetAddr};
use spt_protocol::forward::{BindConflictPolicy, ForwardRateLimits, LocalForwardSpec};
use spt_protocol::{TunnelProtocol, TunnelSession};
use spt_ssh3::{Ssh3Config, Ssh3Protocol, Ssh3ServerAcl, Ssh3TlsConfig};
use spt_trust::TlsPin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

fn install_ring() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Generate a self-signed cert for `localhost`, returning PEM cert + key bytes
/// and the SHA-256 SPKI pin of the leaf so the client can pin it.
fn cert_key_pem_and_pin() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    install_ring();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem().into_bytes();
    let key_pem = cert.key_pair.serialize_pem().into_bytes();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let pin = TlsPin::spki_sha256_of(&cert_der).unwrap();
    (cert_pem, key_pem, pin)
}

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
    std::env::set_var("SPT_SSH3_SERVE_TOK", "tok");
    AuthConfig::new(
        "alice",
        vec![AuthMethod::Bearer {
            token: SecretRef::parse("env:SPT_SSH3_SERVE_TOK").unwrap(),
        }],
    )
}

#[tokio::test]
async fn serve_accept_loop_round_trips_and_shuts_down() {
    let echo_addr = start_echo().await;
    let echo_target = TargetAddr::new(echo_addr.ip().to_string(), echo_addr.port());

    // Build the server config exactly as `spt ssh3-serve --cert --key` does.
    let (cert_pem, key_pem, pin) = cert_key_pem_and_pin();
    let server_cfg = spt_ssh3::tls::build_server_config(&cert_pem, &key_pem)
        .expect("build server config from PEM");
    let acl = Ssh3ServerAcl::fixed_target(echo_target);

    // Bind on an ephemeral loopback port. `serve` binds the endpoint itself, so
    // grab a free port first.
    let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = probe.local_addr().unwrap();
    drop(probe);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let serve_handle = tokio::spawn(async move {
        spt_ssh3::serve(listen, server_cfg, acl, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    // Give the accept loop a moment to bind.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect a real client through the full bootstrap path.
    let cfg = client_config(pin);
    let proto = Ssh3Protocol::new(cfg);
    let endpoint = Endpoint::new("127.0.0.1", listen.port());
    let mut session: Box<dyn TunnelSession> = proto
        .connect(&endpoint, &dummy_auth())
        .await
        .expect("ssh3 bootstrap against serve() endpoint");
    assert_eq!(session.session_info().backend, "ssh3");

    // Open a local-TCP forward and round-trip bytes.
    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listen_addr = probe.local_addr().unwrap();
    drop(probe);
    let spec = LocalForwardSpec {
        name: "serve-tcp".into(),
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

    let mut sock = TcpStream::connect(listen_addr).await.unwrap();
    let payload: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
    sock.write_all(&payload).await.unwrap();
    sock.shutdown().await.unwrap();
    let mut got = Vec::with_capacity(payload.len());
    tokio::time::timeout(Duration::from_secs(10), sock.read_to_end(&mut got))
        .await
        .expect("read_to_end timed out")
        .unwrap();
    assert_eq!(got, payload, "round-trip mismatch");

    let _ = Box::new(session).close().await;

    // Resolve the shutdown future; `serve` must return cleanly.
    let _ = shutdown_tx.send(());
    let res = tokio::time::timeout(Duration::from_secs(10), serve_handle)
        .await
        .expect("serve() did not return after shutdown")
        .expect("serve task panicked");
    assert!(res.is_ok(), "serve() returned an error: {res:?}");
}
