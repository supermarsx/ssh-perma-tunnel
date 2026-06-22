//! e2e: remote-forward wiring through the supervisor against the SSH2 backend.
//!
//! ## Variants
//!
//! * **Mock variant (`remote_forward_wires_through_supervisor`)** — runs in CI.
//!   Asserts the supervisor invokes `TunnelSession::open_remote_forward` for
//!   the profile's remote forward.
//! * **Real russh variant (`remote_forward_roundtrip_real_russh`)** — runs in
//!   CI. Drives the real `Ssh2Protocol` (pure russh 0.61) against the embedded
//!   `RusshTestServer`, whose `tcpip_forward` handler binds a real loopback
//!   listener and pipes inbound bytes back over a `forwarded-tcpip` channel.
//!   We request a remote forward to a local target listener, connect to the
//!   server-bound remote port, and assert the bytes reach the local target.
//!   The original libssh2↔russh KEX blocker is gone now the backend is pure
//!   russh, so this is a real, non-ignored test (no real network).

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::Duration;

use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_config::schema::Profile;
use spt_config::testing::{ForwardBuilder, ProfileBuilder};
use spt_core::BindAddr;
use spt_e2e_tests::SharedLogProtocol;
use spt_forward::testing::SessionCall;
use spt_protocol::{
    BindConflictPolicy, Endpoint, ForwardRateLimits, RemoteForwardSpec, TargetAddr, TunnelProtocol,
};
use spt_ssh2::testing::RusshTestServer;
use spt_ssh2::Ssh2Protocol;
use spt_supervisor::testing::{
    wait_for_state, OrchestratorBuilder, ProfileStateName, ProfileSupervisorConfig,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

async fn free_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

async fn connect_with_retry(port: u16) -> TcpStream {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(sock) => return sock,
            Err(e) if tokio::time::Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => panic!("connect remote listener on {port}: {e}"),
        }
    }
}

fn profile_with_remote_forward(name: &str, fname: &str) -> Profile {
    ProfileBuilder::new(name)
        .endpoint("127.0.0.1", 22)
        .user("alice")
        .add_forward(ForwardBuilder::remote_tcp(fname, "127.0.0.1:0", "127.0.0.1:9").build())
        .build()
}

#[tokio::test]
async fn remote_forward_wires_through_supervisor() {
    let proto = Arc::new(SharedLogProtocol::new());
    let log = Arc::clone(&proto.shared);

    let profile = profile_with_remote_forward("p", "rf");
    let endpoints = vec![Endpoint::new("127.0.0.1", 22)];
    let orch = OrchestratorBuilder::new()
        .with_profile(
            profile,
            proto.clone() as Arc<dyn TunnelProtocol>,
            AuthConfig::new("alice", vec![]),
            endpoints,
            ProfileSupervisorConfig::default(),
        )
        .build();

    wait_for_state(&orch, "p", ProfileStateName::Active, Duration::from_secs(3))
        .await
        .expect("profile reaches active");

    let mut saw = false;
    for _ in 0..50 {
        if log
            .lock()
            .iter()
            .any(|c| matches!(c, SessionCall::OpenRemote(n) if n == "rf"))
        {
            saw = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        saw,
        "supervisor must call open_remote_forward(rf); log = {:?}",
        log.lock()
    );

    orch.shutdown().await;
}

/// Real russh variant (GAP 4). Pure russh client (`Ssh2Protocol`) ↔ russh
/// server (`RusshTestServer`). The server's `tcpip_forward` handler binds a
/// real loopback listener on the requested remote port and, for each inbound
/// connection, opens a `forwarded-tcpip` channel back to the client and pipes
/// the inbound bytes over it; the backend then dials the configured local
/// `target` and delivers them there. We stand up a local target listener,
/// request the remote forward, connect to the server-bound remote port, push
/// bytes, and assert the local target receives them.
#[tokio::test]
async fn remote_forward_roundtrip_real_russh() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");

    std::env::set_var("SPT_TEST_E2E_REMOTE_PW", "anything");
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: SecretRef::Env("SPT_TEST_E2E_REMOTE_PW".into()),
        }],
    );
    let mut session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("russh backend connects");

    // Local target the remote-forward delivers to.
    let local_target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local target");
    let local_target_port = local_target.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        let (mut sock, _) = local_target.accept().await.expect("accept local target");
        let mut buf = [0u8; 4];
        sock.read_exact(&mut buf)
            .await
            .expect("read server-originated bytes");
        let _ = seen_tx.send(buf.to_vec());
    });

    let remote_port = free_loopback_port().await;
    let handle = session
        .open_remote_forward(&RemoteForwardSpec {
            name: "rf-to-local".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{remote_port}")).unwrap(),
            target: TargetAddr::new("127.0.0.1", local_target_port),
            max_connections: Some(4),
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open remote forward");

    // Connect to the server-bound remote port and push bytes; they must reach
    // the local target via the forwarded-tcpip channel.
    let mut remote_sock = connect_with_retry(remote_port).await;
    remote_sock
        .write_all(b"pong")
        .await
        .expect("write to remote listener");
    drop(remote_sock);

    let seen = tokio::time::timeout(Duration::from_secs(5), seen_rx)
        .await
        .expect("timely server-to-client delivery")
        .expect("local target receives bytes");
    assert_eq!(seen, b"pong", "remote forward must deliver to local target");

    handle.close().await;
    session.close().await.expect("close session");
    server.shutdown().await;
}
