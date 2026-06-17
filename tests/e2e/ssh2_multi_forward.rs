//! e2e: multiple concurrent forwards on a single profile.
//!
//! ## Variants
//!
//! * **Mock variant (`three_concurrent_forwards_all_open`)** — runs in CI.
//!   Asserts the supervisor opens **all three** forwards (a local TCP, a
//!   remote TCP, and a second local TCP) on a single session, demonstrating
//!   per-forward isolation in the wiring (each has its own name/spec).
//! * **Real russh variant (`multiple_concurrent_forwards_real_russh`)** — runs
//!   in CI. Drives the real `Ssh2Protocol` (pure russh 0.61) against the
//!   embedded `RusshTestServer` and opens **three** concurrent local
//!   `direct-tcpip` forwards on the **same** session, asserting each carries an
//!   independent byte round-trip. The original libssh2↔russh KEX blocker is
//!   gone now the backend is pure russh, so this is a real, non-ignored test
//!   (no real network).

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_config::schema::Profile;
use spt_config::testing::{ForwardBuilder, ProfileBuilder};
use spt_core::BindAddr;
use spt_e2e_tests::SharedLogProtocol;
use spt_forward::testing::SessionCall;
use spt_protocol::{Endpoint, LocalForwardSpec, TargetAddr, TunnelProtocol};
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

fn profile_with_three_forwards() -> Profile {
    ProfileBuilder::new("multi")
        .endpoint("127.0.0.1", 22)
        .user("alice")
        .add_forward(ForwardBuilder::local_tcp("a", "127.0.0.1:0", "127.0.0.1:1").build())
        .add_forward(ForwardBuilder::remote_tcp("b", "127.0.0.1:0", "127.0.0.1:2").build())
        .add_forward(ForwardBuilder::local_tcp("c", "127.0.0.1:0", "127.0.0.1:3").build())
        .build()
}

#[tokio::test]
async fn three_concurrent_forwards_all_open() {
    let proto = Arc::new(SharedLogProtocol::new());
    let log = Arc::clone(&proto.shared);

    let endpoints = vec![Endpoint::new("127.0.0.1", 22)];
    let orch = OrchestratorBuilder::new()
        .with_profile(
            profile_with_three_forwards(),
            proto.clone() as Arc<dyn TunnelProtocol>,
            AuthConfig::new("alice", vec![]),
            endpoints,
            ProfileSupervisorConfig::default(),
        )
        .build();

    wait_for_state(
        &orch,
        "multi",
        ProfileStateName::Active,
        Duration::from_secs(3),
    )
    .await
    .expect("multi reaches active");

    // Wait for all three forwards to be opened.
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..100 {
        seen.clear();
        for c in log.lock().iter() {
            match c {
                SessionCall::OpenLocal(n) | SessionCall::OpenRemote(n) => {
                    seen.insert(n.clone());
                }
                _ => {}
            }
        }
        if seen.contains("a") && seen.contains("b") && seen.contains("c") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        seen.contains("a") && seen.contains("b") && seen.contains("c"),
        "all three forwards must be opened on the single session; observed = {seen:?}; \
         full log = {:?}",
        log.lock()
    );

    // Each forward must be opened *exactly once* per session — wiring
    // isolation invariant.
    let log_snap = log.lock().clone();
    for fname in ["a", "b", "c"] {
        let n = log_snap
            .iter()
            .filter(|c| match c {
                SessionCall::OpenLocal(n) | SessionCall::OpenRemote(n) => n == fname,
                _ => false,
            })
            .count();
        assert_eq!(
            n, 1,
            "forward `{fname}` must be opened exactly once; got {n}"
        );
    }

    orch.shutdown().await;
}

/// Real russh variant (GAP 4). Three concurrent local forwards on a single
/// pure-russh session, each routed through its own `direct-tcpip` channel to
/// the server's echo backend. We drive a distinct payload through each forward
/// concurrently and assert every payload round-trips on its own listener —
/// proving per-forward channel isolation under concurrent traffic on one
/// session. Pure russh client ↔ russh server, loopback only.
#[tokio::test]
async fn multiple_concurrent_forwards_real_russh() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");

    std::env::set_var("SPT_TEST_E2E_MULTI_PW", "anything");
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: SecretRef::Env("SPT_TEST_E2E_MULTI_PW".into()),
        }],
    );
    let mut session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("russh backend connects");

    // Open three independent local forwards on the one session.
    let mut listen_ports = Vec::with_capacity(3);
    let mut handles = Vec::with_capacity(3);
    for name in ["fwd-a", "fwd-b", "fwd-c"] {
        let port = free_loopback_port().await;
        let handle = session
            .open_local_forward(&LocalForwardSpec {
                name: name.into(),
                listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
                target: TargetAddr::new("server-side-echo", 7),
                max_connections: Some(4),
            })
            .await
            .unwrap_or_else(|e| panic!("open local forward {name}: {e}"));
        listen_ports.push(port);
        handles.push(handle);
    }

    // Drive a distinct payload through each forward concurrently and assert
    // each round-trips on its own listener.
    let mut tasks = Vec::with_capacity(3);
    for (i, port) in listen_ports.iter().copied().enumerate() {
        let tag = i as u8;
        tasks.push(tokio::spawn(async move {
            let payload: Vec<u8> = (0..1024u32).map(|n| (n as u8) ^ tag).collect();
            let mut sock = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect forward listener");
            sock.write_all(&payload).await.expect("write payload");
            let mut echoed = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut echoed))
                .await
                .expect("timely echo")
                .expect("read echo");
            (payload, echoed)
        }));
    }

    for (i, t) in tasks.into_iter().enumerate() {
        let (sent, got) = t.await.expect("forward task join");
        assert_eq!(
            got, sent,
            "forward #{i} payload must round-trip independently"
        );
    }

    // Each forward routed through its own direct-tcpip channel on the session.
    assert!(
        server.channel_opens_direct_tcpip() >= 3,
        "expected >=3 direct-tcpip channel opens (one per forward); got {}",
        server.channel_opens_direct_tcpip()
    );

    for h in handles {
        h.close().await;
    }
    session.close().await.expect("close session");
    server.shutdown().await;
}
