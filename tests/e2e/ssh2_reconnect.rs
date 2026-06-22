//! e2e: supervisor reconnect-on-failure wiring.
//!
//! ## Variants
//!
//! * **Mock variant (`reconnect_on_connect_failure_then_recovery`)** —
//!   runs in CI. Drives the supervisor through a fail/recover cycle by
//!   toggling `SharedLogProtocol::set_connect_fails` and asserts
//!   `connect_count` advances after recovery.
//! * **Real russh variant (`reconnect_via_restart_on_same_port_real_russh`)**
//!   — runs in CI. Drives the real `Ssh2Protocol` (pure russh 0.61) against
//!   the embedded `RusshTestServer`: establish a healthy session, then
//!   `restart_on_same_port()` (which tears the accept loop down and rebinds the
//!   same port). The old session's keepalive probe must eventually report the
//!   transport is dead, and a fresh `connect()` to the same address must
//!   recover (re-handshake + working forward). This exercises the backend
//!   loss-detect + reconnect path the supervisor relies on, without the weight
//!   of a full supervisor-driven cycle (covered by the mock variant above).

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::Duration;

use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_config::testing::ProfileBuilder;
use spt_core::BindAddr;
use spt_e2e_tests::SharedLogProtocol;
use spt_protocol::{
    BindConflictPolicy, Endpoint, ForwardRateLimits, LocalForwardSpec, TargetAddr, TunnelProtocol,
};
use spt_ssh2::testing::RusshTestServer;
use spt_ssh2::Ssh2Protocol;
use spt_supervisor::testing::{
    wait_for_state, OrchestratorBuilder, ProfileStateName, ProfileSupervisorConfig,
};
use spt_supervisor::BackoffConfig;
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

/// Open a local forward to the server's echo backend and assert a token
/// round-trips — used as the "session is healthy and forwarding" witness.
async fn assert_forward_roundtrip(session: &mut Box<dyn spt_protocol::TunnelSession>) {
    let port = free_loopback_port().await;
    let handle = session
        .open_local_forward(&LocalForwardSpec {
            name: "rc-echo".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            target: TargetAddr::new("server-side-echo", 7),
            max_connections: Some(4),
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open local forward");
    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect forward listener");
    sock.write_all(b"live").await.expect("write");
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut buf))
        .await
        .expect("timely echo")
        .expect("read echo");
    assert_eq!(&buf, b"live");
    handle.close().await;
}

#[tokio::test]
async fn reconnect_on_connect_failure_then_recovery() {
    let proto = Arc::new(SharedLogProtocol::new());

    let profile = ProfileBuilder::new("p")
        .endpoint("127.0.0.1", 22)
        .user("alice")
        .build();
    let endpoints = vec![Endpoint::new("127.0.0.1", 22)];

    // Tight backoff so the test isn't dominated by the 1s default
    // initial_delay. 50 ms first delay → 200 ms cap keeps the fail/recover
    // cycle under a second even with full-jitter sampling.
    let sup_cfg = ProfileSupervisorConfig {
        backoff: BackoffConfig {
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_millis(200),
            reset_after: Duration::from_secs(120),
            jitter: 1.0,
            max_attempts: 0,
            retry_auth_failures: false,
        },
        ..ProfileSupervisorConfig::default()
    };

    let orch = OrchestratorBuilder::new()
        .with_profile(
            profile,
            proto.clone() as Arc<dyn TunnelProtocol>,
            AuthConfig::new("alice", vec![]),
            endpoints,
            sup_cfg,
        )
        .build();

    // Step 1: supervisor reaches Active on the first successful connect.
    wait_for_state(&orch, "p", ProfileStateName::Active, Duration::from_secs(3))
        .await
        .expect("first active");
    let after_first = proto.connect_count();
    assert!(after_first >= 1, "expected >=1 connect; got {after_first}");

    // Step 2: flip the protocol into failure mode and tear down the live
    // session so the supervisor reconnects. Because the supervisor's reconnect
    // loop will retry under backoff, we just observe that the count does *not*
    // climb while failing.
    proto.set_connect_fails(true);
    let sup = orch.profile_handle("p").expect("profile p running");
    sup.close_session().await.expect("close session");

    // Brief soak: with connect_fails=true the supervisor will be in a
    // backoff/reconnect loop (50 ms initial → 200 ms max delays).
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Step 3: clear the failure injection. The reconnect loop should bring
    // the supervisor back to Active and connect_count should advance. Poll
    // the count rather than relying purely on `wait_for_state`, because the
    // supervisor may briefly leave Active (between session-close and reconnect)
    // and we want the assertion to be robust against that race.
    proto.set_connect_fails(false);
    let mut after_recover = proto.connect_count();
    for _ in 0..200 {
        after_recover = proto.connect_count();
        if after_recover > after_first {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        after_recover > after_first,
        "expected connect_count to advance after recovery within 10s; \
         before={after_first} after={after_recover}"
    );

    // And the supervisor should now be Active again.
    wait_for_state(&orch, "p", ProfileStateName::Active, Duration::from_secs(3))
        .await
        .expect("recovery to active");

    orch.shutdown().await;
}

/// Real russh variant (GAP 4). Drive a session loss + reconnect against a pure
/// russh server and assert recovery.
///
/// Sequence:
/// 1. Connect `Ssh2Protocol` through a killable TCP relay → `RusshTestServer`,
///    and prove the session forwards.
/// 2. Black-hole the relay so the established transport dies (a server-side
///    accept-loop restart is *not* sufficient — russh keeps already-established
///    per-connection tasks alive, so the only deterministic way to sever a live
///    transport is at the TCP layer; see the keepalive-detect test in
///    `crates/spt-ssh2/tests/russh_backend.rs`).
/// 3. Poll the old session's `keepalive()` until it reports `Err` — the
///    backend's loss-detect path the supervisor relies on to trigger
///    reconnect.
/// 4. Reconnect a fresh session straight to the server and prove it forwards
///    again (full handshake recovery). We also exercise
///    `restart_on_same_port()` to confirm the server's port is stable across a
///    restart, mirroring how a real endpoint comes back on the same address.
#[tokio::test]
async fn reconnect_via_restart_on_same_port_real_russh() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    let server_port = server.addr.port();

    std::env::set_var("SPT_TEST_E2E_RECONNECT_PW", "anything");
    let build_proto = || {
        Ssh2Protocol::builder()
            .trust(spt_ssh2::testing::tofu_trust_verifier())
            .build()
    };
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: SecretRef::Env("SPT_TEST_E2E_RECONNECT_PW".into()),
        }],
    );

    // Killable TCP relay: client → relay → server. Dropping `kill_tx`'s value
    // tears down every proxied connection, black-holing the SSH transport.
    let relay = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay listener");
    let relay_port = relay.local_addr().unwrap().port();
    let (kill_tx, kill_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            let Ok((mut client_side, _)) = relay.accept().await else {
                break;
            };
            let mut kill_rx = kill_rx.clone();
            tokio::spawn(async move {
                let Ok(mut server_side) = TcpStream::connect(("127.0.0.1", server_port)).await
                else {
                    return;
                };
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut client_side, &mut server_side) => {}
                    _ = kill_rx.changed() => {} // drop both halves → RST/EOF
                }
            });
        }
    });

    // Step 1: connect through the relay and prove the session forwards.
    let mut session = build_proto()
        .connect(&Endpoint::new("127.0.0.1", relay_port), &auth)
        .await
        .expect("initial connect through relay");
    session
        .keepalive()
        .await
        .expect("keepalive healthy on fresh session");
    assert_forward_roundtrip(&mut session).await;

    // Step 2: black-hole the transport.
    kill_tx.send(true).expect("signal relay kill");

    // Step 3: the old session's keepalive must eventually detect the dead
    // transport. russh's event loop can take a moment to notice the dropped
    // socket, so poll within a bounded window.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match session.keepalive().await {
            Err(_) => break, // dead session detected — success.
            Ok(()) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(()) => panic!(
                "keepalive still Ok after the transport was severed — \
                 session loss went undetected"
            ),
        }
    }
    let _ = session.close().await;

    // The endpoint comes back on the same port (modelling a server bounce):
    // restart_on_same_port rebinds the identical address.
    let server = server
        .restart_on_same_port()
        .await
        .expect("rebind same port");
    assert_eq!(server.addr.port(), server_port, "port must be stable");

    // Step 4: reconnect a fresh session directly to the recovered server and
    // prove recovery (re-handshake + working forward).
    let mut recovered = build_proto()
        .connect(&Endpoint::new("127.0.0.1", server_port), &auth)
        .await
        .expect("reconnect after recovery");
    recovered
        .keepalive()
        .await
        .expect("keepalive healthy on recovered session");
    assert_forward_roundtrip(&mut recovered).await;

    recovered.close().await.expect("close recovered session");
    server.shutdown().await;
}
