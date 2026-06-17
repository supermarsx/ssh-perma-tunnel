//! e2e: local-forward wiring through the supervisor against the SSH2 backend.
//!
//! ## Variants
//!
//! * **Mock variant (`local_forward_wires_through_supervisor`)** — runs in CI.
//!   Uses the `SharedLogProtocol` from `spt_e2e_tests` so we can observe that
//!   the supervisor invokes `TunnelSession::open_local_forward` for the
//!   profile's local forward. The mock layer cannot move real bytes — the
//!   byte roundtrip is covered by the real russh sibling below.
//! * **Real russh variant (`local_forward_roundtrip_real_russh`)** — runs in
//!   CI. Drives the real `Ssh2Protocol` (pure russh 0.61 backend) against the
//!   embedded `RusshTestServer`, opens a `direct-tcpip` local forward, and
//!   asserts a byte payload round-trips through the server's echo handler.
//!   The original libssh2↔russh KEX blocker is gone now the backend is pure
//!   russh, so this is a real, non-ignored test (russh↔russh, no real
//!   network — `127.0.0.1:0` only).

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

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

fn profile_with_local_forward(name: &str, fname: &str) -> Profile {
    ProfileBuilder::new(name)
        .endpoint("127.0.0.1", 22)
        .user("alice")
        .add_forward(ForwardBuilder::local_tcp(fname, "127.0.0.1:0", "127.0.0.1:9").build())
        .build()
}

#[tokio::test]
async fn local_forward_wires_through_supervisor() {
    let proto = Arc::new(SharedLogProtocol::new());
    let log = Arc::clone(&proto.shared);

    let profile = profile_with_local_forward("p", "lf");
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

    // Wait briefly for the supervisor to invoke open_local_forward.
    let mut saw = false;
    for _ in 0..50 {
        if log
            .lock()
            .iter()
            .any(|c| matches!(c, SessionCall::OpenLocal(n) if n == "lf"))
        {
            saw = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        saw,
        "supervisor must call open_local_forward(lf); log = {:?}",
        log.lock()
    );

    orch.shutdown().await;
}

/// Real russh variant (GAP 4). The backend is now pure russh 0.61, so the
/// original libssh2↔russh KEX interop blocker no longer applies: this is a
/// russh client (`Ssh2Protocol`) talking to a russh server
/// (`RusshTestServer`), both on loopback. The server's
/// `channel_open_direct_tcpip` handler dials sentinel (non-loopback) targets
/// as an echo backend, so we open a local forward to `server-side-echo:7`,
/// connect a `TcpStream` to the local listener, and assert a multi-KiB
/// payload round-trips byte-for-byte.
#[tokio::test]
async fn local_forward_roundtrip_real_russh() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");

    std::env::set_var("SPT_TEST_E2E_LOCAL_PW", "anything");
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: SecretRef::Env("SPT_TEST_E2E_LOCAL_PW".into()),
        }],
    );
    let mut session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("russh backend connects");

    let port = free_loopback_port().await;
    let handle = session
        .open_local_forward(&LocalForwardSpec {
            name: "lf-echo".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            target: TargetAddr::new("server-side-echo", 7),
            max_connections: Some(4),
        })
        .await
        .expect("open local forward");

    // A multi-KiB payload exercises chunked channel-data, not just a token.
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect local forward listener");
    sock.write_all(&payload)
        .await
        .expect("write through forward");

    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut echoed))
        .await
        .expect("timely echo")
        .expect("read echo");
    assert_eq!(echoed, payload, "bytes must round-trip through the forward");

    handle.close().await;
    session.close().await.expect("close session");
    server.shutdown().await;
}
