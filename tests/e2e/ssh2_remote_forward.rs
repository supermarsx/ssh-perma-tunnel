//! e2e: remote-forward wiring through the supervisor against the SSH2 backend.
//!
//! ## Variants
//!
//! * **Mock variant (`remote_forward_wires_through_supervisor`)** — runs in CI.
//!   Asserts the supervisor invokes `TunnelSession::open_remote_forward` for
//!   the profile's remote forward.
//! * **Real-libssh2 variant (`remote_forward_roundtrip_real_libssh2`)** —
//!   `#[ignore]`'d. Blocked on the same russh ↔ libssh2 KEX bug as the local
//!   variant; see `crates/spt-ssh2/tests/russh_basic.rs`.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::Duration;

use spt_auth::AuthConfig;
use spt_config::schema::Profile;
use spt_config::testing::{ForwardBuilder, ProfileBuilder};
use spt_e2e_tests::SharedLogProtocol;
use spt_forward::testing::SessionCall;
use spt_protocol::{Endpoint, TunnelProtocol};
use spt_supervisor::testing::{
    wait_for_state, OrchestratorBuilder, ProfileStateName, ProfileSupervisorConfig,
};

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

/// Real-libssh2 variant. Same upstream block as the local-forward sibling.
/// When fixed, the body should: configure `RusshTestServer` (its
/// `tcpip_forward` handler binds a real loopback listener and pipes inbound
/// bytes back over a `forwarded-tcpip` channel), drive `Ssh2Protocol` to
/// request `tcpip-forward`, then push bytes to the server-side listener and
/// assert they're echoed back on the SSH client side.
#[tokio::test]
#[ignore = "russh<->libssh2 interop blocked at KEX (-8 KEY_EXCHANGE_FAILURE) — see \
crates/spt-ssh2/tests/russh_basic.rs for diagnosis."]
async fn remote_forward_roundtrip_real_libssh2() {
    panic!("real-libssh2 variant intentionally unwritten; see #[ignore] reason");
}
