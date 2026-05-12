//! e2e: local-forward wiring through the supervisor against the SSH2 backend.
//!
//! ## Variants
//!
//! * **Mock variant (`local_forward_wires_through_supervisor`)** — runs in CI.
//!   Uses the `SharedLogProtocol` from `spt_e2e_tests` so we can observe that
//!   the supervisor invokes `TunnelSession::open_local_forward` for the
//!   profile's local forward. The mock layer cannot move real bytes — the
//!   16 KiB roundtrip is covered by the `#[ignore]`'d real-libssh2 sibling.
//! * **Real-libssh2 variant (`local_forward_16k_roundtrip_real_libssh2`)** —
//!   `#[ignore]`'d. Blocked upstream: see
//!   `crates/spt-ssh2/tests/russh_basic.rs` for the russh-0.46 ↔ libssh2-1.11.1
//!   (`WinCNG`) DH `KEY_EXCHANGE_FAILURE` diagnosis. Reason captured on the
//!   `#[ignore]` attribute.

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

/// Real-libssh2 variant. **Currently broken upstream** — see
/// `crates/spt-ssh2/tests/russh_basic.rs` module docs for the russh-0.46 ↔
/// libssh2-1.11.1 (WinCNG) DH `KEY_EXCHANGE_FAILURE` diagnosis. When the
/// upstream fix lands, drop the `#[ignore]` and write the body: spin up
/// `RusshTestServer`, build `Ssh2Protocol` with the WinCNG-compatible
/// `CryptoPolicy`, open a local forward, connect a `TcpStream` to the local
/// listener, and assert a 16 KiB echo roundtrip.
#[tokio::test]
#[ignore = "russh<->libssh2 interop blocked at KEX (-8 KEY_EXCHANGE_FAILURE) — see \
crates/spt-ssh2/tests/russh_basic.rs for diagnosis. Test body intentionally \
unwritten until upstream russh patch or libssh2 transport-state dive lands."]
async fn local_forward_16k_roundtrip_real_libssh2() {
    panic!("real-libssh2 variant intentionally unwritten; see #[ignore] reason");
}
