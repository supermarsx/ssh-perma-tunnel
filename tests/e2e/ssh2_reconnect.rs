//! e2e: supervisor reconnect-on-failure wiring.
//!
//! ## Variants
//!
//! * **Mock variant (`reconnect_on_connect_failure_then_recovery`)** —
//!   runs in CI. Drives the supervisor through a fail/recover cycle by
//!   toggling `SharedLogProtocol::set_connect_fails` and asserts
//!   `connect_count` advances after recovery.
//! * **Real-libssh2 variant (`reconnect_via_restart_on_same_port`)** —
//!   `#[ignore]`'d. Would use `RunningRusshServer::restart_on_same_port` from
//!   the e3 helper expansion. Blocked on the same russh ↔ libssh2 KEX bug.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::Duration;

use spt_auth::AuthConfig;
use spt_config::testing::ProfileBuilder;
use spt_e2e_tests::SharedLogProtocol;
use spt_protocol::{Endpoint, TunnelProtocol};
use spt_supervisor::testing::{
    wait_for_state, OrchestratorBuilder, ProfileStateName, ProfileSupervisorConfig,
};
use spt_supervisor::BackoffConfig;

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

/// Real-libssh2 variant — uses [`spt_ssh2::testing::RunningRusshServer::restart_on_same_port`]
/// from the e3 helper expansion. Body deferred until the upstream russh ↔
/// libssh2 KEX bug is resolved. The helper is unit-tested in
/// `crates/spt-ssh2/src/testing.rs`.
#[tokio::test]
#[ignore = "russh<->libssh2 interop blocked at KEX (-8 KEY_EXCHANGE_FAILURE) — see \
crates/spt-ssh2/tests/russh_basic.rs for diagnosis."]
async fn reconnect_via_restart_on_same_port() {
    panic!("real-libssh2 variant intentionally unwritten; see #[ignore] reason");
}
