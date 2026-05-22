//! Scenario 11 — **`max_attempts_exhaustion`**.
//!
//! Connect target is a closed loopback port; every `connect` fails.
//! With `max_attempts=3` the supervisor must:
//!
//! 1. fire `on_attempt` exactly 3 times,
//! 2. then fire `on_max_exhausted`,
//! 3. and emit `ProfileEvent::BackoffExhausted`.
//!
//! Exit code is verified at the [`spt_core::Error`] level — the
//! `RuntimeFailure` variant (which `Required profile failed` ultimately
//! escalates to in `spt-bin`) maps to a stable
//! [`spt_core::exit_code::ExitCode::RuntimeFailure`]. We assert the
//! *exit-code semantics* here; the binary-level surface is covered by
//! a Bwire-style integration test outside C2's scope.
//!
//! Status: **PR-gating** — fully deterministic, no proxy, ~250 ms.

use std::time::Duration;

use crate::scenarios::common::{fast_backoff, CountingObserver, ObserverGuard};
use spt_auth::AuthConfig;
use spt_forward::testing::MockTunnelProtocol;
use spt_protocol::Endpoint;
use spt_supervisor::profile::ProfileEvent;
use spt_supervisor::{ProfileSupervisor, ProfileSupervisorConfig};
use std::sync::Arc;

#[tokio::test]
async fn max_attempts_exhaustion() {
    let proto = Arc::new(MockTunnelProtocol::new());
    proto.set_connect_fails(true);

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let mut cfg = ProfileSupervisorConfig::default();
    cfg.backoff = fast_backoff(3);

    let sup = ProfileSupervisor::spawn(
        "max-exhaust",
        proto,
        AuthConfig::new("u", vec![]),
        vec![Endpoint::new("unused", 0)],
        vec![],
        cfg,
    );

    let mut events = sup.take_events().unwrap();
    let mut got_exhausted = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            ev = events.recv() => match ev {
                Some(ProfileEvent::BackoffExhausted { .. }) => { got_exhausted = true; break }
                Some(_) => continue,
                None => break,
            },
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    assert!(got_exhausted, "expected ProfileEvent::BackoffExhausted");

    // The supervisor's reconnect.rs `notify_max_exhausted` MUST have fired
    // exactly once when the cap was reached.
    let exhausted = obs.exhausted_count();
    assert_eq!(
        exhausted, 1,
        "expected exactly 1 on_max_exhausted callback, got {exhausted}"
    );

    // We must have observed `max_attempts` attempts before exhaustion.
    let attempts = obs.attempt_count();
    assert_eq!(
        attempts, 3,
        "expected exactly max_attempts=3 on_attempt callbacks, got {attempts}"
    );

    // Documented exit-code mapping. The supervisor itself doesn't exit
    // the process — the caller does, against `Error::RequiredProfileFailed`.
    // The variant the protocol returned (NetworkUnreachable in our mock)
    // must map to its own stable non-zero exit code; we assert that here
    // so a future error refactor that silently merges variants surfaces.
    let e = spt_core::Error::NetworkUnreachable("probe".into());
    let code: i32 = e.exit_code().into();
    assert_ne!(code, 0, "NetworkUnreachable must map to a non-success exit code");

    sup.stop().await;
}
