//! Scenario 5 — **`rst_storm_100_per_sec`**.
//!
//! Real chaos proxy in front of an echo server, with
//! `ChaosBehaviour::RstAfterBytes(0)` — every connection is RST'd before
//! a byte flows. Supervisor is configured with `max_attempts = 5` so the
//! storm cleanly resolves to an exhaustion event in bounded time rather
//! than hammering the test runner.
//!
//! Assertions:
//!
//! * at least 2 `on_attempt` callbacks (i.e. the supervisor actually
//!   reconnected, didn't hang forever after the first RST),
//! * `on_max_exhausted` is hit exactly once,
//! * each captured delay is within the `[0, max_delay]` ceiling
//!   (full-jitter sanity).
//!
//! Status: **PR-gating** — `RstAfterBytes(0)` is fully deterministic on
//! the cross-platform proxy implementation per t8-C1.
//!
//! ~600 ms wall-clock.

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor, CountingObserver, EchoServer, ObserverGuard,
};
use spt_chaos_proxy::ChaosBehaviour;
use spt_supervisor::profile::ProfileEvent;

#[tokio::test]
async fn rst_storm_100_per_sec() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (_proxy, proxy_addr, _proxy_task) =
        spawn_proxy_to(echo.addr(), ChaosBehaviour::RstAfterBytes(0)).await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let sup = spawn_supervisor("rst-storm", proxy_addr, fast_backoff(5));
    let mut events = sup.take_events().unwrap();

    let mut got_exhausted = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
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

    assert!(got_exhausted, "expected BackoffExhausted under RST storm");
    let attempts = obs.attempts_snapshot();
    assert!(
        attempts.len() >= 2,
        "expected ≥2 reconnect attempts under RST storm, got {} ({:?})",
        attempts.len(),
        attempts
    );
    assert_eq!(
        obs.exhausted_count(),
        1,
        "expected exactly one on_max_exhausted"
    );

    // Full-jitter sanity: each captured delay must be ≤ max_delay (200ms
    // in fast_backoff). The supervisor uses thread_rng so we can't pin
    // values, only bounds.
    for (att, d) in &attempts {
        assert!(
            *d <= Duration::from_millis(200),
            "attempt {att} delay {d:?} exceeds max_delay 200ms"
        );
    }

    sup.stop().await;
}
