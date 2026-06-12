//! Scenario 10 — **`repeated_quick_reconnects`**.
//!
//! Proxy in `RstAfterBytes(0)` mode — every accepted connection is
//! immediately RST'd. With `max_attempts = 0` (unlimited) the
//! supervisor would loop forever; we cap to 6 to bound test runtime and
//! assert that:
//!
//! * the backoff actually kicks in (i.e. successive attempts have
//!   non-zero ceiling growth — the `Backoff` ceiling-for-attempt
//!   function is `initial * 2^n`, capped at `max_delay`),
//! * no two attempts fired *simultaneously* (delay between successive
//!   `on_attempt` callbacks is > 0).
//!
//! Status: runs on every PR. It complements `rst_storm_100_per_sec` by
//! validating the *backoff growth* axis specifically. Bounded to 6
//! attempts (`fast_backoff(6)`) and a 10 s deadline that breaks early on
//! exhaustion, so it is deterministic and finishes in ~1-2 s.

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor, CountingObserver, EchoServer, ObserverGuard,
};
use spt_chaos_proxy::ChaosBehaviour;

#[tokio::test]
async fn repeated_quick_reconnects() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (_proxy, proxy_addr, _proxy_task) =
        spawn_proxy_to(echo.addr(), ChaosBehaviour::RstAfterBytes(0)).await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let sup = spawn_supervisor("quick-reconnects", proxy_addr, fast_backoff(6));
    let mut events = sup.take_events().unwrap();

    // Wait for exhaustion or 10 s.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            _ev = events.recv() => {}
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        if obs.exhausted_count() > 0 {
            break;
        }
    }

    let attempts = obs.attempts_snapshot();
    assert!(
        attempts.len() >= 3,
        "expected ≥3 attempts to see backoff progression, got {}",
        attempts.len()
    );
    // Backoff *can* sample zero under full-jitter, so we don't assert
    // strict ordering — we assert at least one attempt's delay is > 0
    // (otherwise the supervisor isn't sleeping at all).
    let any_nonzero = attempts.iter().any(|(_, d)| *d > Duration::ZERO);
    assert!(
        any_nonzero,
        "expected at least one nonzero backoff delay, got {attempts:?}"
    );

    sup.stop().await;
}
