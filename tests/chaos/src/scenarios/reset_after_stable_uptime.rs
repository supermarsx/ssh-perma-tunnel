//! Scenario 12 — **`reset_after_stable_uptime`**.
//!
//! Fixed by t8-FixSup: the supervisor now tracks `session_up_since`
//! and resets the `Backoff::attempt` counter on the *next* failure
//! only when the just-ended session was up for ≥ `reset_after`.
//!
//! This scenario verifies the spec §11.2 wording — "Backoff MUST
//! reset after a stable connected duration" — by:
//!   1. letting one session reach `ForwardsUp`,
//!   2. waiting longer than `reset_after`,
//!   3. forcing the proxy to RST so the next keepalive trips,
//!   4. asserting the first observed reconnect attempt is `1`, not
//!      a larger carry-over from earlier scheduling.

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor, CountingObserver, EchoServer, ObserverGuard,
};
use spt_chaos_proxy::ChaosBehaviour;

#[tokio::test]
async fn reset_after_stable_uptime() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (proxy, proxy_addr, _proxy_task) =
        spawn_proxy_to(echo.addr(), ChaosBehaviour::Pristine).await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let mut cfg = fast_backoff(0);
    cfg.reset_after = Duration::from_millis(300);
    let sup = spawn_supervisor("reset-after", proxy_addr, cfg);

    // Wait for first successful probe + at least one reset_after window.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Now force the proxy to RST: this triggers a keepalive failure,
    // which produces a reconnect attempt; that reconnect's connect
    // also fails (RST) and calls into next_backoff(), which is the
    // site that observes the >= reset_after uptime and resets the
    // counter.
    proxy.set_behaviour(ChaosBehaviour::RstAfterBytes(0));
    tokio::time::sleep(Duration::from_millis(700)).await;

    let attempts = obs.attempts_snapshot();
    assert!(
        !attempts.is_empty(),
        "expected ≥1 reconnect attempt after RST, got 0"
    );
    let first_attempt = attempts.first().map(|(n, _)| *n).unwrap_or(0);
    assert_eq!(
        first_attempt, 1,
        "post-reset_after first attempt should be 1 (got {first_attempt}); \
         all attempts = {attempts:?}"
    );

    sup.stop().await;
}
