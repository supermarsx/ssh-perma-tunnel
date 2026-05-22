//! Scenario 12 — **`reset_after_stable_uptime`**.
//!
//! After `reset_after` of continuous uptime, the supervisor must reset
//! its `Backoff::attempt` counter so a subsequent failure starts fresh
//! at attempt 1.
//!
//! In the current supervisor surface, the only place the attempt
//! counter is reset is at `profile.rs:443 — self.backoff.reset()`,
//! immediately after `ForwardsUp`. That is **not** what the spec
//! describes: spec §11.2 wants reset *after `reset_after` of continuous
//! uptime*, but the implementation resets immediately on first success.
//!
//! That's a **bug surfaced** by this scenario: the `reset_after`
//! `BackoffConfig` field is currently effectively ignored. See
//! `.orchestration/logs/t8-C2.md`.
//!
//! Status: `#[ignore]`'d with FIXME until the supervisor honours
//! `reset_after`.

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor, CountingObserver, EchoServer, ObserverGuard,
};
use spt_chaos_proxy::ChaosBehaviour;

#[tokio::test]
#[ignore = "FIXME(bug): supervisor resets backoff on first ForwardsUp, not after reset_after — see t8-C2.md"]
async fn reset_after_stable_uptime() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (proxy, proxy_addr, _proxy_task) =
        spawn_proxy_to(echo.addr(), ChaosBehaviour::Pristine).await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let mut cfg = fast_backoff(0);
    cfg.reset_after = Duration::from_millis(500);
    let sup = spawn_supervisor("reset-after", proxy_addr, cfg);

    // Wait for first successful probe + at least one reset_after window.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Now force the proxy to RST: this triggers a failure.
    proxy.set_behaviour(ChaosBehaviour::RstAfterBytes(0));
    tokio::time::sleep(Duration::from_millis(500)).await;

    // FIXME: bug — see log. With the spec-correct implementation, the
    // first failure after reset_after should reset attempt to 0 and the
    // next on_attempt's `attempt` field should be 1, not N+1.
    let _ = obs.attempts_snapshot();

    sup.stop().await;
}
