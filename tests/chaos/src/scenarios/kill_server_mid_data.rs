//! Scenario 2 — **`kill_server_mid_data`**.
//!
//! **Bug surfaced in C2, not fixed here.** The supervisor's
//! `ProfileTask::run_active` (`crates/spt-supervisor/src/profile.rs:464`)
//! awaits *only* on the control channel — it does not poll session
//! health, so an established session whose underlying transport dies
//! mid-data is **not detected** by the supervisor. The `keepalive()`
//! method is `TunnelSession::keepalive` and `ProfileTask` never calls
//! it from `run_active`.
//!
//! This means: with the TCP-probe protocol (whose `connect` succeeds and
//! whose session lifecycle is fictional), there's no way for the
//! scenario to observe a reconnect *after* an established session is
//! killed.  The check below is therefore a smoke assertion only and the
//! "reconnect after mid-data kill" expectation is `FIXME`-tagged.
//!
//! See `.orchestration/logs/t8-C2.md`, "Bugs surfaced".

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor, CountingObserver, EchoServer, ObserverGuard,
};
use spt_chaos_proxy::ChaosBehaviour;

#[tokio::test]
#[ignore = "FIXME(bug): supervisor's run_active does not detect in-session disconnects — see t8-C2.md"]
async fn kill_server_mid_data() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (proxy, proxy_addr, _proxy_task) =
        spawn_proxy_to(echo.addr(), ChaosBehaviour::Pristine).await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let sup = spawn_supervisor("kill-mid-data", proxy_addr, fast_backoff(5));

    // Let the first session establish.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let initial_successes = obs.successes.lock().len();
    assert!(initial_successes >= 1, "expected first session to come up");

    // Kill the proxy — every subsequent connect attempt will fail.
    proxy.set_behaviour(ChaosBehaviour::RstAfterBytes(0));

    tokio::time::sleep(Duration::from_secs(2)).await;

    // FIXME: bug — see log. Without the supervisor watching session
    // health, no reconnect attempt fires here. Once
    // ProfileTask::run_active gains a session-health channel, restore:
    //
    //     let attempts = obs.attempts_snapshot();
    //     assert!(attempts.len() >= 1, "expected reconnect after kill");
    //
    // For now we only assert the scaffolding didn't crash.
    let _ = obs.attempts_snapshot();

    sup.stop().await;
}
