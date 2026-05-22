//! Scenario 2 — **`kill_server_mid_data`**.
//!
//! Fixed by t8-FixSup: `ProfileTask::run_active` now polls
//! `TunnelSession::keepalive` on `cfg.keepalive_interval`. When the
//! chaos proxy starts RST'ing mid-session, the keepalive probe fails
//! and the supervisor triggers a reconnect — which then keeps failing
//! and produces observable `on_attempt` callbacks.

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor, CountingObserver, EchoServer, ObserverGuard,
};
use spt_chaos_proxy::ChaosBehaviour;

#[tokio::test]
async fn kill_server_mid_data() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (proxy, proxy_addr, _proxy_task) =
        spawn_proxy_to(echo.addr(), ChaosBehaviour::Pristine).await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let sup = spawn_supervisor("kill-mid-data", proxy_addr, fast_backoff(5));

    // Let the first session establish.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let initial_successes = obs.successes.lock().len();
    assert!(initial_successes >= 1, "expected first session to come up");

    // Kill the proxy — keepalive probes will now fail, then every
    // subsequent connect attempt will fail too.
    proxy.set_behaviour(ChaosBehaviour::RstAfterBytes(0));

    // Wait long enough for keepalive (100ms interval) to fire, fail,
    // and produce at least one reconnect attempt.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let attempts = obs.attempts_snapshot();
    assert!(
        !attempts.is_empty(),
        "expected ≥1 reconnect attempt after mid-data kill, got 0"
    );

    sup.stop().await;
}
