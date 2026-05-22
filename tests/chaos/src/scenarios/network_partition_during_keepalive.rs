//! Scenario 3 — **`network_partition_during_keepalive`**.
//!
//! Fixed by t8-FixSup: the supervisor now drives
//! `TunnelSession::keepalive` periodically in `run_active`. A
//! `Partition { after: … }` injected post-session causes the next
//! keepalive probe (a fresh TCP round-trip in the test
//! `ProbeSession`) to hang past the probe timeout and surface as
//! `Err`, which triggers the reconnect loop.

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor, CountingObserver, EchoServer, ObserverGuard,
};
use spt_chaos_proxy::ChaosBehaviour;

#[tokio::test]
async fn network_partition_during_keepalive() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (proxy, proxy_addr, _proxy_task) =
        spawn_proxy_to(echo.addr(), ChaosBehaviour::Pristine).await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let sup = spawn_supervisor("partition-keepalive", proxy_addr, fast_backoff(0));

    // Let the first probe succeed and the supervisor reach run_active.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Partition the proxy immediately — every newly accepted
    // connection becomes silent the moment it's spawned. The
    // probe-style `ProbeSession::keepalive` opens a fresh TCP per
    // call, so its `read()` will hang past the probe timeout and the
    // supervisor will reconnect.
    proxy.set_behaviour(ChaosBehaviour::Partition {
        after: Duration::from_millis(0),
    });

    tokio::time::sleep(Duration::from_secs(3)).await;

    let attempts = obs.attempts_snapshot();
    assert!(
        !attempts.is_empty(),
        "expected ≥1 reconnect attempt after partition, got 0"
    );

    sup.stop().await;
}
