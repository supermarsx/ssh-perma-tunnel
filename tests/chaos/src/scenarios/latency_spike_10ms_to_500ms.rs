//! Scenario 4 — **`latency_spike_10ms_to_500ms`**.
//!
//! Start the proxy at `LatencyMs(10)`. Let the supervisor connect
//! successfully. Then bump latency to `LatencyMs(500)` — well below the
//! probe timeout (1 s) — and assert *no spurious reconnect attempt*
//! fires.  A reconnect under harmless latency would indicate the
//! supervisor is treating slow-but-alive as failed.
//!
//! `#[ignore]`'d because the probe protocol's `connect` only does one
//! round-trip; without a session-health loop the supervisor never
//! re-probes, so this scenario is trivially passing in the current
//! supervisor surface. Documented for the day that loop lands.

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor, CountingObserver, EchoServer, ObserverGuard,
    TcpProbeProtocol,
};
use spt_chaos_proxy::ChaosBehaviour;

#[tokio::test]
#[ignore = "trivially passing until supervisor adds session-health re-probes — see t8-C2.md"]
async fn latency_spike_10ms_to_500ms() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (proxy, proxy_addr, _proxy_task) =
        spawn_proxy_to(echo.addr(), ChaosBehaviour::LatencyMs(10)).await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let sup = spawn_supervisor("latency-spike", proxy_addr, fast_backoff(0));

    // Make sure first probe completed.
    tokio::time::sleep(Duration::from_millis(300)).await;

    proxy.set_behaviour(ChaosBehaviour::LatencyMs(500));
    tokio::time::sleep(Duration::from_secs(2)).await;

    let attempts = obs.attempts_snapshot();
    assert!(
        attempts.is_empty() || attempts.len() == 1,
        "no spurious reconnects expected under harmless latency, got {attempts:?}"
    );

    sup.stop().await;
    let _ = TcpProbeProtocol::new(proxy_addr); // import keep-alive
}
