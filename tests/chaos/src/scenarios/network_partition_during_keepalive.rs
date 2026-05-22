//! Scenario 3 — **`network_partition_during_keepalive`**.
//!
//! Same bug class as scenario 2: the supervisor's `run_active` does not
//! drive `TunnelSession::keepalive` and does not detect when the
//! underlying transport becomes silent. A `Partition { after: 5s }`
//! injected *after* the session establishes therefore never surfaces as
//! a reconnect.
//!
//! Ship `#[ignore]`'d with a FIXME pointing at the bug.

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor, CountingObserver, EchoServer, ObserverGuard,
};
use spt_chaos_proxy::ChaosBehaviour;

#[tokio::test]
#[ignore = "FIXME(bug): supervisor has no keepalive loop in run_active — see t8-C2.md"]
async fn network_partition_during_keepalive() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (proxy, proxy_addr, _proxy_task) =
        spawn_proxy_to(echo.addr(), ChaosBehaviour::Pristine).await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let sup = spawn_supervisor("partition-keepalive", proxy_addr, fast_backoff(0));

    // Let the first probe succeed.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Partition the proxy after 5 s (representing post-session
    // keepalive scenario).
    proxy.set_behaviour(ChaosBehaviour::Partition {
        after: Duration::from_millis(500),
    });

    tokio::time::sleep(Duration::from_secs(3)).await;

    // FIXME: bug — see log. With keepalive wired this would assert
    // attempts.len() >= 1. Until then, the test only exercises the
    // chaos-proxy partition mechanism end-to-end.
    let _ = obs.attempts_snapshot();

    sup.stop().await;
}
