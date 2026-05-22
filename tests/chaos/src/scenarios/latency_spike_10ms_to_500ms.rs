//! Scenario 4 — **`latency_spike_10ms_to_500ms`**.
//!
//! Start the proxy at `LatencyMs(10)`. Let the supervisor connect
//! successfully. Then bump latency to `LatencyMs(500)` and assert *no
//! spurious reconnect attempt* fires. A reconnect under harmless latency
//! would indicate the supervisor is treating slow-but-alive as failed.
//!
//! ### Timing budget
//!
//! Each probe (`TcpStream::connect → write("keepalive\n") → read 1 byte`)
//! is throttled by the chaos proxy's per-chunk `LatencyMs` delay
//! roughly twice (once per direction of the round-trip), so under
//! `LatencyMs(500)` a single probe takes ≈ 1 s wall-clock. We use a
//! **per-probe timeout of 2 s** — well above the 500 ms injected spike,
//! and well below the production 30 s keepalive interval — so the
//! supervisor classifies the slow round-trip as success rather than
//! triggering a reconnect.
//!
//! Keepalive interval is 250 ms (rather than the 100 ms default the
//! `spawn_supervisor` shorthand uses) so probes don't pile up on a
//! 1 s actual probe duration; the 2 s test window therefore covers
//! ≥ 2 probes deterministically.
//!
//! Un-`#[ignore]`'d by t8-FixLatency once the per-probe timeout
//! became scenario-tunable via
//! [`spawn_supervisor_with_probe_timeout`]. See
//! `.orchestration/logs/t8-FixLatency.md`.

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor_with_probe_timeout, CountingObserver,
    EchoServer, ObserverGuard,
};
use spt_chaos_proxy::ChaosBehaviour;

#[tokio::test]
async fn latency_spike_10ms_to_500ms() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (proxy, proxy_addr, _proxy_task) =
        spawn_proxy_to(echo.addr(), ChaosBehaviour::LatencyMs(10)).await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let sup = spawn_supervisor_with_probe_timeout(
        "latency-spike",
        proxy_addr,
        fast_backoff(0),
        Duration::from_millis(250), // keepalive interval
        Duration::from_secs(2),     // per-probe timeout (≫ 500 ms latency)
    );

    // Wait for the first session to establish so we know the supervisor
    // is in `run_active` and the session-health loop is the only thing
    // exercising the proxy.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !obs.successes.lock().is_empty(),
        "expected first session to establish under LatencyMs(10)"
    );
    let baseline_attempts = obs.attempt_count();

    // Inject the latency spike.
    proxy.set_behaviour(ChaosBehaviour::LatencyMs(500));
    // Wait ≥2× keepalive interval plus enough wall-clock for ≥2 full
    // probes at the new latency (each ≈ 1 s) — but bounded so we don't
    // bloat the suite.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Restore pristine before assertions / cleanup so a slow assertion
    // host doesn't keep amplifying latency in the proxy.
    proxy.set_behaviour(ChaosBehaviour::Pristine);

    let attempts = obs.attempts_snapshot();
    let new_attempts = attempts.len().saturating_sub(baseline_attempts);
    assert_eq!(
        new_attempts, 0,
        "no spurious reconnects expected under 500 ms latency \
         (probe timeout is 2 s), got {new_attempts} new attempt(s): {attempts:?}"
    );

    sup.stop().await;
}
