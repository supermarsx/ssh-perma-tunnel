//! Peer-kill recovery bench.
//!
//! 1. Spin up an orchestrator with `ScriptedTunnelProtocol`, wait for Active.
//! 2. Schedule the *next* connect to fail (network error), then trigger
//!    `close_session()` so the supervisor must reconnect.
//! 3. Measure ms from `close_session()` returning to the profile reaching
//!    `Active` again (skipping over the one failed connect).
//!
//! `#[ignore]` by default — 30 iterations.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use spt_perf_recovery::{
    iterations, make_report, write_report, FailureKind, ScriptedTunnelProtocol,
    DEFAULT_RECOVERY_ITERS,
};
use spt_supervisor::testing::{
    wait_for_state, LiveReconnectTrigger, OrchestratorBuilder, ProfileStateName,
    ReconnectTrigger,
};

/// p95 ceiling for time-to-next-Active after a peer kill (ms).
pub const PEER_KILL_RECOVERY_P95_MS: f64 = 1_500.0;

async fn one_iteration() -> Duration {
    let proto: Arc<ScriptedTunnelProtocol> = Arc::new(ScriptedTunnelProtocol::new());
    let orch = OrchestratorBuilder::new()
        .with_profile_named("peer-kill", proto.clone())
        .build();
    wait_for_state(
        &orch,
        "peer-kill",
        ProfileStateName::Active,
        Duration::from_secs(5),
    )
    .await
    .expect("initial active");

    // Schedule one failure for the upcoming reconnect.
    proto.fail_next(1, FailureKind::Network);

    let sup = orch
        .profile_handle("peer-kill")
        .expect("supervisor handle");
    let trigger = LiveReconnectTrigger::new(sup);

    let t0 = Instant::now();
    trigger.trigger_drop().await.expect("trigger drop");
    // Force the supervisor through at least one failed connect before we
    // wait for Active — otherwise a `wait_for_state(Active)` racing the
    // drop could return immediately on the still-Active prior session.
    let deadline = Instant::now() + Duration::from_secs(15);
    while proto.fail_count() == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    wait_for_state(
        &orch,
        "peer-kill",
        ProfileStateName::Active,
        Duration::from_secs(10),
    )
    .await
    .expect("recovery to Active");
    let elapsed = t0.elapsed();

    orch.shutdown().await;
    elapsed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "perf bench — runs with `--ignored`"]
async fn peer_kill_recovery_suite() {
    let iters = iterations(DEFAULT_RECOVERY_ITERS);
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        samples.push(one_iteration().await);
    }
    let report = make_report(
        "recovery.peer_kill",
        samples,
        Some(PEER_KILL_RECOVERY_P95_MS),
    );
    eprintln!(
        "  {:30}  p50={:>8.2}ms  p95={:>8.2}ms  max={:>8.2}ms  n={}",
        report.name, report.p50_ms, report.p95_ms, report.max_ms, report.iterations,
    );
    let path = write_report("perf-recovery", vec![report.clone()]).expect("write");
    eprintln!("perf-recovery (peer_kill) report → {}", path.display());
    assert!(
        report.passed,
        "peer-kill p95 {:.2}ms exceeds threshold {:?}",
        report.p95_ms, report.threshold_p95_ms
    );
}

#[tokio::test]
async fn peer_kill_smoke() {
    let d = one_iteration().await;
    // Smoke just ensures the loop completes within a generous budget.
    assert!(d < Duration::from_secs(10));
}
