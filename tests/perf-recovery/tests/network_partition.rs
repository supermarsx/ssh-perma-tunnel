//! Network-partition recovery bench.
//!
//! Schedule `WouldBlock` failures for a fixed `PARTITION_MS` window, then
//! drop the session. Measure ms from drop to next Active. Because the
//! supervisor will back off after each failed connect, recovery time is
//! roughly `PARTITION_MS` + one backoff slot + reconnect cost.
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

/// Length of the simulated partition (ms).
pub const PARTITION_MS: u64 = 200;

/// p95 ceiling for partition-recovery time-to-Active (ms). Allows partition
/// length + 2s headroom for supervisor backoff/jitter.
pub const PARTITION_RECOVERY_P95_MS: f64 = (PARTITION_MS as f64) + 2_500.0;

async fn one_iteration() -> Duration {
    let proto: Arc<ScriptedTunnelProtocol> = Arc::new(ScriptedTunnelProtocol::new());
    let orch = OrchestratorBuilder::new()
        .with_profile_named("partition", proto.clone())
        .build();
    wait_for_state(
        &orch,
        "partition",
        ProfileStateName::Active,
        Duration::from_secs(5),
    )
    .await
    .expect("initial active");

    // Open the partition: future connects return WouldBlock for PARTITION_MS.
    proto.fail_until(
        Instant::now() + Duration::from_millis(PARTITION_MS),
        FailureKind::WouldBlock,
    );

    let sup = orch
        .profile_handle("partition")
        .expect("supervisor handle");
    let trigger = LiveReconnectTrigger::new(sup);

    let t0 = Instant::now();
    trigger.trigger_drop().await.expect("drop");
    // Force the supervisor through at least one failed connect first.
    let deadline = Instant::now() + Duration::from_secs(15);
    while proto.fail_count() == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    wait_for_state(
        &orch,
        "partition",
        ProfileStateName::Active,
        Duration::from_secs(15),
    )
    .await
    .expect("recovery");
    let elapsed = t0.elapsed();

    orch.shutdown().await;
    elapsed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "perf bench — runs with `--ignored`"]
async fn network_partition_suite() {
    let iters = iterations(DEFAULT_RECOVERY_ITERS);
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        samples.push(one_iteration().await);
    }
    let report = make_report(
        "recovery.network_partition",
        samples,
        Some(PARTITION_RECOVERY_P95_MS),
    );
    eprintln!(
        "  {:30}  p50={:>8.2}ms  p95={:>8.2}ms  max={:>8.2}ms  n={}",
        report.name, report.p50_ms, report.p95_ms, report.max_ms, report.iterations,
    );
    let path = write_report("perf-recovery", vec![report.clone()]).expect("write");
    eprintln!("perf-recovery (partition) report → {}", path.display());
    assert!(
        report.passed,
        "partition p95 {:.2}ms exceeds threshold {:?}",
        report.p95_ms, report.threshold_p95_ms
    );
}

#[tokio::test]
async fn partition_smoke() {
    let d = one_iteration().await;
    assert!(d < Duration::from_secs(15));
}
