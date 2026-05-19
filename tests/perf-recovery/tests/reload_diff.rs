//! Reload-latency bench: 100 forward changes in one profile.
//!
//! Two old/new `Config`s are constructed where profile `bench` has 100
//! forwards in the old config and 100 forwards in the new config, with
//! every forward's `target` field changed (forces 100 RemoveForward +
//! 100 AddForward, or equivalently 100 Restart-equivalent diffs depending
//! on the forward classifier).
//!
//! Latency measured: `ReloadPlan::compute(&old, &new)` + `Orchestrator::apply`
//! (with a noop provider — we are measuring the diff/apply plumbing, not
//! actual reconnect cost).
//!
//! 30 iterations, percentile reporting, `#[ignore]` by default.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use spt_auth::AuthConfig;
use spt_config::schema::{Config, Profile};
use spt_config::testing::{ConfigBuilder, ForwardBuilder, ProfileBuilder};
use spt_perf_recovery::{
    iterations, make_report, write_report, ScriptedTunnelProtocol, DEFAULT_RECOVERY_ITERS,
};
use spt_protocol::Endpoint;
use spt_supervisor::testing::{
    wait_for_state, OrchestratorBuilder, ProfileStateName, ProfileSupervisorConfig,
};
use spt_supervisor::ReloadPlan;

/// Number of forwards mutated per reload.
pub const FORWARD_CHANGES: usize = 100;

/// p95 ceiling for the compute+apply round of `FORWARD_CHANGES` forwards (ms).
pub const RELOAD_DIFF_P95_MS: f64 = 250.0;

fn make_profile(name: &str, forward_target_suffix: &str, n: usize) -> Profile {
    let mut b = ProfileBuilder::new(name).endpoint("127.0.0.1", 22).user("alice");
    for i in 0..n {
        let fwd = ForwardBuilder::local_tcp(
            &format!("f{i}"),
            &format!("127.0.0.1:{}", 20_000 + i),
            // Mutate the target — same forward name in both configs, but a
            // different target each time. `diff_forwards` will see the
            // forward "changed" and emit a RemoveForward + AddForward pair.
            &format!("upstream-{forward_target_suffix}-{i}:80"),
        )
        .build();
        b = b.add_forward(fwd);
    }
    b.build()
}

fn config_with_forwards(target_suffix: &str, n: usize) -> Config {
    ConfigBuilder::new()
        .add_profile(make_profile("bench", target_suffix, n))
        .build()
}

async fn one_iteration(proto: &Arc<ScriptedTunnelProtocol>) -> Duration {
    // Build an orchestrator running profile "bench" with 100 forwards already.
    let orch = OrchestratorBuilder::new()
        .with_profile_named("bench", proto.clone())
        .build();
    wait_for_state(
        &orch,
        "bench",
        ProfileStateName::Active,
        Duration::from_secs(5),
    )
    .await
    .expect("bench Active");

    let old_cfg = config_with_forwards("old", FORWARD_CHANGES);
    let new_cfg = config_with_forwards("new", FORWARD_CHANGES);

    let proto_clone = proto.clone();
    let new_profiles: Vec<Profile> = new_cfg.profiles.clone();

    let t0 = Instant::now();
    let plan = ReloadPlan::compute(&old_cfg, &new_cfg);
    orch.apply(&plan, move |name| {
        new_profiles.iter().find(|p| p.name == name).cloned().map(|p| {
            (
                p,
                proto_clone.clone() as Arc<dyn spt_protocol::TunnelProtocol>,
                AuthConfig::new("alice", vec![]),
                vec![Endpoint::new("127.0.0.1", 22)],
                ProfileSupervisorConfig::default(),
            )
        })
    })
    .await;
    let elapsed = t0.elapsed();

    orch.shutdown().await;
    elapsed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "perf bench — runs with `--ignored`"]
async fn reload_diff_suite() {
    let iters = iterations(DEFAULT_RECOVERY_ITERS);
    let proto: Arc<ScriptedTunnelProtocol> = Arc::new(ScriptedTunnelProtocol::new());
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        samples.push(one_iteration(&proto).await);
    }
    let report = make_report("recovery.reload_diff", samples, Some(RELOAD_DIFF_P95_MS));
    eprintln!(
        "  {:30}  p50={:>8.2}ms  p95={:>8.2}ms  max={:>8.2}ms  n={}",
        report.name, report.p50_ms, report.p95_ms, report.max_ms, report.iterations,
    );
    let path = write_report("perf-recovery", vec![report.clone()]).expect("write");
    eprintln!("perf-recovery (reload_diff) report → {}", path.display());
    assert!(
        report.passed,
        "reload-diff p95 {:.2}ms exceeds threshold {:?}",
        report.p95_ms, report.threshold_p95_ms
    );
}

#[tokio::test]
async fn reload_diff_smoke() {
    let proto: Arc<ScriptedTunnelProtocol> = Arc::new(ScriptedTunnelProtocol::new());
    let d = one_iteration(&proto).await;
    assert!(d < Duration::from_secs(15));
}
