//! Warm-state-dir perf bench.
//!
//! Mirrors `cold_start.rs` but with a pre-populated state dir
//! (`sessions/`, `status.json` present). Times should be at or below the
//! cold-start times — we don't strictly enforce that comparison here
//! (cross-test ordering races with the OS filesystem cache), but we do
//! tighten the absolute p95 ceilings since warm-path I/O should be cheap.
//!
//! `#[ignore]` by default.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use spt_perf_startup::{
    iterations, locate_minimal_toml, locate_spt_bin, make_report, skipped_report, write_report,
    DEFAULT_STARTUP_ITERS,
};
use spt_supervisor::testing::{
    wait_for_state, MockTunnelProtocol, OrchestratorBuilder, ProfileStateName,
};
use tokio::process::Command;

// Warm thresholds: tighter than cold by ~25%.
pub const WARM_VERSION_P95_MS: f64 = 250.0;
pub const WARM_CONFIG_VALIDATE_P95_MS: f64 = 400.0;
pub const WARM_TUNNEL_READY_P95_MS: f64 = 200.0;

fn populate_warm_state_dir(root: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(root.join("sessions"))?;
    std::fs::write(
        root.join("status.json"),
        r#"{ "version": 1, "profiles": [] }"#,
    )?;
    // Touch a session file so the dir isn't pristine.
    std::fs::write(
        root.join("sessions").join("warm-anchor.json"),
        r#"{ "profile": "warm-anchor", "established_at": 0 }"#,
    )?;
    Ok(())
}

async fn measure_version(spt: &std::path::Path, state_dir: &std::path::Path, iters: usize) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();
        let status = Command::new(spt)
            .arg("--version")
            .env("SPT_STATE_DIR", state_dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .expect("spawn spt --version");
        let elapsed = t0.elapsed();
        assert!(status.success(), "spt --version exited {status:?}");
        samples.push(elapsed);
    }
    samples
}

async fn measure_config_validate(
    spt: &std::path::Path,
    cfg: &std::path::Path,
    state_dir: &std::path::Path,
    iters: usize,
) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();
        let _ = Command::new(spt)
            .args(["config", "validate", "--config"])
            .arg(cfg)
            .env("SPT_STATE_DIR", state_dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .expect("spawn spt config validate");
        samples.push(t0.elapsed());
    }
    samples
}

async fn measure_tunnel_ready(iters: usize) -> Vec<Duration> {
    // Warm tunnel-ready: keep the same protocol Arc across iterations so its
    // internal Arc<Mutex<...>> allocations stay hot. We still rebuild the
    // orchestrator per iteration (that's the unit-under-test).
    let proto: Arc<MockTunnelProtocol> = Arc::new(MockTunnelProtocol::new());
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();
        let orch = OrchestratorBuilder::new()
            .with_profile_named("perf-warm", proto.clone())
            .build();
        wait_for_state(
            &orch,
            "perf-warm",
            ProfileStateName::Active,
            Duration::from_secs(5),
        )
        .await
        .expect("perf-warm reaches Active");
        samples.push(t0.elapsed());
        orch.shutdown().await;
        drop(orch);
    }
    samples
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "perf bench — runs with `--ignored`"]
async fn warm_state_dir_suite() {
    let iters = iterations(DEFAULT_STARTUP_ITERS);

    // Build a state-dir-shaped temp dir for the subprocess variants.
    let state_root = std::env::temp_dir().join(format!(
        "spt-perf-warm-{}",
        std::process::id()
    ));
    populate_warm_state_dir(&state_root).expect("populate warm state dir");

    let mut reports = Vec::new();

    match locate_spt_bin() {
        Some(spt) => {
            let samples = measure_version(&spt, &state_root, iters).await;
            reports.push(make_report(
                "warm.version",
                samples,
                Some(WARM_VERSION_P95_MS),
            ));
        }
        None => reports.push(skipped_report("warm.version", "spt binary not located")),
    }

    match (locate_spt_bin(), locate_minimal_toml()) {
        (Some(spt), Some(cfg)) => {
            let samples = measure_config_validate(&spt, &cfg, &state_root, iters).await;
            reports.push(make_report(
                "warm.config_validate",
                samples,
                Some(WARM_CONFIG_VALIDATE_P95_MS),
            ));
        }
        (None, _) => {
            reports.push(skipped_report("warm.config_validate", "spt binary not located"));
        }
        (_, None) => {
            reports.push(skipped_report(
                "warm.config_validate",
                "examples/minimal.toml not found",
            ));
        }
    }

    let samples = measure_tunnel_ready(iters).await;
    reports.push(make_report(
        "warm.tunnel_ready",
        samples,
        Some(WARM_TUNNEL_READY_P95_MS),
    ));

    let path = write_report("perf-startup-warm", reports.clone()).expect("write warm report");
    eprintln!("perf-startup (warm) report → {}", path.display());

    for r in &reports {
        eprintln!(
            "  {:30}  p50={:>8.2}ms  p95={:>8.2}ms  max={:>8.2}ms  n={}  {}",
            r.name,
            r.p50_ms,
            r.p95_ms,
            r.max_ms,
            r.iterations,
            r.note.as_deref().unwrap_or(""),
        );
    }

    let _ = std::fs::remove_dir_all(&state_root);

    for r in &reports {
        assert!(
            r.passed,
            "{} p95 {:.2}ms exceeds threshold {:?}ms",
            r.name, r.p95_ms, r.threshold_p95_ms
        );
    }
}

#[tokio::test]
async fn warm_tunnel_ready_smoke() {
    let s = measure_tunnel_ready(1).await;
    assert_eq!(s.len(), 1);
}
