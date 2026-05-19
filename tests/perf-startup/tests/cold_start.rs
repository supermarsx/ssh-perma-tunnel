//! Cold-start perf bench.
//!
//! Three measurements:
//!
//! 1. `spt --version` exec time (subprocess) — wall-clock from spawn → exit.
//! 2. `spt config validate --config examples/minimal.toml` exec time.
//! 3. `tunnel run` time-to-Ready against an in-process `MockTunnelProtocol`
//!    (NOT a subprocess; we measure `Orchestrator` startup → first profile
//!    reaches `ProfileStateName::Active`).
//!
//! All three run `iterations()` times; we report p50/p95/max and write
//! `target/perf/perf-startup/<run-id>.json`.
//!
//! `#[ignore]` by default — CI runs them on a `perf-startup` label.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use spt_auth::AuthConfig;
use spt_perf_startup::{
    iterations, locate_minimal_toml, locate_spt_bin, make_report, skipped_report, write_report,
    DEFAULT_STARTUP_ITERS,
};
use spt_protocol::Endpoint;
use spt_supervisor::testing::{
    wait_for_state, MockTunnelProtocol, OrchestratorBuilder, ProfileStateName,
};
use tokio::process::Command;

// ---------------------------------------------------------------------------
// Acceptance thresholds (named consts so post-CI diffing has a clear target).
// ---------------------------------------------------------------------------

/// p95 ceiling for `spt --version` cold exec (ms).
pub const COLD_VERSION_P95_MS: f64 = 300.0;

/// p95 ceiling for `spt config validate examples/minimal.toml` (ms).
pub const COLD_CONFIG_VALIDATE_P95_MS: f64 = 500.0;

/// p95 ceiling for in-process `tunnel run` time-to-Ready (ms).
pub const COLD_TUNNEL_READY_P95_MS: f64 = 250.0;

// ---------------------------------------------------------------------------

async fn measure_version_cold(spt: &std::path::Path, iters: usize) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();
        let status = Command::new(spt)
            .arg("--version")
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

async fn measure_config_validate_cold(
    spt: &std::path::Path,
    cfg: &std::path::Path,
    iters: usize,
) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();
        let status = Command::new(spt)
            .args(["config", "validate", "--config"])
            .arg(cfg)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .expect("spawn spt config validate");
        let elapsed = t0.elapsed();
        // We don't require success — the bench is about cold parse cost. We
        // *do* require the process actually ran (exited).
        let _ = status;
        samples.push(elapsed);
    }
    samples
}

async fn measure_tunnel_ready_in_process(iters: usize) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let proto: Arc<MockTunnelProtocol> = Arc::new(MockTunnelProtocol::new());
        let t0 = Instant::now();
        let orch = OrchestratorBuilder::new()
            .with_profile_named("perf", proto.clone())
            .build();
        // Time-to-Ready = build + first Active.
        wait_for_state(&orch, "perf", ProfileStateName::Active, Duration::from_secs(5))
            .await
            .expect("perf profile reaches Active");
        samples.push(t0.elapsed());

        // Tear down before next iteration so we measure cold path each time.
        orch.shutdown().await;
        // Drop the protocol Arc; new one constructed on next loop.
        drop(orch);
        let _ = proto;
    }
    samples
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "perf bench — runs only with `cargo test --features perf` or `--ignored`"]
async fn cold_start_suite() {
    let iters = iterations(DEFAULT_STARTUP_ITERS);
    let mut reports = Vec::new();

    // ----- spt --version
    match locate_spt_bin() {
        Some(spt) => {
            let samples = measure_version_cold(&spt, iters).await;
            reports.push(make_report(
                "cold.version",
                samples,
                Some(COLD_VERSION_P95_MS),
            ));
        }
        None => {
            reports.push(skipped_report(
                "cold.version",
                "spt binary not located (set SPT_BIN or build the workspace)",
            ));
        }
    }

    // ----- spt config validate
    match (locate_spt_bin(), locate_minimal_toml()) {
        (Some(spt), Some(cfg)) => {
            let samples = measure_config_validate_cold(&spt, &cfg, iters).await;
            reports.push(make_report(
                "cold.config_validate",
                samples,
                Some(COLD_CONFIG_VALIDATE_P95_MS),
            ));
        }
        (None, _) => {
            reports.push(skipped_report(
                "cold.config_validate",
                "spt binary not located",
            ));
        }
        (_, None) => {
            reports.push(skipped_report(
                "cold.config_validate",
                "examples/minimal.toml not found",
            ));
        }
    }

    // ----- tunnel run → Ready (in-process MockTunnelProtocol)
    let samples = measure_tunnel_ready_in_process(iters).await;
    reports.push(make_report(
        "cold.tunnel_ready",
        samples,
        Some(COLD_TUNNEL_READY_P95_MS),
    ));

    // Persist report regardless of pass/fail so trend diffing has data.
    let path = write_report("perf-startup", reports.clone()).expect("write report");
    eprintln!("perf-startup report → {}", path.display());

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

    for r in &reports {
        assert!(
            r.passed,
            "{} p95 {:.2}ms exceeds threshold {:?}ms",
            r.name, r.p95_ms, r.threshold_p95_ms
        );
    }
}

// Lightweight smoke (not #[ignore]) so the harness is exercised in normal CI.
#[tokio::test]
async fn tunnel_ready_smoke_one_iteration() {
    let samples = measure_tunnel_ready_in_process(1).await;
    assert_eq!(samples.len(), 1);
}

// Hold an unused `AuthConfig` to keep the dep visibly part of the crate's
// graph (some downstream invocations exercise it). The compiler would warn
// if we imported the symbol but never used it.
#[allow(dead_code)]
fn _unused_dep_anchor() -> AuthConfig {
    AuthConfig::new("u", vec![])
}

#[allow(dead_code)]
fn _unused_dep_anchor_endpoint() -> Endpoint {
    Endpoint::new("h", 22)
}
