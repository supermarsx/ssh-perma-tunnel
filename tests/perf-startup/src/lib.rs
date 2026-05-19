//! Shared helpers for the `spt-perf-startup` crate.
//!
//! Hand-rolled timing + percentile reporting + JSON report writer. We don't
//! pull `criterion` because the spec explicitly allows "just `Instant` +
//! sorted percentiles" and Criterion's machinery dominates ms-scale sample
//! noise we care about.
//!
//! # Determinism
//!
//! Iteration count and any synthetic randomness derive from
//! `SPT_PERF_SEED` (default: 0). The wall-clock timings themselves cannot
//! be made deterministic — what's deterministic is the *control flow* (same
//! count of operations, same mock failure schedule, same forward changes).
//!
//! # Acceptance thresholds
//!
//! Each test exports its own named `const` thresholds (e.g.
//! `COLD_VERSION_P95_MS`) and writes them into the per-run JSON report
//! alongside the measured values, so post-CI diffing can flag regressions.
//!
//! # Binary resolution
//!
//! `spt` binary path resolution follows this order:
//!
//! 1. `SPT_BIN` env var (preferred — CI sets it explicitly),
//! 2. `<crate>/../../target/release/spt[.exe]`,
//! 3. `<crate>/../../target/debug/spt[.exe]`,
//! 4. otherwise the test logs "skipped" and returns early.
//!
//! Never falls back to `PATH` — that's nondeterministic across machines.

#![forbid(unsafe_code)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

/// Default iteration count for cold-start tests when no env override.
pub const DEFAULT_STARTUP_ITERS: usize = 50;

/// Environment-variable override for iteration count.
pub const ITERS_ENV: &str = "SPT_PERF_ITERS";

/// Environment-variable override for the deterministic seed.
pub const SEED_ENV: &str = "SPT_PERF_SEED";

/// Environment variable that overrides the run id stamped into report.json.
pub const RUN_ID_ENV: &str = "SPT_PERF_RUN_ID";

/// Resolve effective iteration count for a test run.
#[must_use]
pub fn iterations(default: usize) -> usize {
    std::env::var(ITERS_ENV)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

/// Resolve the deterministic seed (default 0).
#[must_use]
pub fn seed() -> u64 {
    std::env::var(SEED_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Resolve the run id stamped into the report. Defaults to a UTC timestamp.
#[must_use]
pub fn run_id() -> String {
    std::env::var(RUN_ID_ENV).unwrap_or_else(|_| {
        chrono::Utc::now()
            .format("%Y%m%dT%H%M%SZ")
            .to_string()
    })
}

/// One measured sample distribution + threshold gate.
#[derive(Debug, Clone, Serialize)]
pub struct TestReport {
    /// Sub-test identifier.
    pub name: String,
    /// Iteration count.
    pub iterations: usize,
    /// 50th percentile, milliseconds.
    pub p50_ms: f64,
    /// 95th percentile, milliseconds.
    pub p95_ms: f64,
    /// Max sample, milliseconds.
    pub max_ms: f64,
    /// Mean, milliseconds.
    pub mean_ms: f64,
    /// Acceptance threshold for `p95_ms`, milliseconds. `None` if advisory.
    pub threshold_p95_ms: Option<f64>,
    /// Whether `p95_ms <= threshold_p95_ms` (always true if threshold is None).
    pub passed: bool,
    /// Optional message (e.g. "skipped: spt binary not found").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Top-level JSON written to `target/perf/<crate>/<run-id>.json`.
#[derive(Debug, Clone, Serialize)]
pub struct CrateReport {
    /// Crate name (e.g. "perf-startup").
    pub crate_name: String,
    /// Run id (e.g. timestamp or CI build id).
    pub run_id: String,
    /// Seed used for deterministic sub-control flow.
    pub seed: u64,
    /// One entry per sub-test.
    pub tests: Vec<TestReport>,
}

/// Compute p50/p95/max from a non-empty vector of durations.
#[must_use]
pub fn percentiles(mut samples: Vec<Duration>) -> (f64, f64, f64, f64) {
    assert!(!samples.is_empty(), "percentiles on empty sample set");
    samples.sort_unstable();
    let to_ms = |d: Duration| (d.as_secs_f64() * 1000.0);
    let n = samples.len();
    let p50_idx = (n * 50).div_ceil(100).saturating_sub(1).min(n - 1);
    let p95_idx = (n * 95).div_ceil(100).saturating_sub(1).min(n - 1);
    let p50 = to_ms(samples[p50_idx]);
    let p95 = to_ms(samples[p95_idx]);
    let max = to_ms(samples[n - 1]);
    let sum_ms: f64 = samples.iter().copied().map(to_ms).sum();
    let mean = sum_ms / (n as f64);
    (p50, p95, max, mean)
}

/// Build a [`TestReport`] from raw samples + optional p95 threshold.
#[must_use]
pub fn make_report(
    name: &str,
    samples: Vec<Duration>,
    threshold_p95_ms: Option<f64>,
) -> TestReport {
    let iterations = samples.len();
    let (p50_ms, p95_ms, max_ms, mean_ms) = percentiles(samples);
    let passed = threshold_p95_ms.map_or(true, |t| p95_ms <= t);
    TestReport {
        name: name.to_owned(),
        iterations,
        p50_ms,
        p95_ms,
        max_ms,
        mean_ms,
        threshold_p95_ms,
        passed,
        note: None,
    }
}

/// Build a "skipped" report — recorded but with no samples and `passed=true`.
#[must_use]
pub fn skipped_report(name: &str, reason: &str) -> TestReport {
    TestReport {
        name: name.to_owned(),
        iterations: 0,
        p50_ms: 0.0,
        p95_ms: 0.0,
        max_ms: 0.0,
        mean_ms: 0.0,
        threshold_p95_ms: None,
        passed: true,
        note: Some(format!("skipped: {reason}")),
    }
}

/// Resolve `target/perf/<crate>` and write `<run-id>.json`.
pub fn write_report(crate_name: &str, tests: Vec<TestReport>) -> std::io::Result<PathBuf> {
    let report = CrateReport {
        crate_name: crate_name.to_owned(),
        run_id: run_id(),
        seed: seed(),
        tests,
    };
    let target = locate_target_dir()?.join("perf").join(crate_name);
    std::fs::create_dir_all(&target)?;
    let out_path = target.join(format!("{}.json", report.run_id));
    let body = serde_json::to_vec_pretty(&report)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&out_path, body)?;
    Ok(out_path)
}

/// Best-effort locate `target/` directory relative to this crate.
fn locate_target_dir() -> std::io::Result<PathBuf> {
    // Standalone crate lives at <repo>/tests/perf-startup; the main workspace
    // target sits two levels up. Some CI runners may set CARGO_TARGET_DIR;
    // honor that first.
    if let Ok(custom) = std::env::var("CARGO_TARGET_DIR") {
        return Ok(PathBuf::from(custom));
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest.join("..").join("..").join("target"))
}

/// Locate the `spt` binary. Returns `None` to signal "skip this measurement".
#[must_use]
pub fn locate_spt_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SPT_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_root = manifest.join("..").join("..").join("target");
    let exe = if cfg!(windows) { "spt.exe" } else { "spt" };
    for profile in ["release", "debug"] {
        let candidate = target_root.join(profile).join(exe);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Locate `examples/minimal.toml` relative to this crate.
#[must_use]
pub fn locate_minimal_toml() -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest
        .join("..")
        .join("..")
        .join("examples")
        .join("minimal.toml");
    if path.is_file() {
        Some(path)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_basic() {
        let samples: Vec<Duration> = (1..=10)
            .map(|n| Duration::from_millis(n * 10))
            .collect();
        let (p50, p95, max, mean) = percentiles(samples);
        // Sorted: 10,20,30,40,50,60,70,80,90,100 ms.
        assert!((p50 - 50.0).abs() < 0.01);
        assert!((p95 - 100.0).abs() < 0.01);
        assert!((max - 100.0).abs() < 0.01);
        assert!((mean - 55.0).abs() < 0.01);
    }

    #[test]
    fn report_pass_fail_gate() {
        let samples: Vec<Duration> = (1..=10)
            .map(|n| Duration::from_millis(n * 10))
            .collect();
        let pass = make_report("ok", samples.clone(), Some(200.0));
        assert!(pass.passed);
        let fail = make_report("bad", samples, Some(50.0));
        assert!(!fail.passed);
    }
}
