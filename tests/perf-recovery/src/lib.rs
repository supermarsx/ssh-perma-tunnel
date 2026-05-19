//! Shared helpers for the `spt-perf-recovery` crate.
//!
//! Mirrors `tests/perf-startup/src/lib.rs` (separate copy — each standalone
//! crate ships its own lib to keep them buildable in isolation).
//!
//! Also hosts the schedulable mock-protocol used by recovery tests:
//! [`ScriptedTunnelProtocol`]. Each test scripts a per-connection failure
//! schedule (fail-N-then-succeed, fail-until-Instant, etc.) and measures the
//! time from "trigger fail" to "next session reaches Active".

#![forbid(unsafe_code)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::Serialize;
use spt_auth::AuthConfig;
use spt_core::{Error, Result};
use spt_forward::testing::MockTunnelSession;
use spt_protocol::{Endpoint, ProtocolCapabilities, TunnelProtocol, TunnelSession};

/// Default iteration count for recovery tests when no env override.
pub const DEFAULT_RECOVERY_ITERS: usize = 30;

/// Iteration-count env override.
pub const ITERS_ENV: &str = "SPT_PERF_ITERS";

/// Seed env override.
pub const SEED_ENV: &str = "SPT_PERF_SEED";

/// Run-id env override.
pub const RUN_ID_ENV: &str = "SPT_PERF_RUN_ID";

/// Resolve iteration count.
#[must_use]
pub fn iterations(default: usize) -> usize {
    std::env::var(ITERS_ENV)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

/// Resolve seed.
#[must_use]
pub fn seed() -> u64 {
    std::env::var(SEED_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Resolve run id.
#[must_use]
pub fn run_id() -> String {
    std::env::var(RUN_ID_ENV).unwrap_or_else(|_| {
        chrono::Utc::now()
            .format("%Y%m%dT%H%M%SZ")
            .to_string()
    })
}

// ---------------------------------------------------------------------------
// Report shapes (mirror perf-startup).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct TestReport {
    pub name: String,
    pub iterations: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
    pub threshold_p95_ms: Option<f64>,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrateReport {
    pub crate_name: String,
    pub run_id: String,
    pub seed: u64,
    pub tests: Vec<TestReport>,
}

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
    let sum: f64 = samples.iter().copied().map(to_ms).sum();
    let mean = sum / (n as f64);
    (p50, p95, max, mean)
}

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

fn locate_target_dir() -> std::io::Result<PathBuf> {
    if let Ok(custom) = std::env::var("CARGO_TARGET_DIR") {
        return Ok(PathBuf::from(custom));
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest.join("..").join("..").join("target"))
}

// ---------------------------------------------------------------------------
// ScriptedTunnelProtocol — controllable failure schedule.
// ---------------------------------------------------------------------------

/// What error flavor a scripted failure should emit. Picks an existing
/// `spt_core::Error` variant so the supervisor's existing classification
/// (network vs DNS vs transient) is exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Plain network unreachable — peer kill / partition shape.
    Network,
    /// DNS NXDOMAIN — `dns_loss` shape.
    Dns,
    /// Would-block / temporarily unavailable — partition shape.
    WouldBlock,
}

/// One scheduled failure mode.
#[derive(Debug, Clone, Default)]
pub enum FailurePlan {
    /// Never fail.
    #[default]
    None,
    /// Fail the next N `connect()` calls then succeed forever.
    FailNext {
        /// Remaining failures to emit.
        remaining: usize,
        /// Error flavor.
        kind: FailureKind,
    },
    /// Fail until `Instant::now() >= until`.
    FailUntil {
        /// Cutoff instant.
        until: Instant,
        /// Error flavor.
        kind: FailureKind,
    },
}

/// Tunnel protocol with a scheduled failure plan.
///
/// Holds an `Arc<Mutex<FailurePlan>>` so tests can rewrite the plan at any
/// time (e.g. "fail for the next 300ms"). Each `connect()` consults the plan
/// before deciding whether to return a session or an error.
#[derive(Debug, Clone, Default)]
pub struct ScriptedTunnelProtocol {
    /// Current schedule.
    pub plan: Arc<Mutex<FailurePlan>>,
    /// Counter of successful connects.
    pub connect_count: Arc<Mutex<u64>>,
    /// Counter of failed connects.
    pub fail_count: Arc<Mutex<u64>>,
}

impl ScriptedTunnelProtocol {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset to never-fail.
    pub fn reset(&self) {
        *self.plan.lock() = FailurePlan::None;
    }

    /// Schedule N upcoming connects to fail with `kind`.
    pub fn fail_next(&self, n: usize, kind: FailureKind) {
        *self.plan.lock() = FailurePlan::FailNext { remaining: n, kind };
    }

    /// Schedule connects to fail with `kind` until `until`.
    pub fn fail_until(&self, until: Instant, kind: FailureKind) {
        *self.plan.lock() = FailurePlan::FailUntil { until, kind };
    }

    /// Successful-connect counter.
    #[must_use]
    pub fn connect_count(&self) -> u64 {
        *self.connect_count.lock()
    }

    /// Failed-connect counter.
    #[must_use]
    pub fn fail_count(&self) -> u64 {
        *self.fail_count.lock()
    }
}

#[async_trait]
impl TunnelProtocol for ScriptedTunnelProtocol {
    async fn connect(
        &self,
        _endpoint: &Endpoint,
        _auth: &AuthConfig,
    ) -> Result<Box<dyn TunnelSession>> {
        // Decide outcome under lock, then drop the lock before awaiting/yielding.
        let outcome: std::result::Result<(), FailureKind> = {
            let mut plan = self.plan.lock();
            match &mut *plan {
                FailurePlan::None => Ok(()),
                FailurePlan::FailNext { remaining, kind } => {
                    if *remaining > 0 {
                        let k = *kind;
                        *remaining -= 1;
                        if *remaining == 0 {
                            *plan = FailurePlan::None;
                        }
                        Err(k)
                    } else {
                        *plan = FailurePlan::None;
                        Ok(())
                    }
                }
                FailurePlan::FailUntil { until, kind } => {
                    if Instant::now() < *until {
                        Err(*kind)
                    } else {
                        let _kept = *kind;
                        *plan = FailurePlan::None;
                        Ok(())
                    }
                }
            }
        };

        match outcome {
            Ok(()) => {
                *self.connect_count.lock() += 1;
                Ok(Box::new(MockTunnelSession::new()))
            }
            Err(kind) => {
                *self.fail_count.lock() += 1;
                Err(match kind {
                    FailureKind::Network => Error::NetworkUnreachable("scripted".into()),
                    FailureKind::Dns => Error::NetworkUnreachable("scripted-dns-nxdomain".into()),
                    FailureKind::WouldBlock => Error::NetworkUnreachable("scripted-wouldblock".into()),
                })
            }
        }
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::ssh3()
    }

    fn name(&self) -> &'static str {
        "scripted-mock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scripted_fail_next_then_succeed() {
        let proto = ScriptedTunnelProtocol::new();
        proto.fail_next(2, FailureKind::Network);
        let ep = Endpoint::new("h", 22);
        let auth = AuthConfig::new("u", vec![]);
        assert!(proto.connect(&ep, &auth).await.is_err());
        assert!(proto.connect(&ep, &auth).await.is_err());
        assert!(proto.connect(&ep, &auth).await.is_ok());
        assert_eq!(proto.fail_count(), 2);
        assert_eq!(proto.connect_count(), 1);
    }

    #[tokio::test]
    async fn scripted_fail_until_recovers() {
        let proto = ScriptedTunnelProtocol::new();
        proto.fail_until(Instant::now() + Duration::from_millis(50), FailureKind::WouldBlock);
        let ep = Endpoint::new("h", 22);
        let auth = AuthConfig::new("u", vec![]);
        assert!(proto.connect(&ep, &auth).await.is_err());
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(proto.connect(&ep, &auth).await.is_ok());
    }

    #[test]
    fn percentiles_basic() {
        let s: Vec<Duration> = (1..=10).map(|n| Duration::from_millis(n * 10)).collect();
        let (p50, p95, max, mean) = percentiles(s);
        assert!((p50 - 50.0).abs() < 0.01);
        assert!((p95 - 100.0).abs() < 0.01);
        assert!((max - 100.0).abs() < 0.01);
        assert!((mean - 55.0).abs() < 0.01);
    }
}
