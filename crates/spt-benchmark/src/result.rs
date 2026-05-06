//! Benchmark result schema (spec §13.13).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Latency percentiles in milliseconds.
#[allow(clippy::struct_field_names)] // every field is a duration in ms — naming is intentional
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Percentiles {
    /// 50th percentile (median).
    pub p50_ms: f64,
    /// 90th.
    pub p90_ms: f64,
    /// 99th.
    pub p99_ms: f64,
    /// 99.9th.
    pub p999_ms: f64,
    /// Worst observed.
    pub max_ms: f64,
}

impl Percentiles {
    /// Compute percentiles from a sample slice. The slice is sorted in
    /// place (caller passes a mutable copy). Empty slice → all zeros.
    pub fn from_samples(samples: &mut [f64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let pick = |q: f64| {
            let idx = ((samples.len() as f64 - 1.0) * q).round() as usize;
            samples[idx.min(samples.len() - 1)]
        };
        Self {
            p50_ms: pick(0.50),
            p90_ms: pick(0.90),
            p99_ms: pick(0.99),
            p999_ms: pick(0.999),
            max_ms: *samples.last().unwrap(),
        }
    }
}

/// Numeric metrics. Drivers populate the subset they care about.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MetricSet {
    /// Latency percentiles, when measured.
    #[serde(default)]
    pub latency: Option<Percentiles>,
    /// Throughput in bytes/sec, when measured.
    #[serde(default)]
    pub throughput_bps: Option<f64>,
    /// Packet rate (pps), used by UDP drivers.
    #[serde(default)]
    pub packets_per_sec: Option<f64>,
    /// Loss rate (0.0..=1.0).
    #[serde(default)]
    pub loss_ratio: Option<f64>,
    /// Jitter in milliseconds.
    #[serde(default)]
    pub jitter_ms: Option<f64>,
    /// Free-form scalar bag. Useful for limits/reconnect drivers.
    #[serde(default)]
    pub extras: BTreeMap<String, f64>,
}

/// Environment metadata embedded in every result. Spec §13.13 mandates the
/// list.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BenchEnv {
    /// Host OS (e.g. `linux`).
    pub os: String,
    /// CPU architecture.
    pub arch: String,
    /// `spt` version that produced the result.
    pub spt_version: String,
    /// `[runtime.config_fingerprint_sha256]` of the effective config.
    #[serde(default)]
    pub config_fingerprint: Option<String>,
    /// Profile id under test.
    #[serde(default)]
    pub profile: Option<String>,
    /// Forward id under test.
    #[serde(default)]
    pub forward: Option<String>,
    /// `ssh2` or `ssh3`.
    #[serde(default)]
    pub protocol: Option<String>,
    /// `host:port` endpoint.
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// One run of one driver.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BenchResult {
    /// Driver identifier.
    pub driver: String,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Iterations actually completed.
    pub iterations_completed: u64,
    /// Iterations attempted (may exceed completed on errors).
    pub iterations_attempted: u64,
    /// Configured payload size.
    pub payload_size: usize,
    /// Error strings, redacted.
    #[serde(default)]
    pub errors: Vec<String>,
    /// Numeric metrics.
    pub metrics: MetricSet,
    /// Throttles that were applied during the run, captured for audit.
    #[serde(default)]
    pub throttles_applied: Vec<String>,
    /// Environment metadata snapshot.
    pub env: BenchEnv,
    /// RFC3339 timestamp.
    pub started_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_from_samples() {
        let mut s = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let p = Percentiles::from_samples(&mut s);
        assert!((p.p50_ms - 6.0).abs() < 0.01 || (p.p50_ms - 5.0).abs() < 0.01);
        assert!((p.max_ms - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_percentiles() {
        let mut s: Vec<f64> = Vec::new();
        let p = Percentiles::from_samples(&mut s);
        assert!(p.max_ms.abs() < f64::EPSILON);
    }

    #[test]
    fn result_roundtrip() {
        let r = BenchResult {
            driver: "latency".into(),
            duration_ms: 500,
            iterations_completed: 10,
            iterations_attempted: 10,
            payload_size: 64,
            errors: vec![],
            metrics: MetricSet::default(),
            throttles_applied: vec![],
            env: BenchEnv::default(),
            started_at: "2026-05-05T12:00:00Z".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: BenchResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }
}
