//! Compare two benchmark reports.

use serde::{Deserialize, Serialize};

use crate::result::BenchResult;

/// One metric's baseline-vs-candidate diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparedMetric {
    /// Metric name.
    pub name: String,
    /// Baseline value (None if absent).
    pub baseline: Option<f64>,
    /// Candidate value.
    pub candidate: Option<f64>,
    /// Absolute difference (`candidate - baseline`). None if either side missing.
    pub abs_delta: Option<f64>,
    /// Relative change `(candidate - baseline) / baseline`. None when
    /// baseline is zero or missing.
    pub rel_delta: Option<f64>,
}

/// Per-driver comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverComparison {
    /// Driver name.
    pub driver: String,
    /// Compared metrics.
    pub metrics: Vec<ComparedMetric>,
}

/// Top-level comparison result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportComparison {
    /// Per-driver entries (joined on driver name).
    pub drivers: Vec<DriverComparison>,
    /// Driver names present only in the baseline.
    pub baseline_only: Vec<String>,
    /// Driver names present only in the candidate.
    pub candidate_only: Vec<String>,
}

/// Compare two report sets driver-by-driver. Order in the input is not
/// significant; pairing is by `driver` name.
#[must_use]
pub fn compare_reports(baseline: &[BenchResult], candidate: &[BenchResult]) -> ReportComparison {
    let mut out = ReportComparison::default();

    let names_b: std::collections::BTreeSet<&str> =
        baseline.iter().map(|r| r.driver.as_str()).collect();
    let names_c: std::collections::BTreeSet<&str> =
        candidate.iter().map(|r| r.driver.as_str()).collect();

    for shared in names_b.intersection(&names_c) {
        let b = baseline.iter().find(|r| &r.driver == shared).unwrap();
        let c = candidate.iter().find(|r| &r.driver == shared).unwrap();
        let mut metrics = Vec::new();
        push_opt(
            &mut metrics,
            "p50_ms",
            lat(b, |p| p.p50_ms),
            lat(c, |p| p.p50_ms),
        );
        push_opt(
            &mut metrics,
            "p99_ms",
            lat(b, |p| p.p99_ms),
            lat(c, |p| p.p99_ms),
        );
        push_opt(
            &mut metrics,
            "throughput_bps",
            b.metrics.throughput_bps,
            c.metrics.throughput_bps,
        );
        out.drivers.push(DriverComparison {
            driver: (*shared).to_string(),
            metrics,
        });
    }
    out.baseline_only = names_b
        .difference(&names_c)
        .map(|s| (*s).to_string())
        .collect();
    out.candidate_only = names_c
        .difference(&names_b)
        .map(|s| (*s).to_string())
        .collect();
    out
}

fn lat<F: Fn(&crate::result::Percentiles) -> f64>(r: &BenchResult, f: F) -> Option<f64> {
    r.metrics.latency.as_ref().map(f)
}

fn push_opt(
    out: &mut Vec<ComparedMetric>,
    name: &str,
    baseline: Option<f64>,
    candidate: Option<f64>,
) {
    let abs = match (baseline, candidate) {
        (Some(b), Some(c)) => Some(c - b),
        _ => None,
    };
    let rel = match (baseline, candidate) {
        (Some(b), Some(c)) if b.abs() > f64::EPSILON => Some((c - b) / b),
        _ => None,
    };
    out.push(ComparedMetric {
        name: name.into(),
        baseline,
        candidate,
        abs_delta: abs,
        rel_delta: rel,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{BenchEnv, MetricSet, Percentiles};

    fn r(name: &str, p50: f64, tput: f64) -> BenchResult {
        BenchResult {
            driver: name.into(),
            duration_ms: 0,
            iterations_completed: 0,
            iterations_attempted: 0,
            payload_size: 0,
            errors: vec![],
            metrics: MetricSet {
                latency: Some(Percentiles {
                    p50_ms: p50,
                    p90_ms: p50,
                    p99_ms: p50,
                    p999_ms: p50,
                    max_ms: p50,
                    ..Default::default()
                }),
                throughput_bps: Some(tput),
                ..Default::default()
            },
            throttles_applied: vec![],
            env: BenchEnv::default(),
            started_at: String::new(),
        }
    }

    #[test]
    fn straightforward_compare() {
        let b = vec![r("latency", 10.0, 1000.0)];
        let c = vec![r("latency", 5.0, 2000.0)];
        let cmp = compare_reports(&b, &c);
        assert_eq!(cmp.drivers.len(), 1);
        let m = &cmp.drivers[0].metrics;
        let p50 = m.iter().find(|x| x.name == "p50_ms").unwrap();
        assert_eq!(p50.abs_delta, Some(-5.0));
        assert_eq!(p50.rel_delta, Some(-0.5));
        let tput = m.iter().find(|x| x.name == "throughput_bps").unwrap();
        assert_eq!(tput.abs_delta, Some(1000.0));
    }

    #[test]
    fn only_one_side() {
        let b = vec![r("a", 1.0, 1.0)];
        let c = vec![r("b", 1.0, 1.0)];
        let cmp = compare_reports(&b, &c);
        assert_eq!(cmp.baseline_only, vec!["a"]);
        assert_eq!(cmp.candidate_only, vec!["b"]);
    }
}
