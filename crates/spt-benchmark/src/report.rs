//! Report writer — JSON / JSONL / CSV / Markdown.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use spt_core::Result;

use crate::result::BenchResult;

/// Output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    /// Single pretty-printed JSON document with all results.
    Json,
    /// One JSON object per line, one per result.
    Jsonl,
    /// CSV with a fixed header row.
    Csv,
    /// Human-readable Markdown table.
    Markdown,
}

/// Render `results` as `format` and atomically write to
/// `<state_dir>/benchmarks/<run_id>.<ext>`. Returns the written path.
pub fn write_report(
    state_dir: &Path,
    run_id: &str,
    results: &[BenchResult],
    format: ReportFormat,
) -> Result<PathBuf> {
    let dir = state_dir.join("benchmarks");
    std::fs::create_dir_all(&dir).map_err(|e| spt_core::Error::StateLockFailed {
        path: dir.clone(),
        reason: format!("mkdir benchmarks dir: {e}"),
    })?;
    let (ext, body) = match format {
        ReportFormat::Json => (
            "json",
            serde_json::to_string_pretty(results).unwrap_or_else(|_| "[]".into()),
        ),
        ReportFormat::Jsonl => {
            let mut out = String::new();
            for r in results {
                let line = serde_json::to_string(r).unwrap_or_else(|_| "{}".into());
                out.push_str(&line);
                out.push('\n');
            }
            ("jsonl", out)
        }
        ReportFormat::Csv => ("csv", render_csv(results)),
        ReportFormat::Markdown => ("md", render_markdown(results)),
    };
    let path = dir.join(format!("{run_id}.{ext}"));
    spt_state::write_atomic_string(&path, &body)?;
    Ok(path)
}

fn render_csv(results: &[BenchResult]) -> String {
    let mut wtr = csv::Writer::from_writer(vec![]);
    let _ = wtr.write_record([
        "driver",
        "duration_ms",
        "iterations_completed",
        "iterations_attempted",
        "payload_size",
        "p50_ms",
        "p99_ms",
        "throughput_bps",
        "errors",
    ]);
    for r in results {
        let p50 = r
            .metrics
            .latency
            .as_ref()
            .map(|p| p.p50_ms)
            .unwrap_or_default();
        let p99 = r
            .metrics
            .latency
            .as_ref()
            .map(|p| p.p99_ms)
            .unwrap_or_default();
        let tput = r.metrics.throughput_bps.unwrap_or_default();
        let _ = wtr.write_record([
            r.driver.as_str(),
            &r.duration_ms.to_string(),
            &r.iterations_completed.to_string(),
            &r.iterations_attempted.to_string(),
            &r.payload_size.to_string(),
            &format!("{p50:.3}"),
            &format!("{p99:.3}"),
            &format!("{tput:.3}"),
            &r.errors.join("; "),
        ]);
    }
    let _ = wtr.flush();
    String::from_utf8(wtr.into_inner().unwrap_or_default()).unwrap_or_default()
}

fn render_markdown(results: &[BenchResult]) -> String {
    let mut out = String::new();
    out.push_str("| driver | iters | duration_ms | p50_ms | p99_ms | throughput_bps | errors |\n");
    out.push_str("|---|---|---|---|---|---|---|\n");
    for r in results {
        let p50 = r
            .metrics
            .latency
            .as_ref()
            .map(|p| p.p50_ms)
            .unwrap_or_default();
        let p99 = r
            .metrics
            .latency
            .as_ref()
            .map(|p| p.p99_ms)
            .unwrap_or_default();
        let tput = r.metrics.throughput_bps.unwrap_or_default();
        let errs = if r.errors.is_empty() {
            String::new()
        } else {
            format!("{} error(s)", r.errors.len())
        };
        out.push_str(&format!(
            "| {} | {} | {} | {p50:.3} | {p99:.3} | {tput:.3} | {} |\n",
            r.driver, r.iterations_completed, r.duration_ms, errs
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{BenchEnv, MetricSet, Percentiles};
    use tempfile::tempdir;

    fn sample() -> BenchResult {
        BenchResult {
            driver: "latency".into(),
            duration_ms: 100,
            iterations_completed: 5,
            iterations_attempted: 5,
            payload_size: 16,
            errors: vec![],
            metrics: MetricSet {
                latency: Some(Percentiles {
                    p50_ms: 1.0,
                    p90_ms: 2.0,
                    p99_ms: 3.0,
                    p999_ms: 4.0,
                    max_ms: 5.0,
                    ..Default::default()
                }),
                ..Default::default()
            },
            throttles_applied: vec![],
            env: BenchEnv::default(),
            started_at: "2026-05-05T00:00:00Z".into(),
        }
    }

    #[test]
    fn writes_all_formats() {
        let d = tempdir().unwrap();
        for f in [
            ReportFormat::Json,
            ReportFormat::Jsonl,
            ReportFormat::Csv,
            ReportFormat::Markdown,
        ] {
            let p = write_report(d.path(), &format!("r-{f:?}"), &[sample()], f).unwrap();
            assert!(p.exists());
            let body = std::fs::read_to_string(&p).unwrap();
            assert!(!body.is_empty());
            match f {
                ReportFormat::Json => assert!(body.starts_with('[')),
                ReportFormat::Jsonl => assert!(body.contains("\"driver\":\"latency\"")),
                ReportFormat::Csv => assert!(body.contains("driver,duration_ms")),
                ReportFormat::Markdown => assert!(body.contains("| driver |")),
            }
        }
    }
}
