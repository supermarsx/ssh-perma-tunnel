//! Implementations for `spt benchmark` live drivers + `report export`.
//!
//! `run_live` dispatches a benchmark against a running spt's MCP loopback
//! transport. The server-side `benchmark_run` tool (see [`super::super::controller`])
//! wires `Orchestrator::live_connector(profile, forward)` into the
//! [`spt_benchmark`] driver suite, so the CLI body here is just an MCP RPC.
//!
//! # Production-impact gating
//!
//! Drivers whose `impact()` is `Production` (`reconnect`, `udp`, `limits`)
//! refuse to run against a live tunnel unless the operator opts in. The opt-in
//! is a **two-key gate** — *both* must be set:
//!
//! 1. the CLI flag `--unsafe-allow-production-impact` on the command, and
//! 2. the config gate `[benchmark].allow_production_impact = true`.
//!
//! [`run_live`] computes `allow_prod = cli_flag && config_flag` and forwards
//! it to the server-side `benchmark_run` tool, which calls `check_safety`.
//! Synthetic loopback runs (the `spt benchmark run` path with no `--profile`,
//! and the in-process connectors in [`crate::benchmark_bridge`]) are never
//! gated — they cannot impact production by construction.
//!
//! `report_export` reads `<state_dir>/benchmarks/<run-id>.json` and renders
//! it to one of the four supported formats (`md|csv|json|jsonl`) at a
//! caller-supplied output path.
//!
//! # Public surface
//!
//! ```ignore
//! pub async fn run_live(global: &GlobalOpts, args: BenchmarkRunArgs) -> Result<()>;
//! pub async fn report_export(global: &GlobalOpts, args: BenchmarkReportExportArgs) -> Result<()>;
//! ```

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::unused_async)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::manual_let_else)]

use std::path::PathBuf;

use serde_json::Value;

use spt_benchmark::{write_report, BenchResult, ReportFormat};
use spt_cli::groups::benchmark::{
    BenchmarkReportExport, BenchmarkReportFormat, BenchmarkRun, BenchmarkRunTarget,
};
use spt_cli::GlobalOpts;
use spt_core::{Error, Result};

use crate::mcp_client::McpClient;

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

/// Arguments for `bench_ops::run_live`.
#[derive(Debug, Clone)]
pub struct BenchmarkRunArgs {
    /// Driver name: `latency|throughput|udp|reconnect|limits`.
    pub driver: String,
    /// Target profile id. None → return clear error (live path requires a profile).
    pub profile: Option<String>,
    /// Optional forward id within the profile.
    pub forward: Option<String>,
    /// Per-driver iteration override.
    pub count: Option<u32>,
    /// Per-driver duration (parsed by `spt_core::duration::parse_duration`).
    pub duration: Option<String>,
    /// User opt-in to production-impacting drivers (combined with config gate).
    pub allow_production_impact: bool,
    /// JSON output.
    pub json: bool,
}

impl From<BenchmarkRun> for BenchmarkRunArgs {
    fn from(v: BenchmarkRun) -> Self {
        Self {
            driver: v.driver,
            profile: v.target.profile,
            forward: v.target.forward,
            count: v.count,
            duration: v.duration,
            allow_production_impact: v.unsafe_allow_production_impact,
            json: v.json,
        }
    }
}

impl BenchmarkRunArgs {
    /// Construct from the per-driver `latency|throughput|udp|reconnect|limits`
    /// argument structs by way of `BenchmarkRun`-shaped inputs.
    #[must_use]
    pub fn from_driver(
        driver: impl Into<String>,
        target: BenchmarkRunTarget,
        count: Option<u32>,
        duration: Option<String>,
        allow_production_impact: bool,
        json: bool,
    ) -> Self {
        Self {
            driver: driver.into(),
            profile: target.profile,
            forward: target.forward,
            count,
            duration,
            allow_production_impact,
            json,
        }
    }
}

/// Arguments for `bench_ops::report_export`.
#[derive(Debug, Clone)]
pub struct BenchmarkReportExportArgs {
    /// Run id (file basename in `<state_dir>/benchmarks/<run-id>.json`).
    pub run_id: String,
    /// Output format (`md|csv|json|jsonl`).
    pub format: BenchmarkReportFormat,
    /// Output path.
    pub out: PathBuf,
}

impl From<BenchmarkReportExport> for BenchmarkReportExportArgs {
    fn from(v: BenchmarkReportExport) -> Self {
        Self {
            run_id: v.run_id,
            format: v.format,
            out: v.out,
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// `spt benchmark <driver> --profile <p> [--forward <f>]` — live tunnel path.
///
/// Requires a running supervisor with `[mcp].listen` enabled. Returns a
/// clear error pointing at the config when the loopback isn't up.
pub async fn run_live(global: &GlobalOpts, args: BenchmarkRunArgs) -> Result<()> {
    let Some(profile) = args.profile.clone() else {
        return Err(Error::InvalidArgs(
            "live benchmarks require --profile <id> (synthetic in-process drivers \
             remain available via the existing `spt benchmark run` path)"
                .into(),
        ));
    };

    // Resolve the production-impact gate: BOTH the CLI flag AND the config
    // flag must be set for the user opt-in to take effect.
    let cfg_allow_prod = global
        .config
        .as_ref()
        .and_then(|p| spt_config::load(p, false).ok())
        .and_then(|(c, _)| c.benchmark)
        .and_then(|b| b.allow_production_impact)
        .unwrap_or(false);
    let allow_prod = args.allow_production_impact && cfg_allow_prod;

    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    let mut client = McpClient::connect_from_state_dir(&state_dir)
        .await
        .map_err(|e| {
            Error::RuntimeFailure(format!(
                "{e}\n\
             hint: live benchmarks need the running supervisor's MCP loopback. \
             Set `[mcp].listen = \"127.0.0.1:<port>\"` in your config and \
             ensure `spt tunnel run` is active.",
            ))
        })?;
    client.initialize().await?;

    let mut payload = serde_json::json!({
        "driver": args.driver,
        "profile": profile,
        "count": args.count.unwrap_or(50),
        "duration_seconds": args
            .duration
            .as_deref()
            .and_then(|d| spt_core::duration::parse_duration(d).ok())
            .map(|d| d.as_secs())
            .unwrap_or(5),
        "allow_production_impact": allow_prod,
    });
    if let Some(f) = args.forward.clone() {
        payload["forward"] = Value::String(f);
    }
    let v = client.call_tool("benchmark_run", payload).await?;

    if !crate::cli::tunnel_ops::emit(global, args.json, &v)? {
        let iter_ok = v
            .get("iterations_completed")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let iter_attempt = v
            .get("iterations_attempted")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let dur = v.get("duration_ms").and_then(Value::as_u64).unwrap_or(0);
        let errors = v
            .get("errors")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        println!(
            "driver={} (live) iter_ok={iter_ok}/{iter_attempt} dur={dur}ms errors={errors}",
            args.driver
        );
    }
    Ok(())
}

/// `spt benchmark report export --format <fmt> <run-id>`.
pub async fn report_export(global: &GlobalOpts, args: BenchmarkReportExportArgs) -> Result<()> {
    if args.run_id.is_empty() {
        return Err(Error::InvalidArgs(
            "benchmark report export requires a run-id (the basename of the \
             JSON file in <state_dir>/benchmarks/)"
                .into(),
        ));
    }
    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    let json_path = state_dir
        .join("benchmarks")
        .join(format!("{}.json", args.run_id));
    let body = std::fs::read_to_string(&json_path).map_err(|e| {
        Error::RuntimeFailure(format!(
            "read `{}`: {e} — does the run-id exist in <state_dir>/benchmarks?",
            json_path.display()
        ))
    })?;
    let results: Vec<BenchResult> = serde_json::from_str(&body)
        .map_err(|e| Error::BenchmarkFailed(format!("parse `{}`: {e}", json_path.display())))?;

    let format = match args.format {
        BenchmarkReportFormat::Json => ReportFormat::Json,
        BenchmarkReportFormat::Jsonl => ReportFormat::Jsonl,
        BenchmarkReportFormat::Csv => ReportFormat::Csv,
        BenchmarkReportFormat::Markdown => ReportFormat::Markdown,
    };

    // `write_report` writes into `<state_dir>/benchmarks/<run_id>.<ext>`.
    // Use a temp dir + rename to honour the user's --out path so we don't
    // duplicate state under the canonical state directory.
    let tmp = tempfile::tempdir().map_err(|e| Error::RuntimeFailure(e.to_string()))?;
    let written = write_report(tmp.path(), &args.run_id, &results, format)?;
    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::RuntimeFailure(format!("mkdir `{}`: {e}", parent.display())))?;
        }
    }
    std::fs::copy(&written, &args.out).map_err(|e| {
        Error::RuntimeFailure(format!(
            "copy {} -> {}: {e}",
            written.display(),
            args.out.display()
        ))
    })?;
    println!("wrote {}", args.out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_benchmark::{BenchEnv, MetricSet, Percentiles};
    use spt_cli::{ColorMode, LogLevel, OutputFormat};

    fn global_with_state_dir(dir: PathBuf) -> GlobalOpts {
        GlobalOpts {
            config: None,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: Some(dir),
            profile: None,
            portable: false,
            output: OutputFormat::Json,
            json: true,
            log_level: LogLevel::Error,
            color: ColorMode::Never,
            quiet: true,
            verbose: 0,
            no_color: true,
            dry_run: false,
        }
    }

    fn sample_bench() -> BenchResult {
        BenchResult {
            driver: "latency".into(),
            duration_ms: 12,
            iterations_completed: 3,
            iterations_attempted: 3,
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

    #[tokio::test]
    async fn run_live_without_profile_errors() {
        let g = global_with_state_dir(std::env::temp_dir());
        let err = run_live(
            &g,
            BenchmarkRunArgs {
                driver: "latency".into(),
                profile: None,
                forward: None,
                count: None,
                duration: None,
                allow_production_impact: false,
                json: true,
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("require --profile"), "{err}");
    }

    #[tokio::test]
    async fn report_export_renders_markdown() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("benchmarks");
        std::fs::create_dir_all(&runs).unwrap();
        let run_id = "test-run";
        let json_path = runs.join(format!("{run_id}.json"));
        std::fs::write(
            &json_path,
            serde_json::to_string(&[sample_bench()]).unwrap(),
        )
        .unwrap();

        let out = dir.path().join("out.md");
        let g = global_with_state_dir(dir.path().to_path_buf());
        report_export(
            &g,
            BenchmarkReportExportArgs {
                run_id: run_id.into(),
                format: BenchmarkReportFormat::Markdown,
                out: out.clone(),
            },
        )
        .await
        .unwrap();
        let body = std::fs::read_to_string(&out).unwrap();
        assert!(body.contains("| driver |"), "{body}");
    }

    #[tokio::test]
    async fn report_export_unknown_run_id_errors() {
        let dir = tempfile::tempdir().unwrap();
        let g = global_with_state_dir(dir.path().to_path_buf());
        let err = report_export(
            &g,
            BenchmarkReportExportArgs {
                run_id: "ghost".into(),
                format: BenchmarkReportFormat::Json,
                out: dir.path().join("ghost.json"),
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("ghost"), "{err}");
    }

    #[test]
    fn args_from_run_target() {
        let target = BenchmarkRunTarget {
            profile: Some("p".into()),
            forward: Some("f".into()),
        };
        let args = BenchmarkRunArgs::from_driver("latency", target, Some(10), None, false, false);
        assert_eq!(args.profile.as_deref(), Some("p"));
        assert_eq!(args.driver, "latency");
        assert_eq!(args.count, Some(10));
    }

    #[test]
    fn args_from_run_target_passes_forward_and_flags() {
        let target = BenchmarkRunTarget {
            profile: Some("p".into()),
            forward: Some("ff".into()),
        };
        let args = BenchmarkRunArgs::from_driver(
            "throughput",
            target,
            None,
            Some("1s".into()),
            true,
            true,
        );
        assert_eq!(args.forward.as_deref(), Some("ff"));
        assert_eq!(args.duration.as_deref(), Some("1s"));
        assert!(args.allow_production_impact);
        assert!(args.json);
        assert_eq!(args.count, None);
    }

    #[test]
    fn args_from_benchmark_run_round_trip() {
        let v = BenchmarkRun {
            driver: "udp".into(),
            target: BenchmarkRunTarget {
                profile: Some("pp".into()),
                forward: None,
            },
            duration: Some("2s".into()),
            connections: None,
            count: Some(5),
            unsafe_allow_production_impact: true,
            json: true,
        };
        let args: BenchmarkRunArgs = v.into();
        assert_eq!(args.driver, "udp");
        assert_eq!(args.profile.as_deref(), Some("pp"));
        assert_eq!(args.forward, None);
        assert_eq!(args.duration.as_deref(), Some("2s"));
        assert_eq!(args.count, Some(5));
        assert!(args.allow_production_impact);
        assert!(args.json);
    }

    #[test]
    fn report_export_args_from_clap_struct() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.csv");
        let raw = BenchmarkReportExport {
            run_id: "abc".into(),
            format: BenchmarkReportFormat::Csv,
            out: out.clone(),
        };
        let args: BenchmarkReportExportArgs = raw.into();
        assert_eq!(args.run_id, "abc");
        assert!(matches!(args.format, BenchmarkReportFormat::Csv));
        assert_eq!(args.out, out);
    }

    #[tokio::test]
    async fn report_export_empty_run_id_errors_before_io() {
        let dir = tempfile::tempdir().unwrap();
        let g = global_with_state_dir(dir.path().to_path_buf());
        let err = report_export(
            &g,
            BenchmarkReportExportArgs {
                run_id: String::new(),
                format: BenchmarkReportFormat::Json,
                out: dir.path().join("out.json"),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)), "{err}");
    }

    #[tokio::test]
    async fn report_export_malformed_json_errors_as_benchmark_failed() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("benchmarks");
        std::fs::create_dir_all(&runs).unwrap();
        let run_id = "bad-json";
        let json_path = runs.join(format!("{run_id}.json"));
        std::fs::write(&json_path, b"{not json}").unwrap();
        let g = global_with_state_dir(dir.path().to_path_buf());
        let err = report_export(
            &g,
            BenchmarkReportExportArgs {
                run_id: run_id.into(),
                format: BenchmarkReportFormat::Json,
                out: dir.path().join("out.json"),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::BenchmarkFailed(_)), "{err}");
    }

    #[tokio::test]
    async fn report_export_csv_jsonl_and_json_all_render() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("benchmarks");
        std::fs::create_dir_all(&runs).unwrap();
        let run_id = "multi";
        let json_path = runs.join(format!("{run_id}.json"));
        std::fs::write(
            &json_path,
            serde_json::to_string(&[sample_bench()]).unwrap(),
        )
        .unwrap();
        let g = global_with_state_dir(dir.path().to_path_buf());
        for (fmt, name) in [
            (BenchmarkReportFormat::Csv, "out.csv"),
            (BenchmarkReportFormat::Jsonl, "out.jsonl"),
            (BenchmarkReportFormat::Json, "out.json"),
        ] {
            let out = dir.path().join(name);
            report_export(
                &g,
                BenchmarkReportExportArgs {
                    run_id: run_id.into(),
                    format: fmt,
                    out: out.clone(),
                },
            )
            .await
            .unwrap();
            assert!(out.exists(), "{name} not written");
            assert!(std::fs::metadata(&out).unwrap().len() > 0);
        }
    }

    #[tokio::test]
    async fn report_export_creates_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("benchmarks");
        std::fs::create_dir_all(&runs).unwrap();
        let run_id = "nested";
        std::fs::write(
            runs.join(format!("{run_id}.json")),
            serde_json::to_string(&[sample_bench()]).unwrap(),
        )
        .unwrap();
        let nested_out = dir.path().join("a/b/c/out.md");
        let g = global_with_state_dir(dir.path().to_path_buf());
        report_export(
            &g,
            BenchmarkReportExportArgs {
                run_id: run_id.into(),
                format: BenchmarkReportFormat::Markdown,
                out: nested_out.clone(),
            },
        )
        .await
        .unwrap();
        assert!(nested_out.exists());
    }
}
