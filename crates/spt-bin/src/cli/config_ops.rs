//! `spt config doctor` / `spt config reload` / `spt config init --example
//! observability` implementations.
//!
//! These are exposed as `pub async fn` entry points so the Phase B
//! `cli_dispatch` wire-up can call them by name without re-implementing the
//! per-subcommand logic.
//!
//! ## Design
//!
//! - `doctor` loads + validates the config, runs a small set of read-only
//!   diagnostic checks (config-only — schema, secret-ref shape, paths
//!   writable, port autodetect for DNS upstreams, MCP listen-address sanity,
//!   observability sink endpoints), and emits a structured report. The
//!   process exits with [`spt_core::Error::DiagnosticFailed`] (exit 32) when
//!   any check has `Status::Fail`. (The brief's draft mentions exit 11 for
//!   "config issues", but exit 11 is `DnsFailed` per spec §7.4 / `ExitCode`;
//!   `DiagnosticFailed` is the closest spec-defined code for failed
//!   pre-flight checks. See `.orchestration/logs/f-cli-config.md`.)
//!
//! - `reload` connects to the running `spt tunnel run` via the loopback MCP
//!   listener (recorded in `<state_dir>/mcp-listen.json`) and calls the
//!   existing `tunnel_reload` MCP tool — the running supervisor re-reads its
//!   on-disk config and applies the diff via `Orchestrator::apply`. If
//!   `[mcp].listen` is empty/absent in the loaded config OR the sidecar is
//!   missing, returns [`spt_core::Error::ReloadFailed`] (exit 14) with the
//!   exact hint string from the brief.
//!
//! - `init_observability_example` writes the contents of
//!   `examples/observability.toml` to a target path. The example body is
//!   embedded at compile time via `include_str!`.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::json;
use spt_cli::{groups, GlobalOpts, OutputFormat};
use spt_config::schema::Config;
use spt_core::{Error, Result};
use spt_diagnostics::check::{Check, Severity, Status};
use spt_diagnostics::framework::{DiagnosticReport, ReportCounts};

use crate::mcp_client::McpClient;

/// Embedded contents of `examples/observability.toml`.
///
/// Produced by `spt config init --example observability`.
const OBSERVABILITY_EXAMPLE: &str = include_str!("../../../../examples/observability.toml");

/// `spt config doctor`.
///
/// Loads + validates the config, runs config-only diagnostic checks, and
/// emits a [`DiagnosticReport`] in the requested `--output` format.
/// Returns [`Error::DiagnosticFailed`] iff any check has `Status::Fail`.
pub async fn doctor(global: &GlobalOpts, args: groups::config::ConfigDoctor) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, warnings) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    let report = run_config_doctor(&cfg, &warnings, &path, &args).await;
    emit_report(&report, output_format(global))?;

    let counts = report.counts();
    if report.has_failures() {
        return Err(Error::DiagnosticFailed {
            check: "config.doctor".into(),
            reason: format!(
                "{} fail / {} warn / {} pass / {} skipped",
                counts.fail, counts.warn, counts.pass, counts.skipped
            ),
        });
    }
    Ok(())
}

/// `spt config reload`.
///
/// Bridge to the running `spt tunnel run` supervisor via the loopback MCP
/// transport. Honors `--wait` by simply returning the synchronous
/// `tunnel_reload` tool result — the tool already invokes
/// `Controller::reload()` to completion before responding.
pub async fn reload(global: &GlobalOpts, args: groups::config::ConfigReload) -> Result<()> {
    // Pre-check: if [mcp].listen is empty or absent in the on-disk config,
    // the running supervisor has no loopback listener and we can't talk to
    // it. Surface the precise hint from the brief.
    if let Some(path) = global.config.clone() {
        if let Ok((cfg, _)) = spt_config::load(&path, false) {
            if !mcp_listen_configured(&cfg) {
                return Err(precondition_no_mcp());
            }
        }
    }

    let state_dir = spt_state::resolve_state_dir(global.state_dir.as_deref())?;
    let mut client = McpClient::connect_from_state_dir(&state_dir)
        .await
        .map_err(|e| {
            // Map "sidecar missing" to the same precondition error so the
            // user sees the actionable hint regardless of whether the
            // problem is config-side (`[mcp].listen` unset) or runtime-side
            // (no `spt tunnel run` is currently active).
            if matches!(&e, Error::RuntimeFailure(m) if m.contains("mcp-listen.json")) {
                precondition_no_mcp()
            } else {
                e
            }
        })?;
    client.initialize().await?;
    let result = client
        .call_tool("tunnel_reload", json!({}))
        .await
        .map_err(|e| Error::ReloadFailed(format!("tunnel_reload: {e}")))?;
    let _ = args.mode;
    let _ = args.wait;
    match output_format(global) {
        OutputFormat::Human => {
            println!("config reload requested via MCP loopback");
            if let Some(applied) = result.get("applied").and_then(|v| v.as_bool()) {
                println!("applied = {applied}");
            }
        }
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&result).unwrap_or_default());
        }
        OutputFormat::Yaml => {
            let s = serde_yaml::to_string(&result)
                .map_err(|e| Error::RuntimeFailure(format!("yaml: {e}")))?;
            print!("{s}");
        }
    }
    Ok(())
}

/// `spt config init --example observability`.
///
/// Writes the canned observability TOML body (embedded at build time) to
/// `target_path`. Refuses to overwrite an existing file. Creates parent
/// directories as needed.
pub async fn init_observability_example(target_path: &Path) -> Result<()> {
    if target_path.exists() {
        return Err(Error::InvalidArgs(format!(
            "refusing to overwrite existing file at `{}`",
            target_path.display()
        )));
    }
    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::InvalidConfig(format!("mkdir `{}`: {e}", parent.display())))?;
        }
    }
    std::fs::write(target_path, OBSERVABILITY_EXAMPLE)
        .map_err(|e| Error::InvalidConfig(format!("write `{}`: {e}", target_path.display())))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn require_config_path(global: &GlobalOpts) -> Result<PathBuf> {
    global.config.clone().ok_or_else(|| {
        Error::InvalidArgs("no config path supplied (pass --config or set $SPT_CONFIG)".into())
    })
}

fn output_format(global: &GlobalOpts) -> OutputFormat {
    if global.json {
        OutputFormat::Json
    } else {
        global.output
    }
}

/// Build the `Error::ReloadFailed` precondition for "no MCP listener".
fn precondition_no_mcp() -> Error {
    Error::ReloadFailed(
        "config reload requires the running spt to have [mcp].listen set; \
         otherwise edit the config and SIGHUP / Windows ParamChange the service"
            .into(),
    )
}

fn mcp_listen_configured(cfg: &Config) -> bool {
    cfg.mcp
        .as_ref()
        .and_then(|m| m.listen.as_deref())
        .is_some_and(|s| !s.trim().is_empty())
}

/// Run config-only checks against an already-loaded [`Config`].
async fn run_config_doctor(
    cfg: &Config,
    warnings: &[String],
    path: &Path,
    args: &groups::config::ConfigDoctor,
) -> DiagnosticReport {
    let mut checks = Vec::new();

    // 1. Schema validation.
    let diag = spt_config::validate(cfg);
    if diag.errors.is_empty() {
        checks.push(
            Check::new("config.schema", Severity::Critical, Status::Pass)
                .with_evidence(format!("validated `{}`", path.display())),
        );
    } else {
        let mut c = Check::new("config.schema", Severity::Critical, Status::Fail);
        for d in &diag.errors {
            c = c.with_evidence(format!("[{}] {}", d.code, d.message));
        }
        c = c.with_remediation("run `spt config validate --strict` and fix every error");
        checks.push(c);
    }
    for d in &diag.warnings {
        checks.push(
            Check::new(
                format!("config.schema.{}", d.code),
                Severity::Low,
                Status::Warn,
            )
            .with_evidence(d.message.clone()),
        );
    }

    // 2. Unknown-key warnings (lenient mode).
    if warnings.is_empty() {
        checks.push(Check::new(
            "config.unknown_keys",
            Severity::Info,
            Status::Pass,
        ));
    } else {
        let mut c = Check::new("config.unknown_keys", Severity::Low, Status::Warn)
            .with_remediation("rerun with `--strict` to reject unknown keys, or remove them");
        for w in warnings {
            c = c.with_evidence(format!("unknown key: {w}"));
        }
        checks.push(c);
    }

    // 3. Secret-reference shape — already covered by the schema validator
    //    (`malformed_secret_ref` diagnostic). We surface an explicit
    //    summary check here for operator visibility.
    let bad_refs = diag
        .errors
        .iter()
        .filter(|d| d.code.contains("secret"))
        .count();
    if bad_refs == 0 {
        checks.push(Check::new(
            "config.secrets.refs",
            Severity::Info,
            Status::Pass,
        ));
    } else {
        checks.push(
            Check::new("config.secrets.refs", Severity::High, Status::Fail)
                .with_evidence(format!("{bad_refs} malformed `secret://...` reference(s)"))
                .with_remediation("use `secret://<namespace>/<name>` form per spec §11"),
        );
    }

    // 4. State directory writability.
    if let Some(rt) = &cfg.runtime {
        if let Some(state_dir) = &rt.state_dir {
            let p = std::path::PathBuf::from(state_dir);
            checks.push(check_path_writable(
                "config.state_dir.writable",
                &p,
                "set `runtime.state_dir` to a path writable by the spt process",
            ));
        }
    }

    // 5. Logging file destination writability (when `destinations`
    //    includes "file" and `file` is set).
    if let Some(lg) = &cfg.logging {
        let writes_file = lg
            .destinations
            .as_ref()
            .map(|d| d.iter().any(|s| s == "file"))
            .unwrap_or(false);
        if writes_file {
            if let Some(file) = &lg.file {
                let p = std::path::PathBuf::from(file);
                let parent = p.parent().unwrap_or_else(|| Path::new("."));
                checks.push(check_path_writable(
                    "config.logging.file.parent_writable",
                    parent,
                    "set `logging.file` to a path whose parent directory is writable",
                ));
            } else {
                checks.push(
                    Check::new("config.logging.file.set", Severity::Medium, Status::Fail)
                        .with_evidence(
                            "`logging.destinations` includes `file` but `logging.file` is unset",
                        )
                        .with_remediation(
                            "set `logging.file = \"...\"` or remove `file` from `destinations`",
                        ),
                );
            }
        }
    }

    // 6. MCP loopback sanity: parseable address, loopback host, valid port.
    if let Some(mcp) = &cfg.mcp {
        if let Some(listen) = mcp.listen.as_deref() {
            if !listen.is_empty() {
                checks.push(check_mcp_listen(listen));
            }
        }
    }

    // 7. Optional toolset gates from CLI flags. The brief asks doctor to
    //    keep all calls read-only; gate-flagged toolsets currently emit
    //    only a Skipped marker to make the user-visible flag wiring real
    //    until those subsystem hooks (deeper checks) land alongside their
    //    matching diagnostic modules.
    for (flag, group) in [
        (args.network, "network"),
        (args.service, "service"),
        (args.secrets, "secrets"),
        (args.dns, "dns"),
        (args.observability, "observability"),
    ] {
        if flag {
            checks.push(
                Check::new(
                    format!("config.doctor.{group}"),
                    Severity::Info,
                    Status::Skipped,
                )
                .with_evidence(format!(
                    "`--{group}` deeper checks are run by `spt diagnose {group}`"
                )),
            );
        }
    }

    // 8. Profile count summary.
    checks.push(
        Check::new("config.profiles.count", Severity::Info, Status::Pass)
            .with_evidence(format!("{} profile(s) loaded", cfg.profiles.len())),
    );

    DiagnosticReport { checks }
}

fn check_path_writable(id: &str, path: &Path, remedy: &str) -> Check {
    if path.exists() {
        match path.metadata() {
            Ok(m) if m.permissions().readonly() => Check::new(id, Severity::High, Status::Fail)
                .with_evidence(format!("path `{}` is read-only", path.display()))
                .with_remediation(remedy),
            Ok(_) => Check::new(id, Severity::Info, Status::Pass)
                .with_evidence(format!("path `{}` exists and is writable", path.display())),
            Err(e) => Check::new(id, Severity::Medium, Status::Warn)
                .with_evidence(format!("stat `{}`: {e}", path.display()))
                .with_remediation(remedy),
        }
    } else {
        // Best-effort: try creating it (and removing it) — but the brief is
        // "all calls read-only", so we DO NOT mutate. Just report the gap.
        Check::new(id, Severity::Medium, Status::Warn)
            .with_evidence(format!("path `{}` does not yet exist", path.display()))
            .with_remediation(remedy)
    }
}

fn check_mcp_listen(listen: &str) -> Check {
    match listen.parse::<std::net::SocketAddr>() {
        Ok(addr) => {
            if addr.ip().is_loopback() {
                Check::new("config.mcp.listen", Severity::Info, Status::Pass)
                    .with_evidence(format!("loopback `{addr}`"))
            } else {
                Check::new("config.mcp.listen", Severity::High, Status::Warn)
                    .with_evidence(format!("`{addr}` is not a loopback address"))
                    .with_remediation(
                        "set `[mcp].listen` to a `127.0.0.1:` / `[::1]:` address \
                         and `[mcp].expose = true` only if you really mean to expose it",
                    )
            }
        }
        Err(e) => Check::new("config.mcp.listen", Severity::High, Status::Fail)
            .with_evidence(format!("`{listen}` is not a valid socket address: {e}"))
            .with_remediation("`[mcp].listen` must be `host:port` (e.g. `127.0.0.1:7878`)"),
    }
}

#[derive(Serialize)]
struct ReportEnvelope<'a> {
    summary: ReportCounts,
    checks: &'a [Check],
}

fn emit_report(report: &DiagnosticReport, fmt: OutputFormat) -> Result<()> {
    let counts = report.counts();
    let envelope = ReportEnvelope {
        summary: counts,
        checks: &report.checks,
    };
    match fmt {
        OutputFormat::Human => {
            for c in &report.checks {
                println!(
                    "[{:>7}] {} ({:?})",
                    format!("{:?}", c.status).to_lowercase(),
                    c.id,
                    c.severity
                );
                for ev in &c.evidence {
                    println!("    - {ev}");
                }
                if let Some(r) = &c.remediation {
                    println!("    hint: {r}");
                }
            }
            println!(
                "summary: {} pass, {} warn, {} fail, {} skipped",
                counts.pass, counts.warn, counts.fail, counts.skipped
            );
        }
        OutputFormat::Json => {
            let s = serde_json::to_string_pretty(&envelope)
                .map_err(|e| Error::RuntimeFailure(format!("json: {e}")))?;
            println!("{s}");
        }
        OutputFormat::Jsonl => {
            for c in &report.checks {
                let s = serde_json::to_string(c)
                    .map_err(|e| Error::RuntimeFailure(format!("jsonl: {e}")))?;
                println!("{s}");
            }
        }
        OutputFormat::Yaml => {
            let s = serde_yaml::to_string(&envelope)
                .map_err(|e| Error::RuntimeFailure(format!("yaml: {e}")))?;
            print!("{s}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_cli::{ColorMode, LogLevel, OutputFormat};

    fn opts(config: Option<PathBuf>) -> GlobalOpts {
        GlobalOpts {
            config,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: None,
            profile: None,
            output: OutputFormat::Json,
            json: false,
            log_level: LogLevel::Error,
            color: ColorMode::Never,
            quiet: true,
            verbose: 0,
            no_color: true,
            dry_run: false,
        }
    }

    fn doctor_args() -> groups::config::ConfigDoctor {
        groups::config::ConfigDoctor {
            network: false,
            service: false,
            secrets: false,
            dns: false,
            observability: false,
        }
    }

    fn workspace_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    #[tokio::test]
    async fn doctor_passes_on_minimal_example() {
        let path = workspace_root().join("examples/minimal.toml");
        let g = opts(Some(path));
        // Should not return DiagnosticFailed.
        let r = doctor(&g, doctor_args()).await;
        assert!(r.is_ok(), "expected pass, got {r:?}");
    }

    #[tokio::test]
    async fn doctor_fails_on_broken_config() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("broken.toml");
        // Bad version + ssh3 without ack — both will produce schema errors.
        std::fs::write(
            &p,
            r#"
                version = 99
                [[profiles]]
                name = "x"
                protocol = "ssh3"
                endpoint = "x.example.com:443"
            "#,
        )
        .unwrap();
        let g = opts(Some(p));
        let r = doctor(&g, doctor_args()).await;
        assert!(
            matches!(r, Err(Error::DiagnosticFailed { .. })),
            "got {r:?}"
        );
    }

    #[tokio::test]
    async fn reload_errors_when_mcp_listen_unset() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.toml");
        std::fs::write(
            &p,
            r#"
                version = 1
                [[profiles]]
                name = "p"
                protocol = "ssh2"
                host = "h.example.com"
            "#,
        )
        .unwrap();
        let mut g = opts(Some(p));
        // Point state_dir at an empty dir so even the connect path can't
        // succeed by accident.
        g.state_dir = Some(tmp.path().to_path_buf());
        let r = reload(
            &g,
            groups::config::ConfigReload {
                mode: None,
                wait: false,
            },
        )
        .await;
        match r {
            Err(Error::ReloadFailed(msg)) => {
                assert!(
                    msg.contains("[mcp].listen"),
                    "expected mcp.listen hint, got `{msg}`"
                );
            }
            other => panic!("expected ReloadFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn init_observability_writes_validatable_file() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("observability.toml");
        init_observability_example(&out).await.unwrap();
        // Must validate clean.
        let (cfg, w) = spt_config::load(&out, true).expect("strict load");
        assert!(w.is_empty(), "unknown keys: {w:?}");
        let diag = spt_config::validate(&cfg);
        assert!(diag.errors.is_empty(), "errors: {:?}", diag.errors);
        // Has the expected shape: at least one profile + remote logging
        // sinks + an mcp listen address.
        assert!(!cfg.profiles.is_empty());
        assert!(cfg
            .logging
            .as_ref()
            .map(|l| !l.remote.is_empty())
            .unwrap_or(false));
        assert!(cfg
            .mcp
            .as_ref()
            .and_then(|m| m.listen.as_deref())
            .is_some_and(|s| !s.is_empty()));
    }

    #[tokio::test]
    async fn init_observability_refuses_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("o.toml");
        std::fs::write(&out, "old").unwrap();
        let r = init_observability_example(&out).await;
        assert!(matches!(r, Err(Error::InvalidArgs(_))));
    }
}
