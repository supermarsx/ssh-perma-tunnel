//! Implementations for `spt diagnose auth | trust | observability` plus the
//! `--udp` extension to `spt diagnose port`.
//!
//! These bodies are called from `cli_dispatch.rs`. They run the appropriate
//! [`spt_diagnostics::Diagnostic`] against a [`DiagnosticContext`] sourced
//! from the loaded config + state directory, then render either a JSON
//! report (when `--json`) or a status-prefixed line stream.
//!
//! # Public surface
//!
//! ```ignore
//! pub async fn auth(global: &GlobalOpts, args: DiagnoseAuthArgs) -> Result<()>;
//! pub async fn trust(global: &GlobalOpts, args: DiagnoseTrustArgs) -> Result<()>;
//! pub async fn observability(global: &GlobalOpts, args: DiagnoseObservabilityArgs) -> Result<()>;
//! pub async fn port(global: &GlobalOpts, args: DiagnosePortArgs) -> Result<()>;
//! ```
//!
//! ## Note on argument shape
//!
//! The brief calls for `DiagnoseAuthArgs { profile: Option<String>, probe: bool }`,
//! but the existing `spt-cli::groups::diagnose::DiagnoseProfile` (which the
//! parser produces for both `auth` and `trust`) is a positional `profile:
//! String` plus `--json`. To stay within the file lock list (we may not
//! touch `spt-cli`), this module accepts its own `*Args` structs and
//! provides `From` conversions from the spt-cli forms. `--probe` for live
//! connection is therefore a follow-up that the dispatcher passes as a
//! plain field once `spt-cli` grows the flag.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::if_not_else)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::case_sensitive_file_extension_comparisons)]
#![allow(clippy::default_trait_access)]

use std::path::PathBuf;
use std::time::Duration;

use spt_cli::groups::diagnose::{DiagnoseObservability, DiagnosePort, DiagnoseProfile};
use spt_cli::GlobalOpts;
use spt_core::{Error, RedactionMode, Result};
use spt_diagnostics::checks::{AuthDiagnostic, ObservabilityDiagnostic, TrustDiagnostic};
use spt_diagnostics::framework::{Diagnostic, DiagnosticContext};
use spt_diagnostics::{autodetect, autodetect_udp, Check, Status};

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

/// Arguments for `diag_ops::auth`.
#[derive(Debug, Clone)]
pub struct DiagnoseAuthArgs {
    /// Restrict to a single profile id. None → every profile.
    pub profile: Option<String>,
    /// Run a live connect after structural validation. Currently parsed
    /// from the optional dispatch flag; left as a forward-compatible
    /// hook (no `--probe` flag exists yet in spt-cli).
    pub probe: bool,
    /// JSON output.
    pub json: bool,
}

impl From<DiagnoseProfile> for DiagnoseAuthArgs {
    fn from(v: DiagnoseProfile) -> Self {
        let profile = if v.profile.is_empty() {
            None
        } else {
            Some(v.profile)
        };
        Self {
            profile,
            probe: false,
            json: v.json,
        }
    }
}

/// Arguments for `diag_ops::trust`.
#[derive(Debug, Clone)]
pub struct DiagnoseTrustArgs {
    /// Restrict to a single profile id. None → every profile.
    pub profile: Option<String>,
    /// JSON output.
    pub json: bool,
}

impl From<DiagnoseProfile> for DiagnoseTrustArgs {
    fn from(v: DiagnoseProfile) -> Self {
        let profile = if v.profile.is_empty() {
            None
        } else {
            Some(v.profile)
        };
        Self {
            profile,
            json: v.json,
        }
    }
}

/// Arguments for `diag_ops::observability`.
#[derive(Debug, Clone)]
pub struct DiagnoseObservabilityArgs {
    /// Restrict to a single sink name. None → every sink.
    pub sink: Option<String>,
    /// JSON output.
    pub json: bool,
}

impl From<DiagnoseObservability> for DiagnoseObservabilityArgs {
    fn from(v: DiagnoseObservability) -> Self {
        Self {
            sink: v.sink,
            json: v.json,
        }
    }
}

/// Arguments for `diag_ops::port`.
#[derive(Debug, Clone)]
pub struct DiagnosePortArgs {
    /// Target host.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// TCP probe.
    pub tcp: bool,
    /// UDP probe (mutually exclusive with `tcp` at the parser level).
    pub udp: bool,
    /// Run service autodetect (TCP-only).
    pub autodetect_service: bool,
    /// JSON output.
    pub json: bool,
}

impl From<DiagnosePort> for DiagnosePortArgs {
    fn from(v: DiagnosePort) -> Self {
        Self {
            host: v.host,
            port: v.port,
            tcp: v.tcp,
            udp: v.udp,
            autodetect_service: v.autodetect_service,
            json: v.json,
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// `spt diagnose auth [--profile <id>]`.
pub async fn auth(global: &GlobalOpts, args: DiagnoseAuthArgs) -> Result<()> {
    let ctx = build_context(global)?;
    let mut diag = AuthDiagnostic::default();
    if let Some(p) = &args.profile {
        diag = AuthDiagnostic::for_profile(p);
    }
    let checks = diag.run(&ctx).await;
    render_checks(&checks, args.json)?;
    if args.probe {
        eprintln!(
            "spt: --probe live-connect not yet exposed by spt-cli; structural validation only"
        );
    }
    fail_if_any_failures(&checks)
}

/// `spt diagnose trust [--profile <id>]`.
pub async fn trust(global: &GlobalOpts, args: DiagnoseTrustArgs) -> Result<()> {
    let ctx = build_context(global)?;
    let mut diag = TrustDiagnostic::default();
    if let Some(p) = &args.profile {
        diag = TrustDiagnostic::for_profile(p);
    }
    let checks = diag.run(&ctx).await;
    render_checks(&checks, args.json)?;
    fail_if_any_failures(&checks)
}

/// `spt diagnose observability [--sink <name>]`.
pub async fn observability(global: &GlobalOpts, args: DiagnoseObservabilityArgs) -> Result<()> {
    let ctx = build_context(global)?;
    let mut diag = ObservabilityDiagnostic::default();
    if let Some(s) = &args.sink {
        diag = ObservabilityDiagnostic::for_sink(s);
    }
    let checks = diag.run(&ctx).await;
    render_checks(&checks, args.json)?;
    fail_if_any_failures(&checks)
}

/// `spt diagnose port --host <h> --port <p> [--tcp|--udp] [--autodetect-service]`.
pub async fn port(_global: &GlobalOpts, args: DiagnosePortArgs) -> Result<()> {
    let target_addr = format!("{}:{}", args.host, args.port);
    let mut output = serde_json::Map::new();
    output.insert(
        "target".into(),
        serde_json::Value::String(target_addr.clone()),
    );

    if args.udp {
        output.insert("transport".into(), serde_json::Value::String("udp".into()));
        let parsed = match tokio::net::lookup_host(&target_addr).await {
            Ok(mut it) => it.next(),
            Err(e) => {
                output.insert("reachable".into(), serde_json::Value::Bool(false));
                output.insert("error".into(), serde_json::Value::String(e.to_string()));
                return print_port(&output, args.json, &target_addr);
            }
        };
        let Some(addr) = parsed else {
            output.insert("reachable".into(), serde_json::Value::Bool(false));
            output.insert(
                "error".into(),
                serde_json::Value::String("dns: no addresses".into()),
            );
            return print_port(&output, args.json, &target_addr);
        };
        let det = autodetect_udp(addr, Duration::from_secs(3)).await;
        match det {
            Some(d) => {
                output.insert("reachable".into(), serde_json::Value::Bool(true));
                output.insert(
                    "service".into(),
                    serde_json::Value::String(format!("{:?}", d.class).to_lowercase()),
                );
                output.insert("evidence".into(), serde_json::Value::String(d.evidence));
            }
            None => {
                output.insert("reachable".into(), serde_json::Value::Bool(false));
            }
        }
        return print_port(&output, args.json, &target_addr);
    }

    output.insert("transport".into(), serde_json::Value::String("tcp".into()));
    match tokio::net::TcpStream::connect(&target_addr).await {
        Ok(_stream) => {
            output.insert("reachable".into(), serde_json::Value::Bool(true));
            if args.autodetect_service {
                let parsed = tokio::net::lookup_host(&target_addr)
                    .await
                    .ok()
                    .and_then(|mut it| it.next());
                if let Some(addr) = parsed {
                    let det = autodetect(addr, Duration::from_secs(3)).await;
                    if let Some(d) = det {
                        output.insert(
                            "service".into(),
                            serde_json::Value::String(format!("{:?}", d.class).to_lowercase()),
                        );
                        output.insert("evidence".into(), serde_json::Value::String(d.evidence));
                    }
                }
            }
        }
        Err(e) => {
            output.insert("reachable".into(), serde_json::Value::Bool(false));
            output.insert("error".into(), serde_json::Value::String(e.to_string()));
        }
    }
    print_port(&output, args.json, &target_addr)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn build_context(global: &GlobalOpts) -> Result<DiagnosticContext> {
    let cfg = global
        .config
        .as_ref()
        .and_then(|p| spt_config::load(p, false).ok())
        .map(|(c, _)| c);
    let state_dir: Option<PathBuf> = spt_state::resolve_state_dir(global.state_dir.as_deref()).ok();
    let mut ctx = DiagnosticContext::default();
    ctx.state_dir = state_dir;
    if let Some(c) = &cfg {
        ctx.effective_config = Some(spt_config::render(c, RedactionMode::Standard));
        ctx.mcp_enabled = c.mcp.as_ref().and_then(|m| m.enabled).unwrap_or(false);
    }
    Ok(ctx)
}

fn render_checks(checks: &[Check], json: bool) -> Result<()> {
    if json {
        let v = serde_json::to_string_pretty(checks)
            .map_err(|e| Error::DiagnosticBundleFailed(e.to_string()))?;
        println!("{v}");
    } else if checks.is_empty() {
        println!("(no checks ran)");
    } else {
        for c in checks {
            println!(
                "[{:?}] {} ({:?}): {}",
                c.status,
                c.id,
                c.severity,
                c.evidence.join("; ")
            );
            if let Some(remedy) = &c.remediation {
                println!("    remediation: {remedy}");
            }
        }
    }
    Ok(())
}

fn fail_if_any_failures(checks: &[Check]) -> Result<()> {
    if checks.iter().any(|c| c.status == Status::Fail) {
        return Err(Error::RuntimeFailure(
            "one or more diagnostic checks failed".into(),
        ));
    }
    Ok(())
}

fn print_port(
    output: &serde_json::Map<String, serde_json::Value>,
    json: bool,
    target: &str,
) -> Result<()> {
    if json {
        let s = serde_json::to_string_pretty(output)
            .map_err(|e| Error::RuntimeFailure(e.to_string()))?;
        println!("{s}");
    } else if output.get("reachable") == Some(&serde_json::Value::Bool(true)) {
        let svc = output.get("service").and_then(|v| v.as_str()).unwrap_or("");
        if svc.is_empty() {
            println!("{target}: reachable");
        } else {
            println!("{target}: reachable ({svc})");
        }
    } else {
        let err = output
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unreachable");
        println!("{target}: {err}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_cli::{ColorMode, LogLevel, OutputFormat};

    fn global(config: Option<PathBuf>) -> GlobalOpts {
        GlobalOpts {
            config,
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: None,
            profile: None,
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

    #[tokio::test]
    async fn auth_runs_against_inline_config() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("c.toml");
        std::fs::write(
            &cfg,
            r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "agent"
agent = true
"#,
        )
        .unwrap();
        auth(
            &global(Some(cfg)),
            DiagnoseAuthArgs {
                profile: None,
                probe: false,
                json: true,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn trust_handles_missing_config_gracefully() {
        // No config — the diagnostic emits a Skipped check, which is not Fail.
        trust(
            &global(None),
            DiagnoseTrustArgs {
                profile: None,
                json: true,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn port_tcp_unreachable_is_an_ok_outcome() {
        port(
            &global(None),
            DiagnosePortArgs {
                host: "127.0.0.1".into(),
                port: 1,
                tcp: true,
                udp: false,
                autodetect_service: false,
                json: true,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn port_udp_no_responder_returns_nobanner() {
        port(
            &global(None),
            DiagnosePortArgs {
                host: "127.0.0.1".into(),
                port: 1,
                tcp: false,
                udp: true,
                autodetect_service: false,
                json: true,
            },
        )
        .await
        .unwrap();
    }
}
