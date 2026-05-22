//! `spt` — permanent SSH2/SSH3 tunnel CLI binary entry point.
//!
//! Wires the parsed [`spt_cli::Cli`] to the implementing crates. The actual
//! command dispatch tree lives in [`cli_dispatch`]; this file owns process
//! lifecycle (runtime build, state-lock acquisition, signal handlers, exit
//! code mapping).

#![allow(clippy::needless_pass_by_value)]
// Several module-level helpers exist as anchored public-API surface that
// later milestones will exercise (e.g. config-driven runtime sizing,
// orchestrator controller hookup). Suppress the dead-code warnings.
#![allow(dead_code)]

mod audit;
mod benchmark_bridge;
mod cli;
mod cli_dispatch;
mod controller;
mod mcp_client;
mod mcp_listen;
mod mcp_server;
mod policy;
mod profile_factory;
mod runtime;
mod scm_dispatch;
mod secrets_bridge;
mod signals;
mod status_api_tls;
mod tracing_init;

pub(crate) use benchmark_bridge::run_live_benchmark;

use std::path::PathBuf;
use std::process::ExitCode as ProcExitCode;

use spt_cli::{groups, Cli, ColorMode, Command, GlobalOpts, LogLevel};
use spt_core::{Error, ExitCode, Result};

fn main() -> ProcExitCode {
    // ------------------------------------------------------------------
    // Pre-clap scan for the global `--portable` flag (t6-e8).
    //
    // The flag is intentionally NOT declared on `spt_cli::GlobalOpts` —
    // adding it there would touch a crate outside this executor's lock
    // budget. We strip the flag from the raw argv before clap sees the
    // rest, then install the resulting context into the three
    // process-global slots that gate BaseDirs leakage:
    //
    // * `spt_state::portable::install` — state dir, file sink root.
    // * `spt_secrets::set_portable_mode` — keyring skip + file-backed
    //   master key.
    // * `spt_config::load::set_portable_mode` — `~/.ssh/config` skip.
    let (raw_args, portable) = portable_pre_scan(std::env::args_os());

    let portable_install = if portable {
        match resolve_portable_context() {
            Ok(ctx) => {
                let root = ctx.root.clone();
                spt_state::portable::install(Some(ctx));
                spt_secrets::set_portable_mode(true);
                spt_config::load::set_portable_mode(true);
                Some(root)
            }
            Err(e) => {
                eprintln!("spt: --portable: {e}");
                return ProcExitCode::from(ExitCode::RuntimeFailure.as_i32() as u8);
            }
        }
    } else {
        None
    };

    // Memory-hygiene hardening: best-effort process-level lockdown
    // (PR_SET_DUMPABLE=0 + drop SeDebugPrivilege + PT_DENY_ATTACH + core
    // dump cap). Runs once, never panics, returns a report we log at
    // debug. Failure is silent by design — defense-in-depth, not a hard
    // contract.
    let hardening = spt_mem_hygiene::harden();
    tracing::debug!(report = ?hardening, "spt-mem-hygiene applied");

    if let Some(root) = portable_install.as_ref() {
        if let Err(e) = spt_state::ensure_writable(root) {
            eprintln!("spt: --portable: {e}");
            return ProcExitCode::from(ExitCode::RuntimeFailure.as_i32() as u8);
        }
    }

    // Windows SCM dispatch path: if SCM started us, the ImagePath ends in
    // `--scm-dispatch`. Detect it BEFORE clap parses `Cli` (clap doesn't
    // know about the flag and would reject it). The dispatch handler builds
    // its own tokio runtime, so we short-circuit out of the normal
    // CLI/runtime bootstrap entirely.
    if scm_dispatch::is_scm_dispatch_invocation() {
        // Tracing initialisation deferred to the orchestrator path inside
        // `enter_scm_dispatch` — once the config has been loaded the full
        // `spt-observability` pipeline can be wired. Until then the only
        // visible output is whatever ships via `tracing` defaults (no-op).
        let result = scm_dispatch::enter_scm_dispatch("spt");
        return map_exit(result);
    }

    let cli = match <Cli as clap::Parser>::try_parse_from(&raw_args) {
        Ok(c) => c,
        Err(e) => {
            // Defer to clap's built-in formatter (handles --help/--version
            // exit codes correctly).
            e.exit();
        }
    };

    // Tracing: best-effort init from CLI flags. We can't read config yet
    // (commands like `config validate` parse it themselves), so we initialise
    // a minimal stderr subscriber up-front and let long-running commands
    // (`tunnel run`, `service run`, `mcp serve`) re-init through the proper
    // pipeline once they own the config.
    let _trace_guard = if defers_tracing_to_config(&cli) {
        None
    } else {
        tracing_init::init_minimal(&cli.global)
    };

    // Build a runtime sized to the threads section if config is loadable;
    // otherwise default. Most commands are short-lived so a small mt runtime
    // is fine.
    let rt = match runtime::build_default_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("spt: failed to build async runtime: {e}");
            return ProcExitCode::from(ExitCode::RuntimeFailure.as_i32() as u8);
        }
    };

    let result = rt.block_on(run(cli));
    rt.shutdown_timeout(std::time::Duration::from_secs(5));
    map_exit(result)
}

async fn run(cli: Cli) -> Result<()> {
    cli_dispatch::dispatch(cli).await
}

fn map_exit(r: Result<()>) -> ProcExitCode {
    match r {
        Ok(()) => ProcExitCode::from(0),
        Err(e) => {
            // t8-A1: when the error carries a structured `Diagnostic`, render
            // it through miette's graphical reporter (the workspace enables
            // miette's `fancy` feature) so the operator sees help text and
            // file/line context. Operator can force the legacy one-line
            // format via `SPT_DIAGNOSTIC_STYLE=plain`. Legacy `String`-payload
            // variants always keep their original one-line format.
            let style_plain = std::env::var_os("SPT_DIAGNOSTIC_STYLE")
                .is_some_and(|v| v.eq_ignore_ascii_case("plain"));
            if let (false, Some(diag)) = (style_plain, e.diagnostic()) {
                // Clone the Diagnostic into a miette::Report; this routes
                // the Display + help() output through miette's
                // GraphicalReportHandler. The `{:?}` formatter on Report
                // invokes the configured handler (NOT std Debug).
                let report = miette::Report::new(diag.clone());
                eprintln!("spt error (exit {}):", e.exit_code().as_i32());
                eprintln!("{report:?}");
            } else {
                eprintln!("spt: {e}");
            }
            ProcExitCode::from(e.exit_code().as_i32() as u8)
        }
    }
}

fn defers_tracing_to_config(cli: &Cli) -> bool {
    matches!(
        &cli.command,
        Command::Tunnel(groups::tunnel::TunnelCmd {
            command: groups::tunnel::TunnelSub::Run(_),
        })
    )
}

/// Resolve the config path with the documented precedence:
/// `--config` > `$SPT_CONFIG` (handled by clap `env`) > per-OS default.
pub(crate) fn resolve_config_path(global: &GlobalOpts) -> Option<PathBuf> {
    global.config.clone()
}

/// Convert the CLI log level to the tracing filter directive.
pub(crate) fn log_level_directive(level: LogLevel, verbose: u8) -> String {
    let base = match level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    };
    if verbose >= 2 {
        "trace".into()
    } else if verbose == 1 {
        "debug".into()
    } else {
        base.into()
    }
}

/// Convenience for handlers: should we honor color escapes?
#[allow(dead_code)]
pub(crate) fn color_enabled(global: &GlobalOpts) -> bool {
    if global.no_color {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    match global.color {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            // crude tty check; full atty handling lives in `is_terminal`.
            use std::io::IsTerminal;
            std::io::stderr().is_terminal()
        }
    }
}

/// Construct an `Error` indicating a not-yet-implemented subcommand.
/// Used by `cli_dispatch` for commands tracked in a later milestone so the
/// process exits cleanly with exit code `RuntimeFailure` rather than panicking.
pub(crate) fn stub_err(cmd: &str, milestone: &str) -> Error {
    Error::runtime_failure(
        spt_core::Diagnostic::what(format!(
            "Subcommand `{cmd}` is not yet implemented in this build"
        ))
        .why(format!("scheduled for milestone {milestone}"))
        .how_to_fix(
            "Check `docs/milestones.md` for the planned ship date, or pin to a \
             release that includes the feature.",
        )
        .retry_advice(spt_core::RetryAdvice::NotRetryable)
        .build(),
    )
}

/// Strip the global `--portable` flag from a raw argv. Returns the
/// filtered argv plus a boolean indicating whether the flag was seen.
///
/// Anything after a `--` terminator is left intact so a future
/// `spt exec -- foo --portable bar` invocation would pass `--portable`
/// to the child unmodified. The flag is otherwise position-agnostic.
pub(crate) fn portable_pre_scan<I, S>(args: I) -> (Vec<std::ffi::OsString>, bool)
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let mut seen = false;
    let mut after_term = false;
    for raw in args {
        let arg = raw.into();
        if after_term {
            out.push(arg);
            continue;
        }
        if arg == "--" {
            after_term = true;
            out.push(arg);
            continue;
        }
        if arg == "--portable" {
            seen = true;
            continue;
        }
        out.push(arg);
    }
    (out, seen)
}

/// Resolve a [`spt_state::PortableContext`] from the running executable.
fn resolve_portable_context() -> Result<spt_state::PortableContext> {
    let exe = std::env::current_exe().map_err(|e| {
        Error::RuntimeFailure(format!(
            "--portable: could not determine executable path: {e}"
        ))
    })?;
    spt_state::portable_context_for(&exe)
}

#[cfg(test)]
mod portable_tests {
    use super::*;
    use std::ffi::OsString;

    fn vs(items: &[&str]) -> Vec<OsString> {
        items.iter().map(|s| OsString::from(*s)).collect()
    }

    #[test]
    fn pre_scan_strips_flag() {
        let (out, seen) = portable_pre_scan(vs(&["spt", "--portable", "tunnel", "run"]));
        assert!(seen);
        assert_eq!(out, vs(&["spt", "tunnel", "run"]));
    }

    #[test]
    fn pre_scan_returns_false_when_absent() {
        let (out, seen) = portable_pre_scan(vs(&["spt", "tunnel", "list"]));
        assert!(!seen);
        assert_eq!(out, vs(&["spt", "tunnel", "list"]));
    }

    #[test]
    fn pre_scan_preserves_args_after_terminator() {
        let (out, seen) =
            portable_pre_scan(vs(&["spt", "exec", "--", "child", "--portable", "arg"]));
        assert!(!seen);
        assert_eq!(
            out,
            vs(&["spt", "exec", "--", "child", "--portable", "arg"])
        );
    }

    #[test]
    fn pre_scan_strips_flag_after_subcommand() {
        let (out, seen) = portable_pre_scan(vs(&["spt", "tunnel", "run", "--portable"]));
        assert!(seen);
        assert_eq!(out, vs(&["spt", "tunnel", "run"]));
    }
}
