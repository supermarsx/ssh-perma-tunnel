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
mod tracing_init;

pub(crate) use benchmark_bridge::run_live_benchmark;

use std::path::PathBuf;
use std::process::ExitCode as ProcExitCode;

use spt_cli::{Cli, ColorMode, GlobalOpts, LogLevel};
use spt_core::{Error, ExitCode, Result};

fn main() -> ProcExitCode {
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

    let cli = Cli::parse_args();

    // Tracing: best-effort init from CLI flags. We can't read config yet
    // (commands like `config validate` parse it themselves), so we initialise
    // a minimal stderr subscriber up-front and let long-running commands
    // (`tunnel run`, `service run`, `mcp serve`) re-init through the proper
    // pipeline once they own the config.
    let _trace_guard = tracing_init::init_minimal(&cli.global);

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
            // Emit a one-line human summary to stderr. Detailed diagnostics
            // are produced by the per-command handlers (which use miette
            // where useful).
            eprintln!("spt: {e}");
            ProcExitCode::from(e.exit_code().as_i32() as u8)
        }
    }
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
    Error::RuntimeFailure(format!(
        "`{cmd}` is not yet implemented in this milestone (tracked in {milestone}). \
         See docs/milestones.md."
    ))
}
