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

mod cli_dispatch;
mod controller;
mod mcp_server;
mod profile_factory;
mod runtime;
mod secrets_bridge;
mod signals;
mod tracing_init;

use std::path::PathBuf;
use std::process::ExitCode as ProcExitCode;

use spt_cli::{Cli, ColorMode, GlobalOpts, LogLevel};
use spt_core::{Error, ExitCode, Result};

fn main() -> ProcExitCode {
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
