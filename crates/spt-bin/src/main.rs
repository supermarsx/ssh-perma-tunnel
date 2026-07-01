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
mod dns_health;
mod mcp_client;
mod mcp_listen;
mod mcp_notifier;
mod mcp_server;
mod policy;
mod profile_factory;
mod runtime;
mod scm_dispatch;
mod secrets_bridge;
mod signals;
mod status_api_tls;
mod tracing_init;

#[cfg(test)]
pub(crate) mod test_locks {
    //! Process-global env locks shared across the crate's unit-test modules.
    //!
    //! All of `spt-bin`'s unit tests compile into a SINGLE test binary and run
    //! in parallel by default, so tests in DIFFERENT modules that mutate the
    //! SAME process env var must serialise on ONE mutex. Keying the lock here
    //! (rather than a per-module static) is what stops e.g. `signals.rs` and
    //! `tracing_init.rs` — which both mutate `SPT_LOG` — from racing when run
    //! WITHOUT `--test-threads=1`.
    use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

    fn guard(cell: &'static OnceLock<Mutex<()>>) -> MutexGuard<'static, ()> {
        cell.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Serialises any test that reads or mutates the `SPT_LOG` env var.
    pub(crate) fn spt_log_env() -> MutexGuard<'static, ()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        guard(&L)
    }
}

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
    // dump cap). Runs once, never panics. Failure is silent by design —
    // defense-in-depth, not a hard contract.
    //
    // E7-F15: do NOT log here — no tracing subscriber is installed yet, so
    // the report would go to a no-op subscriber and a failed mitigation
    // (`err_count() > 0`) would never be surfaced. We stash the report and
    // log it (warn on any errors) right *after* tracing init below — once on
    // the CLI path, and inside `enter_scm_dispatch` for the SCM path.
    let hardening = spt_mem_hygiene::harden();

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
        // The SCM service path initialises its own tracing subscriber (file
        // sink under the state dir + winevent mirror) inside
        // `enter_scm_dispatch`, *before* the orchestrator boots, so service
        // startup failures are observable (E7-F1). The mem-hygiene report is
        // handed in so it can be logged once that subscriber exists (E7-F15).
        let result = scm_dispatch::enter_scm_dispatch("spt", hardening);
        return map_exit(result);
    }

    let cli = match <Cli as clap::Parser>::try_parse_from(&raw_args) {
        Ok(c) => c,
        Err(e) => {
            // Render clap's formatted error/help to the appropriate stream,
            // then map to a spec-compliant exit code. clap's default
            // `e.exit()` exits 2 on usage errors, but the §7.4 contract
            // reserves 2 for `InvalidConfig`; genuine usage errors must be
            // `InvalidArgs` (1). `--help`/`--version` are successful (0).
            return clap_error_exit(&e);
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
        let guard = tracing_init::init_minimal(&cli.global);
        // E7-F15: now that a subscriber exists, surface the mem-hygiene
        // report. Commands that defer tracing to config (`tunnel run`) log it
        // once they install their own subscriber.
        log_hardening_report(&hardening);
        guard
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

/// Log the memory-hygiene hardening report (E7-F15).
///
/// Must be called *after* a tracing subscriber is installed. Emits a `warn!`
/// when any mitigation failed (`err_count() > 0`) so a silently-rejected
/// hardening step — e.g. a dynamic-code policy the OS refused — is visible;
/// otherwise logs the full report at `debug`.
pub(crate) fn log_hardening_report(report: &spt_mem_hygiene::HardeningReport) {
    if report.err_count() > 0 {
        tracing::warn!(
            errors = report.err_count(),
            report = %report,
            "spt-mem-hygiene: one or more hardening mitigations failed"
        );
    } else {
        tracing::debug!(report = ?report, "spt-mem-hygiene applied");
    }
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

/// Render a clap parse error/help/version message to the right stream and
/// translate clap's exit semantics into the project's §7.4 exit contract.
///
/// clap's own `Error::exit` exits 2 for usage errors, which collides with the
/// documented `InvalidConfig` code. Instead:
///   * `DisplayHelp` / `DisplayVersion` (and the help-on-missing-subcommand
///     variant) print to stdout and exit 0 — these are successful requests.
///   * every other kind is a genuine usage error: print to stderr and exit
///     `InvalidArgs` (1).
fn clap_error_exit(e: &clap::Error) -> ProcExitCode {
    use clap::error::ErrorKind;
    let code = clap_exit_code(e.kind());
    if matches!(
        e.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayVersion
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    ) {
        // clap renders help/version to stdout; mirror that.
        print!("{e}");
    } else {
        eprint!("{e}");
    }
    ProcExitCode::from(code as u8)
}

/// Pure mapping from a clap [`ErrorKind`](clap::error::ErrorKind) to the
/// process exit code. Split out from [`clap_error_exit`] so the contract is
/// unit-testable without the rendering side effects.
fn clap_exit_code(kind: clap::error::ErrorKind) -> i32 {
    use clap::error::ErrorKind;
    match kind {
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => 0,
        // Every other kind is a genuine usage error. §7.4 reserves 1 for
        // InvalidArgs (clap's default would be 2 = InvalidConfig).
        _ => ExitCode::InvalidArgs.as_i32(),
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

/// Build a [`Styler`](crate::cli::style::Styler) honoring the resolved
/// color policy. Renderers should call this once and thread the result
/// through their human-output paths.
pub(crate) fn styler(global: &GlobalOpts) -> crate::cli::style::Styler {
    crate::cli::style::Styler::new(color_enabled(global))
}

/// Convenience for handlers: should we honor color escapes?
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
            // Color escapes go on the stdout-bound output, so probe stdout's
            // tty status (E4-F16) — not stderr.
            use std::io::IsTerminal;
            std::io::stdout().is_terminal()
        }
    }
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

#[cfg(test)]
mod clap_exit_tests {
    use super::*;

    /// Parse `args` through `Cli`, expecting a clap error, and return the
    /// exit code our mapping assigns to it.
    fn exit_code_for(args: &[&str]) -> i32 {
        let err = <Cli as clap::Parser>::try_parse_from(args)
            .expect_err("expected clap to reject/short-circuit these args");
        clap_exit_code(err.kind())
    }

    #[test]
    fn usage_error_maps_to_invalid_args() {
        // Unknown flag — a genuine usage error. clap defaults to exit 2;
        // the §7.4 contract requires InvalidArgs (1).
        assert_eq!(
            exit_code_for(&["spt", "--definitely-not-a-flag"]),
            ExitCode::InvalidArgs.as_i32()
        );
        assert_eq!(ExitCode::InvalidArgs.as_i32(), 1);
    }

    #[test]
    fn unknown_subcommand_maps_to_invalid_args() {
        assert_eq!(
            exit_code_for(&["spt", "not-a-real-subcommand"]),
            ExitCode::InvalidArgs.as_i32()
        );
    }

    #[test]
    fn help_maps_to_zero() {
        assert_eq!(exit_code_for(&["spt", "--help"]), 0);
    }

    #[test]
    fn version_maps_to_zero() {
        assert_eq!(exit_code_for(&["spt", "--version"]), 0);
    }

    #[test]
    fn missing_subcommand_help_maps_to_zero() {
        // `spt` with no subcommand short-circuits with a help/usage display;
        // whichever help variant clap emits must still be a success (0).
        assert_eq!(exit_code_for(&["spt"]), 0);
    }
}
