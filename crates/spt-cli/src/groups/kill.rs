//! `spt kill` — terminate every running `spt` process on the host.
//!
//! Cross-platform: enumerates processes via `sysinfo`, then signals each
//! match through the existing platform-specific terminate path
//! (POSIX `kill(SIGTERM)` / Windows `TerminateProcess`). The current
//! process is skipped by default so calling `spt kill` from a still-running
//! session doesn't trip over itself.

use clap::Args;

/// `spt kill` — terminate every running `spt` instance on this host.
///
/// Matches by executable basename (`spt` on Unix, `spt.exe` on Windows).
/// Override with `--name <regex>` to match alternative binary names (e.g.
/// renamed or development builds).
#[derive(Args, Debug, Clone, Default)]
pub struct KillCmd {
    /// Skip the graceful signal and go straight to a hard kill
    /// (`SIGKILL` / `TerminateProcess`). Default: send a graceful signal
    /// (`SIGTERM` / `TerminateProcess` with grace window) first.
    #[arg(long)]
    pub force: bool,

    /// Include the current process in the kill list (the calling `spt`
    /// itself). Off by default — typical use is "kill all the other ones."
    #[arg(long)]
    pub include_self: bool,

    /// Print what would be killed without actually signalling anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Override the basename matched against running processes. Plain
    /// substring match; case-insensitive. Defaults to `spt` (Unix) /
    /// `spt.exe` (Windows).
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Per-process grace window before the platform terminate returns.
    /// Defaults to 5 seconds. Honoured on Windows
    /// (`WaitForSingleObject`); informational on Unix where `SIGTERM` is
    /// asynchronous.
    #[arg(long, value_name = "DURATION", default_value = "5s")]
    pub timeout: humantime::Duration,
}
