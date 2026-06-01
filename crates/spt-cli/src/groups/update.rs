//! `spt update` — embedded auto-updater CLI surface.
//!
//! The runtime polling thread lives in `spt-updater` and is spawned by
//! the supervisor when `[updater].enabled = true`. The commands below
//! are the operator-facing surface: every one works regardless of
//! whether the background thread is running.

use clap::{Args, Subcommand};

/// `spt update` — manage the embedded auto-updater.
#[derive(Args, Debug, Clone)]
pub struct UpdateCmd {
    /// Subcommand. Defaults to `status` when omitted (matches the
    /// convention used by `spt about` / `spt mcp`).
    #[command(subcommand)]
    pub command: Option<UpdateSub>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum UpdateSub {
    /// One-shot poll: print whether a newer release is available.
    Check(UpdateCheck),
    /// Download the latest artifact to the staging directory without
    /// installing.
    Download(UpdateDownload),
    /// Install the staged artifact (atomic swap, then optional restart).
    Apply(UpdateApply),
    /// Run `check` + `download` + `apply` in one go.
    Now(UpdateNow),
    /// Print current status: enabled flag, last check, latest version,
    /// next-scheduled tick, staged artifact.
    Status(UpdateStatus),
    /// Past update events from the audit log.
    History(UpdateHistory),
}

#[derive(Args, Debug, Clone, Default)]
pub struct UpdateCheck {
    /// Bypass `[updater].source` and consult the named source kind.
    /// One of `github|url|static`. Optional override for one-off probes.
    #[arg(long, value_name = "KIND")]
    pub source: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct UpdateDownload {
    /// Target triple to fetch. Defaults to the running spt's target.
    #[arg(long, value_name = "TRIPLE")]
    pub target: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct UpdateApply {
    /// Skip the post-install restart even when
    /// `[updater.action].restart_supervisor = true`.
    #[arg(long)]
    pub no_restart: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct UpdateNow {
    /// Skip the post-install restart.
    #[arg(long)]
    pub no_restart: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct UpdateStatus {
    /// Emit JSON instead of the human table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct UpdateHistory {
    /// How many past events to display. Default 10.
    #[arg(long, value_name = "N", default_value_t = 10)]
    pub limit: u32,
}
