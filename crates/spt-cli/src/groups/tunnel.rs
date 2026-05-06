//! `spt tunnel` — runtime control.

use clap::{Args, Subcommand};

const EXAMPLES: &str = "EXAMPLES:
  spt tunnel run --foreground
  spt tunnel run --once --profiles edge,backup
  spt tunnel status --watch --json
  spt tunnel failover edge --to dr --reason \"primary degraded\"
  spt tunnel reload --wait";

/// `spt tunnel` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct TunnelCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: TunnelSub,
}

/// Subcommands of `spt tunnel`.
#[derive(Subcommand, Debug)]
pub enum TunnelSub {
    /// Run configured tunnels.
    Run(TunnelRun),
    /// Show overall tunnel status.
    Status(TunnelStatus),
    /// Live or one-shot stats.
    Stats(TunnelStats),
    /// List active sessions.
    Sessions(TunnelSessions),
    /// Stop tunnels.
    Stop(TunnelStop),
    /// Reload running configuration.
    Reload(TunnelReload),
    /// Health summary.
    Health(TunnelHealth),
    /// Manually trigger failover for a profile.
    Failover(TunnelFailover),
}

/// `spt tunnel run`.
#[derive(Args, Debug)]
pub struct TunnelRun {
    /// Run in the foreground.
    #[arg(long)]
    pub foreground: bool,
    /// Start once and exit non-zero on startup failure.
    #[arg(long)]
    pub once: bool,
    /// Comma-separated profile filter.
    #[arg(long, value_name = "A,B,C", value_delimiter = ',')]
    pub profiles: Vec<String>,
}

/// `spt tunnel status`.
#[derive(Args, Debug)]
pub struct TunnelStatus {
    /// Continuously refresh.
    #[arg(long)]
    pub watch: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt tunnel stats`.
#[derive(Args, Debug)]
pub struct TunnelStats {
    /// Filter by profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Filter by forward.
    #[arg(long)]
    pub forward: Option<String>,
    /// Refresh interval.
    #[arg(long, value_name = "DURATION")]
    pub interval: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt tunnel sessions`.
#[derive(Args, Debug)]
pub struct TunnelSessions {
    /// Filter by profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Filter by forward.
    #[arg(long)]
    pub forward: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt tunnel stop`.
#[derive(Args, Debug)]
pub struct TunnelStop {
    /// Stop a specific profile (or all if absent).
    #[arg(long)]
    pub profile: Option<String>,
    /// Grace period for in-flight connections.
    #[arg(long, value_name = "DURATION")]
    pub grace: Option<String>,
}

/// `spt tunnel reload`.
#[derive(Args, Debug)]
pub struct TunnelReload {
    /// Block until reload finishes.
    #[arg(long)]
    pub wait: bool,
}

/// `spt tunnel health`.
#[derive(Args, Debug)]
pub struct TunnelHealth {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt tunnel failover`.
#[derive(Args, Debug)]
pub struct TunnelFailover {
    /// Profile name.
    pub profile: String,
    /// Override target endpoint as `host:port`. Synonym: `--to`.
    #[arg(long, alias = "to", value_name = "ENDPOINT")]
    pub endpoint: Option<String>,
    /// Free-form reason for audit.
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
}
