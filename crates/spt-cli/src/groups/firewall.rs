//! `spt firewall` — packet-filter rule planning and application.

use clap::{Args, Subcommand};

const EXAMPLES: &str = "EXAMPLES:
  spt firewall plan --profile edge --json
  spt firewall apply --system --dry-run
  spt firewall remove --user
  spt firewall bind-preview --forward edge/db
  spt firewall interfaces --json";

/// `spt firewall` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct FirewallCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: FirewallSub,
}

/// Subcommands of `spt firewall`.
#[derive(Subcommand, Debug)]
pub enum FirewallSub {
    /// Plan rules without applying.
    Plan(FirewallPlan),
    /// Apply rules (idempotent).
    Apply(FirewallApply),
    /// Remove rules.
    Remove(FirewallApply),
    /// Show current applied state.
    Status(FirewallStatus),
    /// List interfaces / bind targets.
    Interfaces(FirewallStatus),
    /// Preview the bind for a forward.
    BindPreview(FirewallBindPreview),
}

/// `spt firewall plan`.
#[derive(Args, Debug)]
pub struct FirewallPlan {
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

/// `spt firewall apply` / `remove`.
#[derive(Args, Debug)]
pub struct FirewallApply {
    /// Filter by profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Filter by forward.
    #[arg(long)]
    pub forward: Option<String>,
    /// User-scoped scope.
    #[arg(long, group = "fw_scope")]
    pub user: bool,
    /// System-scoped scope.
    #[arg(long, group = "fw_scope")]
    pub system: bool,
    /// Print actions without changing system state.
    #[arg(long)]
    pub dry_run: bool,
}

/// `spt firewall status` / `interfaces`.
#[derive(Args, Debug)]
pub struct FirewallStatus {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt firewall bind-preview`.
#[derive(Args, Debug)]
pub struct FirewallBindPreview {
    /// `<profile>/<forward>`.
    #[arg(long, value_name = "PROFILE/FORWARD")]
    pub forward: String,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}
