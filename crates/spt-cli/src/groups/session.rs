//! `spt session` — inspect and manage active sessions.

use clap::{Args, Subcommand, ValueEnum};

pub(crate) const EXAMPLES: &str = "EXAMPLES:
  spt session list --profile edge
  spt session show abc123 --json
  spt session close abc123 --grace 5s --reason \"drain\"
  spt session drain edge --timeout 30s
  spt session top --sort bytes --limit 20";

/// `spt session` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct SessionCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: SessionSub,
}

/// Subcommands of `spt session`.
#[derive(Subcommand, Debug)]
pub enum SessionSub {
    /// List sessions.
    List(SessionList),
    /// Show a session.
    Show(SessionShow),
    /// Close a session.
    Close(SessionClose),
    /// Drain sessions for a profile.
    Drain(SessionDrain),
    /// Top-style live view.
    Top(SessionTop),
}

/// `spt session list`.
#[derive(Args, Debug)]
pub struct SessionList {
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

/// `spt session show`.
#[derive(Args, Debug)]
pub struct SessionShow {
    /// Session id.
    #[arg(value_name = "SESSION-ID")]
    pub id: String,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt session close`.
#[derive(Args, Debug)]
pub struct SessionClose {
    /// Session id.
    #[arg(value_name = "SESSION-ID")]
    pub id: String,
    /// Grace period.
    #[arg(long, value_name = "DURATION")]
    pub grace: Option<String>,
    /// Free-form reason for audit.
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
}

/// `spt session drain`.
#[derive(Args, Debug)]
pub struct SessionDrain {
    /// Profile name (positional).
    pub profile: String,
    /// Filter by forward.
    #[arg(long)]
    pub forward: Option<String>,
    /// Drain timeout / grace period. Synonym: `--timeout`.
    #[arg(long, alias = "timeout", value_name = "DURATION")]
    pub grace: Option<String>,
}

/// Sort key for `spt session top`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum SessionSort {
    Age,
    Bytes,
    Rate,
    Errors,
}

/// `spt session top`.
#[derive(Args, Debug)]
pub struct SessionTop {
    /// Sort key.
    #[arg(long, value_enum)]
    pub sort: Option<SessionSort>,
    /// Result limit.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
}
