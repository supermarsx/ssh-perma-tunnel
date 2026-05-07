//! `spt forward` — manage forwards.

use clap::{Args, Subcommand};

const EXAMPLES: &str = "EXAMPLES:
  spt forward add local --profile edge --listen 127.0.0.1:5432 --to db:5432 --tcp
  spt forward add remote --profile edge --listen 0.0.0.0:8080 --to web:80 --tcp
  spt forward throttle edge/db --in 10MiB/s --out 10MiB/s --connections 64
  spt forward test edge/db --connect --dns-name db.local
  spt forward remove edge/db";

/// `spt forward` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct ForwardCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: ForwardSub,
}

/// Subcommands of `spt forward`.
#[derive(Subcommand, Debug)]
pub enum ForwardSub {
    /// List configured forwards.
    List(ForwardList),
    /// Show a forward.
    Show(ForwardShow),
    /// Add a forward.
    Add(ForwardAdd),
    /// Explain how a forward is plumbed.
    Explain(ForwardRef),
    /// Run targeted forward tests.
    Test(ForwardTest),
    /// Update throttle/limit knobs at runtime.
    Throttle(ForwardThrottle),
    /// Remove a forward.
    Remove(ForwardRef),
}

/// `spt forward list`.
#[derive(Args, Debug)]
pub struct ForwardList {
    /// Filter by profile name.
    #[arg(long)]
    pub profile: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt forward show <profile>/<forward>`.
#[derive(Args, Debug)]
pub struct ForwardShow {
    /// `<profile>/<forward>` reference.
    #[arg(value_name = "PROFILE/FORWARD")]
    pub reference: String,
    /// Friendly textual layout.
    #[arg(long)]
    pub friendly: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt forward add`.
#[derive(Args, Debug)]
pub struct ForwardAdd {
    /// Direction selector.
    #[command(subcommand)]
    pub direction: ForwardDirection,
}

/// Direction selector for `spt forward add`.
#[derive(Subcommand, Debug)]
pub enum ForwardDirection {
    /// Local forward (`-L`).
    Local(ForwardAddArgs),
    /// Remote forward (`-R`).
    Remote(ForwardAddArgs),
}

/// Args common to `spt forward add local|remote`.
#[derive(Args, Debug)]
pub struct ForwardAddArgs {
    /// Owning profile name.
    #[arg(long)]
    pub profile: String,
    /// Listen address (`host:port` or `[::1]:port`).
    #[arg(long, value_name = "ADDR:PORT")]
    pub listen: String,
    /// Target address forwarded to.
    #[arg(long, value_name = "HOST:PORT")]
    pub to: String,
    /// TCP forward (default).
    #[arg(long, group = "fwd_proto")]
    pub tcp: bool,
    /// UDP forward (SSH3 only).
    #[arg(long, group = "fwd_proto")]
    pub udp: bool,
}

/// `<profile>/<forward>` shorthand argument.
#[derive(Args, Debug)]
pub struct ForwardRef {
    /// `<profile>/<forward>`.
    #[arg(value_name = "PROFILE/FORWARD")]
    pub reference: String,
}

/// `spt forward test`.
#[derive(Args, Debug)]
pub struct ForwardTest {
    /// `<profile>/<forward>`.
    #[arg(value_name = "PROFILE/FORWARD")]
    pub reference: String,
    /// Probe with a TCP connect.
    #[arg(long)]
    pub connect: bool,
    /// Probe with a DNS resolution.
    #[arg(long, value_name = "NAME")]
    pub dns_name: Option<String>,
    /// Timeout for the connect probe (e.g. `10s`).
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
}

/// `spt forward throttle`.
#[derive(Args, Debug)]
pub struct ForwardThrottle {
    /// `<profile>/<forward>`.
    #[arg(value_name = "PROFILE/FORWARD")]
    pub reference: String,
    /// Inbound rate (e.g. `10MiB/s`).
    #[arg(long, value_name = "RATE")]
    pub r#in: Option<String>,
    /// Outbound rate.
    #[arg(long, value_name = "RATE")]
    pub out: Option<String>,
    /// Per-forward connection limit.
    #[arg(long, value_name = "N")]
    pub connections: Option<u32>,
}
