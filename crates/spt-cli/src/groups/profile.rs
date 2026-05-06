//! `spt profile` — manage tunnel profiles.

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt profile add edge --protocol ssh2 --host gw.example --user ubuntu
  spt profile configure --tui --name edge
  spt profile set edge keepalive.interval=30s reconnect.max_backoff=2m
  spt profile enable edge
  spt profile test edge --connect-only";

/// `spt profile` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct ProfileCmd {
    /// Subcommand selecting the profile operation.
    #[command(subcommand)]
    pub command: ProfileSub,
}

/// Protocol selector for new profiles.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Protocol {
    Ssh2,
    Ssh3,
}

/// Subcommands of `spt profile`.
#[derive(Subcommand, Debug)]
pub enum ProfileSub {
    /// List configured profiles.
    List(ProfileList),
    /// Show the resolved profile (optionally redacted).
    Show(ProfileShow),
    /// Add a new profile.
    Add(ProfileAdd),
    /// Interactive TUI configurator.
    Configure(ProfileConfigure),
    /// Set one or more `key=value` overrides.
    Set(ProfileSet),
    /// Enable a profile.
    Enable(ProfileName),
    /// Disable a profile.
    Disable(ProfileName),
    /// Remove a profile.
    Remove(ProfileName),
    /// Run targeted profile tests.
    Test(ProfileTest),
}

/// `spt profile list`.
#[derive(Args, Debug)]
pub struct ProfileList {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt profile show <name>`.
#[derive(Args, Debug)]
pub struct ProfileShow {
    /// Profile name.
    pub name: String,
    /// Redact secret fields.
    #[arg(long)]
    pub redacted: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt profile add`.
#[derive(Args, Debug)]
pub struct ProfileAdd {
    /// Profile name.
    pub name: String,
    /// Protocol selector.
    #[arg(long, value_enum)]
    pub protocol: Protocol,
    /// Remote host.
    #[arg(long)]
    pub host: String,
    /// SSH user.
    #[arg(long)]
    pub user: String,
}

/// `spt profile configure`.
#[derive(Args, Debug)]
pub struct ProfileConfigure {
    /// Profile name (created if missing).
    #[arg(long)]
    pub name: Option<String>,
    /// Force the TUI wizard.
    #[arg(long, conflicts_with = "no_tui")]
    pub tui: bool,
    /// Disable the TUI wizard (non-interactive).
    #[arg(long)]
    pub no_tui: bool,
    /// Seed from a built-in template.
    #[arg(long, value_name = "NAME")]
    pub from_template: Option<String>,
}

/// `spt profile set`.
#[derive(Args, Debug)]
pub struct ProfileSet {
    /// Profile name.
    pub name: String,
    /// One or more `key=value` pairs.
    #[arg(value_name = "KEY=VALUE", required = true)]
    pub overrides: Vec<String>,
}

/// `spt profile enable|disable|remove <name>`.
#[derive(Args, Debug)]
pub struct ProfileName {
    /// Profile name.
    pub name: String,
}

/// `spt profile test`.
#[derive(Args, Debug)]
pub struct ProfileTest {
    /// Profile name.
    pub name: String,
    /// Only test connect.
    #[arg(long, group = "profile_test_scope")]
    pub connect_only: bool,
    /// Only test bind.
    #[arg(long, group = "profile_test_scope")]
    pub bind_only: bool,
    /// Only test auth.
    #[arg(long, group = "profile_test_scope")]
    pub auth_only: bool,
    /// Only test trust (host-key/TLS pin).
    #[arg(long, group = "profile_test_scope")]
    pub trust_only: bool,
    /// Only test DNS.
    #[arg(long, group = "profile_test_scope")]
    pub dns_only: bool,
}
