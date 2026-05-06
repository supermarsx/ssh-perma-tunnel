//! `spt auth` — authentication helpers.

use clap::{Args, Subcommand};

/// `spt auth` group.
#[derive(Args, Debug)]
pub struct AuthCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: AuthSub,
}

/// Subcommands of `spt auth`.
#[derive(Subcommand, Debug)]
pub enum AuthSub {
    /// Test authentication for a profile.
    Test(AuthProfile),
    /// Run an SSH3 OIDC device-flow login and optionally store the token.
    Ssh3Login(AuthSsh3Login),
}

/// Single positional profile argument.
#[derive(Args, Debug)]
pub struct AuthProfile {
    /// Profile name.
    pub profile: String,
}

/// `spt auth ssh3-login`.
#[derive(Args, Debug)]
pub struct AuthSsh3Login {
    /// OIDC issuer URL (the `.well-known/openid-configuration` parent).
    #[arg(long, value_name = "URL")]
    pub issuer: String,
    /// OAuth client id registered with the issuer.
    #[arg(long, value_name = "ID")]
    pub client_id: String,
    /// Optional OAuth audience.
    #[arg(long, value_name = "AUD")]
    pub audience: Option<String>,
    /// Optional space-separated scope (defaults to `openid offline_access`).
    #[arg(long, value_name = "SCOPE")]
    pub scope: Option<String>,
    /// If set, persist the resulting access (and refresh) token through
    /// the configured secret backend at this `secret://ns/name` ref.
    #[arg(long, value_name = "secret://ns/name")]
    pub save_as: Option<String>,
    /// JSON output (machine-readable).
    #[arg(long)]
    pub json: bool,
}
