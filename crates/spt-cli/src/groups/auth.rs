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
    /// Run an SSH3 OIDC / bearer login flow.
    Ssh3Login(AuthProfile),
}

/// Single positional profile argument.
#[derive(Args, Debug)]
pub struct AuthProfile {
    /// Profile name.
    pub profile: String,
}
