//! `spt status` — read-only status API server controls.
//!
//! These subcommands operate on the optional read-only HTTP/JSON status API
//! defined in plan §t4-e5. The supervisor normally hosts the server inline
//! when `[status_api].enabled = true`; the `serve` subcommand is a foreground
//! fallback that doesn't require the supervisor to be running.

use std::path::PathBuf;

use clap::{Args, Subcommand};

const EXAMPLES: &str = "EXAMPLES:
  spt status status
  spt status status --output json
  spt status serve --config /etc/spt/spt.toml
  spt status token rotate";

/// `spt status` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct StatusCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: StatusSub,
}

/// Subcommands of `spt status`.
#[derive(Subcommand, Debug)]
pub enum StatusSub {
    /// Run the status API server in foreground (rare — supervisor normally
    /// hosts inline when `[status_api].enabled = true`).
    Serve(StatusServeArgs),
    /// Show whether the API is bound + how to reach it.
    Status(StatusStatusArgs),
    /// Bearer-token management for the status API auth.
    Token(StatusTokenCmd),
}

/// `spt status serve`.
#[derive(Args, Debug)]
pub struct StatusServeArgs {
    /// Override config path (otherwise inherits `--config`).
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Override the bind address. Defaults to the value in `[status_api].bind`.
    #[arg(long, value_name = "HOST:PORT")]
    pub bind: Option<String>,
}

/// `spt status status`.
#[derive(Args, Debug)]
pub struct StatusStatusArgs {
    /// Show the resolved auth mode and TLS state in addition to the bind.
    #[arg(long = "detail")]
    pub detail: bool,
}

/// `spt status token` — token-management subcommands.
#[derive(Args, Debug)]
pub struct StatusTokenCmd {
    /// Token subcommand.
    #[command(subcommand)]
    pub command: StatusTokenSub,
}

/// Subcommands of `spt status token`.
#[derive(Subcommand, Debug)]
pub enum StatusTokenSub {
    /// Rotate the bearer token in the vault (only when `auth.mode = "bearer"`
    /// and the `token_from` SecretRef points at a writable backend).
    Rotate(StatusTokenRotateArgs),
}

/// `spt status token rotate`.
#[derive(Args, Debug)]
pub struct StatusTokenRotateArgs {
    /// Print the new token to stdout (default: only print success +
    /// SecretRef). Useful for piping into other tooling.
    #[arg(long)]
    pub print_token: bool,
    /// Length in bytes of the random token before base64 encoding. Defaults
    /// to 32 (256-bit).
    #[arg(long, value_name = "BYTES", default_value_t = 32)]
    pub bytes: usize,
}
