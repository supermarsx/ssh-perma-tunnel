//! `spt status` — app-status overview, and `spt status-api` — read-only
//! status API server controls.
//!
//! `spt status` renders a one-shot (or `--watch` live) overview of the whole
//! application: the daemon/supervisor, tunnels and profiles, forwards, and the
//! optional subsystems (status API, MCP, DNS, metrics, remote-config, events,
//! services).
//!
//! `spt status-api` operates on the optional read-only HTTP/JSON status API
//! defined in plan §t4-e5. The supervisor normally hosts the server inline
//! when `[status_api].enabled = true`; the `serve` subcommand is a foreground
//! fallback that doesn't require the supervisor to be running.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::OutputFormat;

// ---------------------------------------------------------------------------
// `spt status` — app-status overview
// ---------------------------------------------------------------------------

pub(crate) const STATUS_EXAMPLES: &str = "EXAMPLES:
  spt status
  spt status --detail
  spt status --json
  spt status --output yaml
  spt status --watch";

/// `spt status` — app-status overview command.
///
/// A single overview (no subcommands): summarises the daemon, tunnels and
/// profiles, forwards, and subsystem health.
#[derive(Args, Debug)]
#[command(after_help = STATUS_EXAMPLES)]
pub struct StatusCmd {
    /// Output format for the overview (overrides the global `--output`).
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub output: Option<OutputFormat>,
    /// Convenience alias for `--output json` (machine-readable overview).
    #[arg(long)]
    pub json: bool,
    /// Show verbose per-component state (resolved bind addresses, auth modes,
    /// last-error detail, per-forward counters) instead of the compact roll-up.
    #[arg(long)]
    pub detail: bool,
    /// Continuously refresh the overview in place instead of printing once.
    #[arg(long)]
    pub watch: bool,
}

// ---------------------------------------------------------------------------
// `spt status-api` — read-only HTTP status API controls
// ---------------------------------------------------------------------------

pub(crate) const STATUS_API_EXAMPLES: &str = "EXAMPLES:
  spt status-api show
  spt status-api show --output json
  spt status-api serve --config /etc/spt/spt.toml
  spt status-api token rotate";

/// `spt status-api` group.
#[derive(Args, Debug)]
#[command(after_help = STATUS_API_EXAMPLES)]
pub struct StatusApiCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: StatusApiSub,
}

/// Subcommands of `spt status-api`.
#[derive(Subcommand, Debug)]
pub enum StatusApiSub {
    /// Run the status API server in foreground (rare — supervisor normally
    /// hosts inline when `[status_api].enabled = true`).
    Serve(StatusApiServeArgs),
    /// Show whether the API is bound + how to reach it.
    Show(StatusApiShowArgs),
    /// Bearer-token management for the status API auth.
    Token(StatusApiTokenCmd),
}

/// `spt status-api serve`.
#[derive(Args, Debug)]
pub struct StatusApiServeArgs {
    /// Override config path (otherwise inherits `--config`).
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Override the bind address. Defaults to the value in `[status_api].bind`.
    #[arg(long, value_name = "HOST:PORT")]
    pub bind: Option<String>,
}

/// `spt status-api show`.
#[derive(Args, Debug)]
pub struct StatusApiShowArgs {
    /// Show the resolved auth mode and TLS state in addition to the bind.
    #[arg(long = "detail")]
    pub detail: bool,
}

/// `spt status-api token` — token-management subcommands.
#[derive(Args, Debug)]
pub struct StatusApiTokenCmd {
    /// Token subcommand.
    #[command(subcommand)]
    pub command: StatusApiTokenSub,
}

/// Subcommands of `spt status-api token`.
#[derive(Subcommand, Debug)]
pub enum StatusApiTokenSub {
    /// Rotate the bearer token in the vault (only when `auth.mode = "bearer"`
    /// and the `token_from` SecretRef points at a writable backend).
    Rotate(StatusApiTokenRotateArgs),
}

/// `spt status-api token rotate`.
#[derive(Args, Debug)]
pub struct StatusApiTokenRotateArgs {
    /// Print the new token to stdout (default: only print success +
    /// SecretRef). Useful for piping into other tooling.
    #[arg(long)]
    pub print_token: bool,
    /// Length in bytes of the random token before base64 encoding. Defaults
    /// to 32 (256-bit).
    #[arg(long, value_name = "BYTES", default_value_t = 32)]
    pub bytes: usize,
}
