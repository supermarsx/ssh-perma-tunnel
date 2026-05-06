//! `spt mcp` — Model Context Protocol server controls.

use std::path::PathBuf;

use clap::{Args, Subcommand};

const EXAMPLES: &str = "EXAMPLES:
  spt mcp serve --stdio --read-only --enable
  spt mcp serve --listen 127.0.0.1:9095 --read-only --enable
  spt mcp inspect --json
  spt mcp policy show
  spt mcp policy set allow_write_tools=profile.set,event.test";

/// `spt mcp` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct McpCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: McpSub,
}

/// Subcommands of `spt mcp`.
#[derive(Subcommand, Debug)]
pub enum McpSub {
    /// Run the MCP server.
    Serve(McpServe),
    /// Inspect MCP capabilities, resources, tools.
    Inspect(McpInspect),
    /// Manage the MCP policy.
    Policy(McpPolicy),
}

/// `spt mcp serve`.
#[derive(Args, Debug)]
pub struct McpServe {
    /// Speak MCP over stdio.
    #[arg(long, group = "mcp_transport")]
    pub stdio: bool,
    /// Listen on a loopback TCP address (`127.0.0.1:port`).
    #[arg(long, value_name = "127.0.0.1:PORT", group = "mcp_transport")]
    pub listen: Option<String>,
    /// Force read-only.
    #[arg(long)]
    pub read_only: bool,
    /// Override config path.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Explicit `--enable` toggle (required unless `[mcp].enabled = true`).
    #[arg(long)]
    pub enable: bool,
}

/// `spt mcp inspect`.
#[derive(Args, Debug)]
pub struct McpInspect {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt mcp policy`.
#[derive(Args, Debug)]
pub struct McpPolicy {
    /// Policy subcommand.
    #[command(subcommand)]
    pub command: McpPolicySub,
}

/// Subcommands of `spt mcp policy`.
#[derive(Subcommand, Debug)]
pub enum McpPolicySub {
    /// Show the current policy.
    Show,
    /// Update one or more policy keys.
    Set(McpPolicySet),
}

/// `spt mcp policy set`.
#[derive(Args, Debug)]
pub struct McpPolicySet {
    /// `key=value` pairs.
    #[arg(value_name = "KEY=VALUE", required = true)]
    pub overrides: Vec<String>,
}
