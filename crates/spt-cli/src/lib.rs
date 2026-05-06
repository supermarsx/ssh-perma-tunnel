//! Clap-derived command-line interface for `spt`.
//!
//! This crate exposes the full command tree as a `Cli` value. The binary
//! ([`spt-bin`]) is responsible for dispatching parsed commands to their
//! implementing crates; this crate intentionally contains no runtime logic
//! beyond shell-completion generation, which is trivial and lives in
//! [`groups::completion`].

#![allow(clippy::large_enum_variant)]
#![allow(clippy::doc_markdown)]

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

pub mod groups;

/// Root `spt` command.
#[derive(Parser, Debug)]
#[command(
    name = "spt",
    version,
    about = "Permanent SSH2/SSH3 tunnels with reconnect, observability, and service integration.",
    long_about = None,
    propagate_version = true,
)]
pub struct Cli {
    /// Global options that apply to every subcommand.
    #[command(flatten)]
    pub global: GlobalOpts,
    /// The selected top-level command group.
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// Parse `Cli` from the process command line, exiting on error.
    #[must_use]
    pub fn parse_args() -> Self {
        <Self as Parser>::parse()
    }
}

/// Convenience entry point used by the `spt` binary.
#[must_use]
pub fn parse() -> Cli {
    Cli::parse_args()
}

/// Output format for command results.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text (default).
    Human,
    /// Structured JSON.
    Json,
    /// JSON Lines (one record per line).
    Jsonl,
    /// YAML.
    Yaml,
}

/// Tracing log-level selector.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum LogLevel {
    /// Only errors.
    Error,
    /// Warnings and above.
    Warn,
    /// Informational and above (default).
    Info,
    /// Debug and above.
    Debug,
    /// Trace and above (very verbose).
    Trace,
}

/// Color policy for human output.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ColorMode {
    /// Auto-detect based on tty.
    Auto,
    /// Always emit color escapes.
    Always,
    /// Never emit color escapes.
    Never,
}

/// Globally-applicable flags. See spec §7.1.
#[derive(Args, Debug, Clone)]
pub struct GlobalOpts {
    /// Path to a single config file.
    #[arg(long, env = "SPT_CONFIG", global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Path to a directory of `*.toml` configs (loaded in lexical order).
    #[arg(long, global = true, value_name = "PATH")]
    pub config_dir: Option<PathBuf>,
    /// HTTPS URL of a remote config to fetch.
    #[arg(long, env = "SPT_CONFIG_URL", global = true, value_name = "URL")]
    pub config_url: Option<String>,
    /// SHA-256 fingerprint pin for `--config-url`.
    #[arg(long, global = true, value_name = "SHA256")]
    pub config_fingerprint: Option<String>,
    /// Override the runtime state directory.
    #[arg(long, env = "SPT_STATE_DIR", global = true, value_name = "PATH")]
    pub state_dir: Option<PathBuf>,
    /// Restrict operations to the named profile.
    #[arg(long, global = true, value_name = "NAME")]
    pub profile: Option<String>,
    /// Output format for command results.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,
    /// Convenience alias for `--output json`.
    #[arg(long, global = true)]
    pub json: bool,
    /// Tracing log level.
    #[arg(long, global = true, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,
    /// Color policy for human output.
    #[arg(long, global = true, value_enum, default_value_t = ColorMode::Auto)]
    pub color: ColorMode,
    /// Suppress non-essential output.
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,
    /// Increase verbosity (repeat for more).
    #[arg(long, short = 'v', action = ArgAction::Count, global = true)]
    pub verbose: u8,
    /// Disable color (legacy convenience flag; use `--color never`).
    #[arg(long, global = true)]
    pub no_color: bool,
    /// Show what would happen without making changes.
    #[arg(long, global = true)]
    pub dry_run: bool,
}

/// Top-level command groups. See spec §7.2.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Manage configuration files (init, validate, diff, render, reload).
    Config(groups::config::ConfigCmd),
    /// Manage SSH/SSH3 tunnel profiles.
    Profile(groups::profile::ProfileCmd),
    /// Manage forwards (local/remote TCP, UDP).
    Forward(groups::forward::ForwardCmd),
    /// Run, inspect, and control tunnels.
    Tunnel(groups::tunnel::TunnelCmd),
    /// Install and control native services.
    Service(groups::service::ServiceCmd),
    /// Generate, inspect, and install SSH keys.
    Key(groups::key::KeyCmd),
    /// Manage the secret vault and OS keychain references.
    Secret(groups::secret::SecretCmd),
    /// Authentication helpers.
    Auth(groups::auth::AuthCmd),
    /// Built-in DNS resolver and hosts-file management.
    Dns(groups::dns::DnsCmd),
    /// Inspect and manage OS firewall / packet-filter rules.
    Firewall(groups::firewall::FirewallCmd),
    /// Log tailing, sink testing, and export.
    Log(groups::log::LogCmd),
    /// Metrics, SNMP, and Windows Event Log helpers.
    Observe(groups::observe::ObserveCmd),
    /// Event bindings and sinks.
    Event(groups::event::EventCmd),
    /// Statistics summaries and live counters.
    Stats(groups::stats::StatsCmd),
    /// Inspect and manage active sessions.
    Session(groups::session::SessionCmd),
    /// Targeted diagnostics and support bundles.
    Diagnose(groups::diagnose::DiagnoseCmd),
    /// Controlled benchmarking against forwards.
    Benchmark(groups::benchmark::BenchmarkCmd),
    /// Built-in MCP server controls.
    Mcp(groups::mcp::McpCmd),
    /// Generate shell completions.
    Completion(groups::completion::CompletionCmd),
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_debug_assert() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_root_help() {
        let err = Cli::try_parse_from(["spt", "--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn parses_config_validate() {
        let cli = Cli::try_parse_from(["spt", "config", "validate", "--strict"]).unwrap();
        match cli.command {
            Command::Config(_) => {}
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn parses_profile_add() {
        Cli::try_parse_from([
            "spt", "profile", "add", "edge", "--protocol", "ssh2", "--host", "a.example",
            "--user", "ubuntu",
        ])
        .unwrap();
    }

    #[test]
    fn parses_forward_add_local() {
        Cli::try_parse_from([
            "spt",
            "forward",
            "add",
            "local",
            "--profile",
            "p1",
            "--listen",
            "127.0.0.1:5432",
            "--to",
            "db:5432",
            "--tcp",
        ])
        .unwrap();
    }

    #[test]
    fn parses_tunnel_run_foreground_once() {
        Cli::try_parse_from(["spt", "tunnel", "run", "--foreground", "--once"]).unwrap();
    }

    #[test]
    fn parses_service_install() {
        Cli::try_parse_from([
            "spt", "service", "install", "--config", "c.toml", "--system",
        ])
        .unwrap();
    }

    #[test]
    fn parses_key_generate_ed25519() {
        Cli::try_parse_from([
            "spt", "key", "generate", "--type", "ed25519", "--out", "id_ed25519",
        ])
        .unwrap();
    }

    #[test]
    fn parses_secret_set_prompt() {
        Cli::try_parse_from(["spt", "secret", "set", "db/password", "--prompt"]).unwrap();
    }

    #[test]
    fn parses_auth_test() {
        Cli::try_parse_from(["spt", "auth", "test", "p1"]).unwrap();
    }

    #[test]
    fn parses_dns_record_add() {
        Cli::try_parse_from([
            "spt", "dns", "record", "add", "svc.local", "--addr", "10.0.0.1", "--ttl", "5m",
        ])
        .unwrap();
    }

    #[test]
    fn parses_firewall_apply() {
        Cli::try_parse_from(["spt", "firewall", "apply", "--system", "--dry-run"]).unwrap();
    }

    #[test]
    fn parses_log_tail_follow() {
        Cli::try_parse_from(["spt", "log", "tail", "--follow", "--since", "1h"]).unwrap();
    }

    #[test]
    fn parses_observe_metrics() {
        Cli::try_parse_from(["spt", "observe", "metrics", "--format", "prometheus"]).unwrap();
    }

    #[test]
    fn parses_event_replay() {
        Cli::try_parse_from([
            "spt", "event", "replay", "--since", "10m", "--binding", "ops",
        ])
        .unwrap();
    }

    #[test]
    fn parses_stats_summary() {
        Cli::try_parse_from(["spt", "stats", "summary", "--profile", "p1", "--json"]).unwrap();
    }

    #[test]
    fn parses_session_close() {
        Cli::try_parse_from([
            "spt", "session", "close", "abc123", "--grace", "5s", "--reason", "drain",
        ])
        .unwrap();
    }

    #[test]
    fn parses_diagnose_port() {
        Cli::try_parse_from([
            "spt",
            "diagnose",
            "port",
            "--host",
            "h",
            "--port",
            "443",
            "--tcp",
            "--autodetect-service",
        ])
        .unwrap();
    }

    #[test]
    fn parses_benchmark_run() {
        Cli::try_parse_from([
            "spt",
            "benchmark",
            "run",
            "--profile",
            "p1",
            "--forward",
            "f1",
            "--duration",
            "30s",
        ])
        .unwrap();
    }

    #[test]
    fn parses_mcp_serve() {
        Cli::try_parse_from(["spt", "mcp", "serve", "--stdio", "--read-only", "--enable"])
            .unwrap();
    }

    #[test]
    fn parses_completion_generate() {
        Cli::try_parse_from(["spt", "completion", "generate", "bash"]).unwrap();
    }
}
