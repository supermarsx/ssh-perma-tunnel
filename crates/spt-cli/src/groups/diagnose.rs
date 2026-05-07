//! `spt diagnose` — targeted checks and support bundles.

use std::path::PathBuf;

use clap::{Args, Subcommand};

const EXAMPLES: &str = "EXAMPLES:
  spt diagnose run --all --report report.json
  spt diagnose port --host db --port 5432 --tcp --autodetect-service
  spt diagnose bundle --out support.tgz --redacted --since 24h
  spt diagnose service --config /etc/ssh-perma-tunnel/config.toml --system
  spt diagnose dns --name db.local";

/// `spt diagnose` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct DiagnoseCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: DiagnoseSub,
}

/// Subcommands of `spt diagnose`.
#[derive(Subcommand, Debug)]
pub enum DiagnoseSub {
    /// Run a battery of diagnostic checks.
    Run(DiagnoseRun),
    /// Network checks.
    Network(DiagnoseNetwork),
    /// Authentication checks for a profile.
    Auth(DiagnoseProfile),
    /// Trust checks for a profile.
    Trust(DiagnoseProfile),
    /// DNS checks.
    Dns(DiagnoseDns),
    /// Bind checks.
    Bind(DiagnoseBind),
    /// Probe a host:port.
    Port(DiagnosePort),
    /// Service-manager checks.
    Service(DiagnoseService),
    /// Secret-backend checks.
    Secrets(DiagnoseJson),
    /// Observability sink checks.
    Observability(DiagnoseObservability),
    /// MCP server checks.
    Mcp(DiagnoseJson),
    /// Build a redacted support bundle.
    Bundle(DiagnoseBundle),
}

/// `spt diagnose run`.
#[derive(Args, Debug)]
pub struct DiagnoseRun {
    /// Run every check.
    #[arg(long)]
    pub all: bool,
    /// Restrict to offline-only checks.
    #[arg(long, group = "diag_mode")]
    pub offline: bool,
    /// Restrict to online-only checks.
    #[arg(long, group = "diag_mode")]
    pub online: bool,
    /// Filter by profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Write a structured report.
    #[arg(long, value_name = "PATH")]
    pub report: Option<PathBuf>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt diagnose network`.
#[derive(Args, Debug)]
pub struct DiagnoseNetwork {
    /// Filter by profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Filter by endpoint.
    #[arg(long, value_name = "NAME")]
    pub endpoint: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt diagnose auth|trust <profile>`.
#[derive(Args, Debug)]
pub struct DiagnoseProfile {
    /// Profile name (omit or pass empty for "all profiles").
    #[arg(default_value = "")]
    pub profile: String,
    /// Run a live connect probe (forward-compatible; structural-only today).
    #[arg(long)]
    pub probe: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt diagnose dns`.
#[derive(Args, Debug)]
pub struct DiagnoseDns {
    /// Name to test.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt diagnose bind`.
#[derive(Args, Debug)]
pub struct DiagnoseBind {
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

/// `spt diagnose port`.
#[derive(Args, Debug)]
pub struct DiagnosePort {
    /// Target host.
    #[arg(long)]
    pub host: String,
    /// Target port.
    #[arg(long)]
    pub port: u16,
    /// TCP probe.
    #[arg(long, group = "port_proto")]
    pub tcp: bool,
    /// UDP probe.
    #[arg(long, group = "port_proto")]
    pub udp: bool,
    /// Try to identify the service.
    #[arg(long)]
    pub autodetect_service: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt diagnose service`.
#[derive(Args, Debug)]
pub struct DiagnoseService {
    /// Path to the config file.
    #[arg(long, value_name = "PATH")]
    pub config: PathBuf,
    /// User scope.
    #[arg(long, group = "diag_svc_scope")]
    pub user: bool,
    /// System scope.
    #[arg(long, group = "diag_svc_scope")]
    pub system: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// Generic `--json` only argument struct.
#[derive(Args, Debug)]
pub struct DiagnoseJson {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt diagnose observability`.
#[derive(Args, Debug)]
pub struct DiagnoseObservability {
    /// Filter by sink name.
    #[arg(long, value_name = "NAME")]
    pub sink: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt diagnose bundle`.
#[derive(Args, Debug)]
pub struct DiagnoseBundle {
    /// Output bundle path.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
    /// Redact secrets and PII.
    #[arg(long)]
    pub redacted: bool,
    /// Lookback window for events.
    #[arg(long, value_name = "DURATION")]
    pub since: Option<String>,
}
