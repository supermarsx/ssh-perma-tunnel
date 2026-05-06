//! `spt service` — install/control native services.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt service install --config /etc/ssh-perma-tunnel/config.toml --system
  spt service start --config /etc/ssh-perma-tunnel/config.toml --system
  spt service status --config /etc/ssh-perma-tunnel/config.toml --json
  spt service render --config config.toml --format unit
  spt service uninstall --config config.toml --user";

/// `spt service` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct ServiceCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: ServiceSub,
}

/// Subcommands of `spt service`.
#[derive(Subcommand, Debug)]
pub enum ServiceSub {
    /// Install a service for a config file.
    Install(ServiceArgs),
    /// Uninstall a service.
    Uninstall(ServiceArgs),
    /// Start a service.
    Start(ServiceArgs),
    /// Stop a service.
    Stop(ServiceArgs),
    /// Restart a service.
    Restart(ServiceArgs),
    /// Show service status.
    Status(ServiceStatus),
    /// Render the would-be service unit.
    Render(ServiceRender),
}

/// Common scope flags for service operations.
#[derive(Args, Debug, Clone)]
pub struct ServiceScope {
    /// User-scoped service.
    #[arg(long, group = "svc_scope")]
    pub user: bool,
    /// System-scoped service.
    #[arg(long, group = "svc_scope")]
    pub system: bool,
    /// Override the service unit name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
}

/// Args for install/uninstall/start/stop/restart.
#[derive(Args, Debug)]
pub struct ServiceArgs {
    /// Path to the config file backing the service.
    #[arg(long, value_name = "PATH")]
    pub config: PathBuf,
    /// Scope flags.
    #[command(flatten)]
    pub scope: ServiceScope,
}

/// `spt service status`.
#[derive(Args, Debug)]
pub struct ServiceStatus {
    /// Path to the config file.
    #[arg(long, value_name = "PATH")]
    pub config: PathBuf,
    /// Scope flags.
    #[command(flatten)]
    pub scope: ServiceScope,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// Render formats for `spt service render`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum RenderFormat {
    /// systemd / OpenRC / SysV unit.
    Unit,
    /// macOS launchd plist.
    Plist,
    /// Windows service definition.
    Windows,
}

/// `spt service render`.
#[derive(Args, Debug)]
pub struct ServiceRender {
    /// Path to the config file.
    #[arg(long, value_name = "PATH")]
    pub config: PathBuf,
    /// Scope flags.
    #[command(flatten)]
    pub scope: ServiceScope,
    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub format: Option<RenderFormat>,
}
