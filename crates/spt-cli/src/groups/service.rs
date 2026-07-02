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

/// Restart policy for the generated unit (maps to `spt_service::RestartPolicy`).
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum RestartPolicyArg {
    /// Always restart on exit.
    Always,
    /// Restart only on non-zero exit (default).
    OnFailure,
    /// Never restart automatically.
    Never,
}

/// Unit-shaping options threaded into the generated service unit at install /
/// render time. Without these the installed unit would run as root with an
/// empty environment and `Type=simple` regardless of intent.
///
/// Consumed only by `install` and `render`; ignored by the lifecycle verbs.
#[derive(Args, Debug, Default, Clone)]
pub struct ServiceUnitOpts {
    /// Run the service as this user (system scope). Maps to systemd `User=` /
    /// OpenRC `command_user` / launchd `UserName` / SysV `DAEMON_USER`.
    #[arg(long = "run-as-user", value_name = "USER")]
    pub run_as_user: Option<String>,
    /// Run the service as this group (system scope). Maps to systemd `Group=`.
    #[arg(long = "run-as-group", value_name = "GROUP")]
    pub run_as_group: Option<String>,
    /// Restart policy for the generated unit.
    #[arg(long = "restart", value_enum, value_name = "POLICY")]
    pub restart: Option<RestartPolicyArg>,
    /// Enable systemd `Type=notify` (the daemon sends READY=1/STOPPING=1).
    #[arg(long = "sd-notify")]
    pub sd_notify: bool,
    /// systemd `WatchdogSec=` interval in seconds. `0` disables the watchdog;
    /// omitted uses a sane default.
    #[arg(long = "watchdog-sec", value_name = "SECONDS")]
    pub watchdog_sec: Option<u64>,
    /// Redirect service stdout to this path (launchd / SysV).
    #[arg(long = "stdout", value_name = "PATH")]
    pub stdout_path: Option<PathBuf>,
    /// Redirect service stderr to this path (launchd / SysV).
    #[arg(long = "stderr", value_name = "PATH")]
    pub stderr_path: Option<PathBuf>,
    /// Extra environment variable `KEY=VALUE` (repeatable).
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,
    /// Override the unit description.
    #[arg(long = "description", value_name = "TEXT")]
    pub description: Option<String>,
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
    /// Unit-shaping options (honored by `install`; ignored by other verbs).
    #[command(flatten)]
    pub unit: ServiceUnitOpts,
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
    /// Unit-shaping options (same as `install`, so `render` previews the real
    /// unit).
    #[command(flatten)]
    pub unit: ServiceUnitOpts,
    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub format: Option<RenderFormat>,
}
