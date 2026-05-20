//! `spt observe` — metrics and Windows Event Log.

use clap::{Args, Subcommand, ValueEnum};

#[cfg(feature = "snmp")]
const EXAMPLES: &str = "EXAMPLES:
  spt observe metrics --format prometheus
  spt observe snmp serve --foreground
  spt observe snmp test-trap --sink ops
  spt observe windows-event install-source --source SshPermaTunnel
  spt observe windows-event test --source SshPermaTunnel";

#[cfg(not(feature = "snmp"))]
const EXAMPLES: &str = "EXAMPLES:
  spt observe metrics --format prometheus
  spt observe windows-event install-source --source SshPermaTunnel
  spt observe windows-event test --source SshPermaTunnel";

/// `spt observe` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct ObserveCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: ObserveSub,
}

/// Subcommands of `spt observe`.
#[derive(Subcommand, Debug)]
pub enum ObserveSub {
    /// Print metrics.
    Metrics(ObserveMetrics),
    /// SNMP agent and traps.
    #[cfg(feature = "snmp")]
    Snmp(ObserveSnmp),
    /// Windows Event Log integration.
    WindowsEvent(ObserveWinEvent),
}

/// Metric output format.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum MetricsFormat {
    Prometheus,
    Json,
}

/// `spt observe metrics`.
#[derive(Args, Debug)]
pub struct ObserveMetrics {
    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub format: Option<MetricsFormat>,
}

/// `spt observe snmp`.
#[cfg(feature = "snmp")]
#[derive(Args, Debug)]
pub struct ObserveSnmp {
    /// SNMP subcommand.
    #[command(subcommand)]
    pub command: ObserveSnmpSub,
}

/// Subcommands of `spt observe snmp`.
#[cfg(feature = "snmp")]
#[derive(Subcommand, Debug)]
pub enum ObserveSnmpSub {
    /// Run the SNMP agent.
    Serve(ObserveSnmpServe),
    /// Send a test trap to a sink.
    TestTrap(ObserveSnmpTestTrap),
}

/// `spt observe snmp serve`.
#[cfg(feature = "snmp")]
#[derive(Args, Debug)]
pub struct ObserveSnmpServe {
    /// Run in the foreground.
    #[arg(long)]
    pub foreground: bool,
}

/// `spt observe snmp test-trap`.
#[cfg(feature = "snmp")]
#[derive(Args, Debug)]
pub struct ObserveSnmpTestTrap {
    /// Sink name.
    #[arg(long, value_name = "NAME")]
    pub sink: String,
}

/// `spt observe windows-event`.
#[derive(Args, Debug)]
pub struct ObserveWinEvent {
    /// Windows Event subcommand.
    #[command(subcommand)]
    pub command: ObserveWinEventSub,
}

/// Subcommands of `spt observe windows-event`.
#[derive(Subcommand, Debug)]
pub enum ObserveWinEventSub {
    /// Install a Windows Event Log source.
    InstallSource(ObserveWinEventSource),
    /// Uninstall a Windows Event Log source.
    UninstallSource(ObserveWinEventSource),
    /// Emit a test event.
    Test(ObserveWinEventTest),
}

/// Common args for `spt observe windows-event` subcommands.
#[derive(Args, Debug)]
pub struct ObserveWinEventSource {
    /// Source name.
    #[arg(long, value_name = "NAME")]
    pub source: Option<String>,
    /// Event Log channel. Defaults to `[observability.windows_event].channel`
    /// or `Application`.
    #[arg(long, value_name = "CHANNEL")]
    pub channel: Option<String>,
    /// Message table DLL or EXE for source registration.
    #[arg(long, value_name = "PATH")]
    pub message_dll: Option<std::path::PathBuf>,
}

/// `spt observe windows-event test`.
#[derive(Args, Debug)]
pub struct ObserveWinEventTest {
    /// Source name.
    #[arg(long, value_name = "NAME")]
    pub source: Option<String>,
    /// Event Log channel. Used for config/default resolution.
    #[arg(long, value_name = "CHANNEL")]
    pub channel: Option<String>,
    /// Event severity (`info`, `warning`, `error`).
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    pub level: String,
    /// Event identifier.
    #[arg(long, value_name = "ID", default_value_t = 1000)]
    pub event_id: u32,
    /// Event message.
    #[arg(long, value_name = "TEXT")]
    pub message: Option<String>,
}
