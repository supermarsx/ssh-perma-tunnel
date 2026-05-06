//! `spt observe` — metrics, SNMP, Windows Event Log.

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt observe metrics --format prometheus
  spt observe snmp serve --foreground
  spt observe snmp test-trap --sink ops
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
#[derive(Args, Debug)]
pub struct ObserveSnmp {
    /// SNMP subcommand.
    #[command(subcommand)]
    pub command: ObserveSnmpSub,
}

/// Subcommands of `spt observe snmp`.
#[derive(Subcommand, Debug)]
pub enum ObserveSnmpSub {
    /// Run the SNMP agent.
    Serve(ObserveSnmpServe),
    /// Send a test trap to a sink.
    TestTrap(ObserveSnmpTestTrap),
}

/// `spt observe snmp serve`.
#[derive(Args, Debug)]
pub struct ObserveSnmpServe {
    /// Run in the foreground.
    #[arg(long)]
    pub foreground: bool,
}

/// `spt observe snmp test-trap`.
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
    /// Emit a test event.
    Test(ObserveWinEventSource),
}

/// Common args for `spt observe windows-event` subcommands.
#[derive(Args, Debug)]
pub struct ObserveWinEventSource {
    /// Source name.
    #[arg(long, value_name = "NAME")]
    pub source: Option<String>,
}
