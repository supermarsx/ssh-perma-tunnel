//! `spt log` — log tailing, sink testing, export.

use clap::{Args, Subcommand, ValueEnum};

pub(crate) const EXAMPLES: &str = "EXAMPLES:
  spt log tail --follow --profile edge --since 15m
  spt log test --sink remote-syslog
  spt log remote list
  spt log remote test --sink remote-syslog --send-test-record
  spt log export --format jsonl --since 24h
  spt log tail --since 1h --json
  spt log export --format jsonl --since 7d";

/// `spt log` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct LogCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: LogSub,
}

/// Subcommands of `spt log`.
#[derive(Subcommand, Debug)]
pub enum LogSub {
    /// Tail logs.
    Tail(LogTail),
    /// Manage configured remote log sinks.
    Remote(LogRemote),
    /// Probe a configured sink.
    Test(LogTest),
    /// Export logs to a structured format.
    Export(LogExport),
}

/// `spt log remote`.
#[derive(Args, Debug)]
pub struct LogRemote {
    /// Subcommand.
    #[command(subcommand)]
    pub command: LogRemoteSub,
}

/// Remote-log subcommands.
#[derive(Subcommand, Debug)]
pub enum LogRemoteSub {
    /// List configured remote log sinks.
    List(LogRemoteList),
    /// Probe a configured remote log sink.
    Test(LogRemoteTest),
    /// Show local delivery status for a remote log sink.
    Status(LogRemoteStatus),
    /// Drain a remote log sink's disk spool.
    Drain(LogRemoteDrain),
}

/// `spt log remote list`.
#[derive(Args, Debug)]
pub struct LogRemoteList {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt log remote test`.
#[derive(Args, Debug)]
pub struct LogRemoteTest {
    /// Sink name.
    #[arg(long, value_name = "NAME")]
    pub sink: String,
    /// Send a real synthetic record instead of only probing reachability.
    #[arg(long)]
    pub send_test_record: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt log remote status`.
#[derive(Args, Debug)]
pub struct LogRemoteStatus {
    /// Sink name.
    #[arg(long, value_name = "NAME")]
    pub sink: String,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt log remote drain`.
#[derive(Args, Debug)]
pub struct LogRemoteDrain {
    /// Sink name.
    #[arg(long, value_name = "NAME")]
    pub sink: String,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt log tail`.
#[derive(Args, Debug)]
pub struct LogTail {
    /// Follow mode.
    #[arg(long)]
    pub follow: bool,
    /// Filter by profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Lookback window (e.g. `1h`).
    #[arg(long, value_name = "DURATION")]
    pub since: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt log test`.
#[derive(Args, Debug)]
pub struct LogTest {
    /// Sink name.
    #[arg(long, value_name = "NAME")]
    pub sink: String,
}

/// Export format for `spt log export`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum LogExportFormat {
    Jsonl,
    Csv,
}

/// `spt log export`.
#[derive(Args, Debug)]
pub struct LogExport {
    /// Output format.
    #[arg(long, value_enum)]
    pub format: LogExportFormat,
    /// Lookback window.
    #[arg(long, value_name = "DURATION")]
    pub since: String,
}
