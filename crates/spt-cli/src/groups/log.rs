//! `spt log` — log tailing, sink testing, export.

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt log tail --follow --profile edge --since 15m
  spt log test --sink remote-syslog
  spt log export --format jsonl --since 24h
  spt log tail --since 1h --json
  spt log export --format csv --since 7d";

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
    /// Probe a configured sink.
    Test(LogTest),
    /// Export logs to a structured format.
    Export(LogExport),
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
