//! `spt stats` — statistics summaries and live counters.

use clap::{Args, Subcommand, ValueEnum};

/// `spt stats` group.
#[derive(Args, Debug)]
pub struct StatsCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: StatsSub,
}

/// Subcommands of `spt stats`.
#[derive(Subcommand, Debug)]
pub enum StatsSub {
    /// Snapshot summary.
    Summary(StatsFilter),
    /// Live updating view.
    Live(StatsLive),
    /// Connection table.
    Connections(StatsFilter),
    /// Throughput windows.
    Throughput(StatsThroughput),
    /// Recent errors.
    Errors(StatsErrors),
    /// Export stats to a file.
    Export(StatsExport),
}

/// Common profile/forward filter.
#[derive(Args, Debug, Clone)]
pub struct StatsFilter {
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

/// `spt stats live`.
#[derive(Args, Debug)]
pub struct StatsLive {
    /// Refresh interval.
    #[arg(long, value_name = "DURATION")]
    pub interval: Option<String>,
    /// Filter by profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Filter by forward.
    #[arg(long)]
    pub forward: Option<String>,
}

/// `spt stats throughput`.
#[derive(Args, Debug)]
pub struct StatsThroughput {
    /// Filter by profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Filter by forward.
    #[arg(long)]
    pub forward: Option<String>,
    /// Window size.
    #[arg(long, value_name = "DURATION")]
    pub window: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt stats errors`.
#[derive(Args, Debug)]
pub struct StatsErrors {
    /// Lookback window.
    #[arg(long, value_name = "DURATION")]
    pub since: Option<String>,
    /// Filter by profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// Export format for `spt stats export`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum StatsExportFormat {
    Json,
    Jsonl,
    Csv,
    Prometheus,
}

/// `spt stats export`.
#[derive(Args, Debug)]
pub struct StatsExport {
    /// Output format.
    #[arg(long, value_enum)]
    pub format: StatsExportFormat,
    /// Lookback window.
    #[arg(long, value_name = "DURATION")]
    pub since: String,
}
