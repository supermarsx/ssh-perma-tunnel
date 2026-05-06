//! `spt benchmark` — controlled benchmarks against forwards.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt benchmark run --profile edge --forward db --duration 30s --connections 16
  spt benchmark latency --profile edge --forward db --samples 1000
  spt benchmark throughput --profile edge --forward db --duration 60s --payload-size 64KiB
  spt benchmark report compare --baseline base.json --candidate cand.json
  spt benchmark report export --format markdown --out report.md";

/// `spt benchmark` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct BenchmarkCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: BenchmarkSub,
}

/// Subcommands of `spt benchmark`.
#[derive(Subcommand, Debug)]
pub enum BenchmarkSub {
    /// End-to-end mixed workload.
    Run(BenchmarkRun),
    /// Latency-focused benchmark.
    Latency(BenchmarkLatency),
    /// Throughput-focused benchmark.
    Throughput(BenchmarkThroughput),
    /// UDP benchmark (SSH3 only).
    Udp(BenchmarkUdp),
    /// Reconnect benchmark.
    Reconnect(BenchmarkReconnect),
    /// DNS benchmark.
    Dns(BenchmarkDns),
    /// Limit/throttle introspection.
    Limits(BenchmarkLimits),
    /// Report tooling.
    Report(BenchmarkReport),
}

/// Common forward target.
#[derive(Args, Debug, Clone)]
pub struct BenchmarkTarget {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Forward name.
    #[arg(long)]
    pub forward: String,
}

/// `spt benchmark run`.
#[derive(Args, Debug)]
pub struct BenchmarkRun {
    /// Driver to dispatch (one of `latency`, `throughput`, `udp`,
    /// `reconnect`, `dns`, `limits`).
    #[arg(long, value_name = "NAME")]
    pub driver: String,
    /// Forward target (optional for synthetic drivers like `dns`).
    #[command(flatten)]
    pub target: BenchmarkRunTarget,
    /// Duration.
    #[arg(long, value_name = "DURATION")]
    pub duration: Option<String>,
    /// Concurrent connections.
    #[arg(long, value_name = "N")]
    pub connections: Option<u32>,
    /// Iteration / sample count override.
    #[arg(long, value_name = "N")]
    pub count: Option<u32>,
    /// Allow drivers that may impact production. Combined with the
    /// `[benchmark.allow_production_impact]` config flag.
    #[arg(long)]
    pub unsafe_allow_production_impact: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// Optional forward target (subset of `BenchmarkTarget`, both flags optional).
#[derive(Args, Debug, Clone)]
pub struct BenchmarkRunTarget {
    /// Profile name.
    #[arg(long)]
    pub profile: Option<String>,
    /// Forward name.
    #[arg(long)]
    pub forward: Option<String>,
}

/// `spt benchmark latency`.
#[derive(Args, Debug)]
pub struct BenchmarkLatency {
    /// Forward target.
    #[command(flatten)]
    pub target: BenchmarkTarget,
    /// Sample count.
    #[arg(long, value_name = "N")]
    pub samples: Option<u32>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt benchmark throughput`.
#[derive(Args, Debug)]
pub struct BenchmarkThroughput {
    /// Forward target.
    #[command(flatten)]
    pub target: BenchmarkTarget,
    /// Duration.
    #[arg(long, value_name = "DURATION")]
    pub duration: Option<String>,
    /// Payload size.
    #[arg(long, value_name = "SIZE")]
    pub payload_size: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt benchmark udp`.
#[derive(Args, Debug)]
pub struct BenchmarkUdp {
    /// Forward target.
    #[command(flatten)]
    pub target: BenchmarkTarget,
    /// Duration.
    #[arg(long, value_name = "DURATION")]
    pub duration: Option<String>,
    /// Datagram size.
    #[arg(long, value_name = "SIZE")]
    pub packet_size: Option<String>,
    /// Packets per second.
    #[arg(long, value_name = "N")]
    pub pps: Option<u32>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt benchmark reconnect`.
#[derive(Args, Debug)]
pub struct BenchmarkReconnect {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Iteration count.
    #[arg(long, value_name = "N")]
    pub iterations: Option<u32>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt benchmark dns`.
#[derive(Args, Debug)]
pub struct BenchmarkDns {
    /// Name to resolve.
    #[arg(long, value_name = "NAME")]
    pub name: String,
    /// Sample count.
    #[arg(long, value_name = "N")]
    pub samples: Option<u32>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt benchmark limits`.
#[derive(Args, Debug)]
pub struct BenchmarkLimits {
    /// Forward target.
    #[command(flatten)]
    pub target: BenchmarkTarget,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt benchmark report`.
#[derive(Args, Debug)]
pub struct BenchmarkReport {
    /// Report subcommand.
    #[command(subcommand)]
    pub command: BenchmarkReportSub,
}

/// Subcommands of `spt benchmark report`.
#[derive(Subcommand, Debug)]
pub enum BenchmarkReportSub {
    /// Compare two benchmark results.
    Compare(BenchmarkReportCompare),
    /// Export a benchmark result.
    Export(BenchmarkReportExport),
}

/// `spt benchmark report compare`.
#[derive(Args, Debug)]
pub struct BenchmarkReportCompare {
    /// Baseline result file.
    #[arg(long, value_name = "PATH")]
    pub baseline: PathBuf,
    /// Candidate result file.
    #[arg(long, value_name = "PATH")]
    pub candidate: PathBuf,
}

/// Report export format.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum BenchmarkReportFormat {
    Json,
    Jsonl,
    Csv,
    Markdown,
}

/// `spt benchmark report export`.
#[derive(Args, Debug)]
pub struct BenchmarkReportExport {
    /// Output format.
    #[arg(long, value_enum)]
    pub format: BenchmarkReportFormat,
    /// Output path.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
}
