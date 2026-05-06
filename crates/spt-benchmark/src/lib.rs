//! Benchmark drivers and result schemas for spt.
//!
//! Implements spec §13.13: structured benchmark drivers with safety gating,
//! a stable result schema, and JSON / JSONL / CSV / Markdown export +
//! baseline-vs-candidate comparison.
//!
//! # Layout
//! - [`driver`]  — [`BenchmarkDriver`] trait + [`BenchContext`].
//! - [`drivers`] — concrete drivers (latency, throughput) plus stub drivers
//!                 for the rest (UDP / reconnect / DNS / limits) marked
//!                 unimplemented until t1-e18 wires real protocol crates.
//! - [`result`]  — [`BenchResult`] + serialisation.
//! - [`safety`]  — production-impact gating.
//! - [`compare`] — load two reports → side-by-side diff.
//! - [`report`]  — write a report into `<state_dir>/benchmarks/<id>.{json,md}`.
//!
//! Drivers abstract over the connector: they accept a [`Connector`] closure
//! that produces an `AsyncRead+AsyncWrite` stream, so tests can use
//! `tokio::io::duplex` and production wires real tunnel forwards.

#![deny(missing_docs)]

pub mod compare;
pub mod driver;
pub mod drivers;
pub mod report;
pub mod result;
pub mod safety;

pub use compare::{compare_reports, ComparedMetric, ReportComparison};
pub use driver::{BenchContext, BenchmarkDriver, Connector};
pub use drivers::{LatencyDriver, ThroughputDriver};
pub use report::{write_report, ReportFormat};
pub use result::{BenchEnv, BenchResult, MetricSet, Percentiles};
pub use safety::{check_safety, SafetyError};
