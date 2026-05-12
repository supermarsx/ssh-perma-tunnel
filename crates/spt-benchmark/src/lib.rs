//! Benchmark drivers and result schemas for spt.
//!
//! Implements spec §13.13: structured benchmark drivers with safety gating,
//! a stable result schema, and JSON / JSONL / CSV / Markdown export +
//! baseline-vs-candidate comparison.
//!
//! # Layout
//! - [`driver`]  — [`BenchmarkDriver`] trait + [`BenchContext`].
//! - [`drivers`] — concrete drivers: latency, throughput, UDP loss/jitter,
//!                 reconnect time, DNS query rate, and limits enforcement.
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

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use compare::{compare_reports, ComparedMetric, ReportComparison};
pub use driver::{
    BenchContext, BenchmarkDriver, Connector, DnsClient, ReconnectTrigger, UdpConnector,
    UdpEndpoint,
};
pub use drivers::limits::LimitsExpectations;
pub use drivers::{
    DnsDriver, LatencyDriver, LimitsDriver, ReconnectDriver, ThroughputDriver, UdpDriver,
};
pub use report::{write_report, ReportFormat};
pub use result::{BenchEnv, BenchResult, MetricSet, Percentiles};
pub use safety::{check_safety, SafetyError};
