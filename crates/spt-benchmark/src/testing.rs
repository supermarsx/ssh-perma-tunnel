//! Public test facilities for `spt-benchmark` (gated behind `feature = "testing"`).
//!
//! These helpers let sibling crates and downstream tests exercise benchmark
//! code paths without rebuilding the same in-process `tokio::io::duplex`
//! boilerplate, fake DNS clients, and reconnect triggers.
//!
//! Everything here is deterministic by default — no real network, no clocks
//! that depend on wall time beyond the obvious `started_at` timestamp.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::driver::{BenchContext, BoxedStream, Connector, DnsClient, ReconnectTrigger};
use crate::result::{BenchEnv, BenchResult, MetricSet, Percentiles};

// --------------------------------------------------------------------------
// Synthetic results / comparisons
// --------------------------------------------------------------------------

/// Build a fully populated [`BenchResult`] with realistic-looking percentiles.
///
/// The percentile distribution is deterministic — `count` synthetic samples
/// are generated as `1.0 + i * 0.1` ms — so test assertions can pin exact
/// values. The driver name is taken verbatim and recorded in `driver`.
///
/// ```
/// use spt_benchmark::testing::synthetic_result;
///
/// let r = synthetic_result("latency", 100);
/// assert_eq!(r.driver, "latency");
/// assert_eq!(r.iterations_completed, 100);
/// assert!(r.metrics.latency.is_some());
/// ```
#[must_use]
pub fn synthetic_result(driver: &str, count: usize) -> BenchResult {
    let mut samples: Vec<f64> = (0..count).map(|i| 1.0 + (i as f64) * 0.1).collect();
    let percentiles = Percentiles::from_samples(&mut samples);
    BenchResult {
        driver: driver.into(),
        duration_ms: (count as u64).saturating_mul(2),
        iterations_completed: count as u64,
        iterations_attempted: count as u64,
        payload_size: 64,
        errors: Vec::new(),
        metrics: MetricSet {
            latency: Some(percentiles),
            throughput_bps: Some(1_000_000.0),
            ..Default::default()
        },
        throttles_applied: Vec::new(),
        env: BenchEnv {
            os: "test".into(),
            arch: "test".into(),
            spt_version: "0.1.0".into(),
            profile: Some("p1".into()),
            forward: Some("f1".into()),
            protocol: Some("ssh2".into()),
            endpoint: Some("127.0.0.1:2222".into()),
            ..Default::default()
        },
        started_at: "2026-05-05T12:00:00Z".into(),
    }
}

/// Build a synthetic [`crate::compare::ReportComparison`] derived from two
/// [`synthetic_result`] calls — useful when a downstream test needs a populated
/// comparison without running real drivers.
///
/// ```
/// use spt_benchmark::testing::synthetic_compare;
///
/// let cmp = synthetic_compare();
/// assert_eq!(cmp.drivers.len(), 1);
/// assert!(cmp.drivers[0].metrics.iter().any(|m| m.name == "p50_ms"));
/// ```
#[must_use]
pub fn synthetic_compare() -> crate::compare::ReportComparison {
    let baseline = vec![synthetic_result("latency", 50)];
    let candidate = vec![synthetic_result("latency", 100)];
    crate::compare::compare_reports(&baseline, &candidate)
}

// --------------------------------------------------------------------------
// MockConnector
// --------------------------------------------------------------------------

/// In-process [`Connector`] backed by `tokio::io::duplex` plus a per-call
/// echo task on the far end. Each call to the connector returns a fresh,
/// fully isolated stream pair.
///
/// ```no_run
/// use spt_benchmark::testing::MockConnector;
/// let _conn = MockConnector::echo().into_connector();
/// ```
pub struct MockConnector {
    buf_size: usize,
}

impl MockConnector {
    /// Build an echo connector. Bytes written to the returned stream are
    /// echoed back on the same stream, byte-for-byte.
    #[must_use]
    pub fn echo() -> Self {
        Self {
            buf_size: 64 * 1024,
        }
    }

    /// Override the per-direction in-memory duplex buffer size. Defaults to
    /// 64 KiB which is plenty for synthetic tests.
    #[must_use]
    pub fn with_buf_size(mut self, n: usize) -> Self {
        self.buf_size = n;
        self
    }

    /// Convert into a boxed [`Connector`] callable by drivers.
    #[must_use]
    pub fn into_connector(self) -> Connector {
        let buf_size = self.buf_size;
        Box::new(move || {
            Box::pin(async move {
                let (near, far) = tokio::io::duplex(buf_size);
                tokio::spawn(async move {
                    let (mut reader, mut writer) = tokio::io::split(far);
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
                let stream: BoxedStream = Box::pin(near);
                Ok(stream)
            })
        })
    }
}

// --------------------------------------------------------------------------
// RecordingDnsClient
// --------------------------------------------------------------------------

/// A [`DnsClient`] that records every queried name and returns a canned
/// response.
///
/// ```
/// use spt_benchmark::testing::RecordingDnsClient;
/// use spt_benchmark::DnsClient;
/// use std::net::IpAddr;
///
/// # async fn run() {
/// let c = RecordingDnsClient::new(vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
/// let _ = c.query("example.com").await.unwrap();
/// assert_eq!(c.calls(), vec!["example.com".to_string()]);
/// # }
/// ```
#[derive(Debug)]
pub struct RecordingDnsClient {
    calls: Mutex<Vec<String>>,
    response: Vec<IpAddr>,
}

impl RecordingDnsClient {
    /// Build a client that returns `response` for every query.
    #[must_use]
    pub fn new(response: Vec<IpAddr>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            response,
        }
    }

    /// Snapshot of every name queried so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl DnsClient for RecordingDnsClient {
    async fn query(&self, name: &str) -> std::io::Result<Vec<String>> {
        self.calls.lock().unwrap().push(name.to_string());
        Ok(self
            .response
            .iter()
            .map(std::string::ToString::to_string)
            .collect())
    }
}

// --------------------------------------------------------------------------
// StubReconnectTrigger
// --------------------------------------------------------------------------

/// A [`ReconnectTrigger`] whose `wait_session_up` returns after a fixed delay
/// and whose `trigger_drop` is a no-op. Useful for shaping reconnect-driver
/// timing in tests.
///
/// ```
/// use spt_benchmark::testing::StubReconnectTrigger;
/// use std::time::Duration;
/// let _t = StubReconnectTrigger::new(Duration::from_millis(5));
/// ```
#[derive(Debug, Clone)]
pub struct StubReconnectTrigger {
    /// Delay applied by every call to `wait_session_up`.
    pub delay: Duration,
}

impl StubReconnectTrigger {
    /// New trigger with the given per-cycle delay.
    #[must_use]
    pub fn new(delay: Duration) -> Self {
        Self { delay }
    }
}

#[async_trait]
impl ReconnectTrigger for StubReconnectTrigger {
    async fn wait_session_up(&self) -> std::io::Result<()> {
        tokio::time::sleep(self.delay).await;
        Ok(())
    }
    async fn trigger_drop(&self) -> std::io::Result<()> {
        Ok(())
    }
}

// --------------------------------------------------------------------------
// Fixtures
// --------------------------------------------------------------------------

/// Canonical pre-built fixtures.
pub mod fixtures {
    use super::{BenchContext, BenchEnv, Duration, MockConnector};

    /// Default [`BenchContext`] suitable for in-process driver tests:
    /// 8 iterations, 64-byte payload, 5 s wall cap, [`MockConnector::echo`].
    ///
    /// ```
    /// let ctx = spt_benchmark::testing::fixtures::default_bench_context();
    /// assert_eq!(ctx.iterations, 8);
    /// ```
    #[must_use]
    pub fn default_bench_context() -> BenchContext {
        BenchContext {
            iterations: 8,
            payload_size: 64,
            max_duration: Duration::from_secs(5),
            connector: MockConnector::echo().into_connector(),
            allow_production_impact: false,
            env: BenchEnv {
                os: "test".into(),
                arch: "test".into(),
                spt_version: "0.1.0".into(),
                ..Default::default()
            },
        }
    }
}

/// Wrap a [`StubReconnectTrigger`] in an `Arc` so it can be shared across
/// tasks that hold `Arc<dyn ReconnectTrigger>`.
///
/// ```
/// use spt_benchmark::testing::{shared_trigger, StubReconnectTrigger};
/// use std::time::Duration;
/// let t = shared_trigger(StubReconnectTrigger::new(Duration::from_millis(1)));
/// assert!(std::sync::Arc::strong_count(&t) >= 1);
/// ```
#[must_use]
pub fn shared_trigger(t: StubReconnectTrigger) -> Arc<dyn ReconnectTrigger> {
    Arc::new(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::BenchmarkDriver;
    use crate::drivers::LatencyDriver;

    #[test]
    fn synthetic_result_round_trips_json() {
        let r = synthetic_result("latency", 100);
        let s = serde_json::to_string(&r).unwrap();
        let back: BenchResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn synthetic_compare_has_shared_driver() {
        let cmp = synthetic_compare();
        assert_eq!(cmp.drivers.len(), 1);
        assert_eq!(cmp.drivers[0].driver, "latency");
        assert!(cmp.baseline_only.is_empty());
        assert!(cmp.candidate_only.is_empty());
    }

    #[tokio::test]
    async fn mock_connector_drives_latency_driver() {
        let ctx = fixtures::default_bench_context();
        let res = LatencyDriver.run(&ctx).await;
        assert_eq!(res.iterations_completed, 8);
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }

    #[tokio::test]
    async fn recording_dns_records_queries() {
        let c = RecordingDnsClient::new(vec!["127.0.0.1".parse().unwrap()]);
        let r = c.query("a.test").await.unwrap();
        assert_eq!(r, vec!["127.0.0.1".to_string()]);
        let _ = c.query("b.test").await.unwrap();
        assert_eq!(c.calls(), vec!["a.test".to_string(), "b.test".to_string()]);
    }

    #[tokio::test]
    async fn stub_reconnect_trigger_returns_after_delay() {
        let t = StubReconnectTrigger::new(Duration::from_millis(1));
        t.trigger_drop().await.unwrap();
        t.wait_session_up().await.unwrap();
    }
}
