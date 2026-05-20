//! Throughput driver — push N bytes through a forward, measure goodput.

use async_trait::async_trait;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::driver::{BenchContext, BenchmarkDriver, ImpactLevel};
use crate::result::{BenchResult, MetricSet};

/// Goodput driver. `iterations` is interpreted as the number of write blocks
/// to send; total bytes = `iterations * payload_size`.
#[derive(Default, Debug)]
pub struct ThroughputDriver;

#[async_trait]
impl BenchmarkDriver for ThroughputDriver {
    fn name(&self) -> &str {
        "throughput"
    }
    fn impact(&self) -> ImpactLevel {
        ImpactLevel::Synthetic
    }
    async fn run(&self, ctx: &BenchContext) -> BenchResult {
        let total = (ctx.payload_size as u64).saturating_mul(ctx.iterations);
        let block = vec![0x5Au8; ctx.payload_size.max(1)];
        let start = Instant::now();
        let mut errors = Vec::new();
        let mut written: u64 = 0;
        let mut read_back: u64 = 0;

        let conn = (ctx.connector)();
        match conn.await {
            Ok(mut stream) => {
                let (mut reader, mut writer) = tokio::io::split(s_into(&mut stream));
                let iters = ctx.iterations;
                let write_fut = async {
                    for _ in 0..iters {
                        if let Err(e) = writer.write_all(&block).await {
                            return Err(format!("write: {e}"));
                        }
                    }
                    if let Err(e) = writer.shutdown().await {
                        return Err(format!("shutdown: {e}"));
                    }
                    Ok(iters.saturating_mul(block.len() as u64))
                };
                let read_fut = async {
                    let mut buf = vec![0u8; 64 * 1024];
                    let mut total: u64 = 0;
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(k) => total += k as u64,
                            Err(e) => return Err(format!("read: {e}")),
                        }
                    }
                    Ok(total)
                };
                match tokio::join!(write_fut, read_fut) {
                    (Ok(w_n), Ok(r_n)) => {
                        written = w_n;
                        read_back = r_n;
                    }
                    (we, re) => {
                        if let Err(e) = we {
                            errors.push(e);
                        }
                        if let Err(e) = re {
                            errors.push(e);
                        }
                    }
                }
            }
            Err(e) => errors.push(format!("connect: {e}")),
        }

        let elapsed = start.elapsed();
        let secs = elapsed.as_secs_f64().max(0.000_001);
        let bytes = read_back.max(written);
        BenchResult {
            driver: self.name().into(),
            duration_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            iterations_completed: written / (block.len() as u64).max(1),
            iterations_attempted: ctx.iterations,
            payload_size: ctx.payload_size,
            errors,
            metrics: MetricSet {
                throughput_bps: Some(bytes as f64 / secs),
                extras: [
                    ("bytes_written".into(), written as f64),
                    ("bytes_read".into(), read_back as f64),
                    ("bytes_target".into(), total as f64),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            throttles_applied: Vec::new(),
            env: ctx.env.clone(),
            started_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// We need to split a `BoxedStream`. Pin<Box<dyn AsyncStream + Send + Unpin>>
// implements AsyncRead+AsyncWrite via deref of Box, but `tokio::io::split`
// wants `AsyncRead + AsyncWrite + Sized`. We borrow it through this helper
// function which returns a `&mut` reference that itself implements both.
fn s_into(
    s: &mut crate::driver::BoxedStream,
) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + '_ {
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{BoxedStream, Connector};
    use crate::result::BenchEnv;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    fn env() -> BenchEnv {
        BenchEnv {
            os: "test".into(),
            arch: "x86_64".into(),
            spt_version: "0.0.0".into(),
            ..Default::default()
        }
    }

    /// Build a `Connector` whose stream is one end of a `tokio::io::duplex`
    /// pair. The other end runs an in-process echo task that reads everything
    /// the driver writes and writes it back, then closes when EOF is observed.
    fn echo_connector(cap: usize) -> Connector {
        Box::new(move || {
            Box::pin(async move {
                let (a, mut b) = tokio::io::duplex(cap);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match tokio::io::AsyncReadExt::read(&mut b, &mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tokio::io::AsyncWriteExt::write_all(&mut b, &buf[..n])
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = b.shutdown().await;
                });
                let boxed: BoxedStream = Box::pin(a);
                Ok(boxed)
            })
        })
    }

    /// Connector that always returns a fresh I/O error on construction.
    fn failing_connector() -> Connector {
        Box::new(|| {
            Box::pin(async move {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "boom",
                ))
            })
        })
    }

    fn ctx(connector: Connector, iters: u64, payload: usize) -> BenchContext {
        BenchContext {
            iterations: iters,
            payload_size: payload,
            max_duration: Duration::from_secs(5),
            connector,
            allow_production_impact: false,
            env: env(),
        }
    }

    #[test]
    fn name_and_impact_constant() {
        let d = ThroughputDriver;
        assert_eq!(d.name(), "throughput");
        assert_eq!(d.impact(), ImpactLevel::Synthetic);
    }

    #[tokio::test]
    async fn echo_drives_full_roundtrip() {
        let d = ThroughputDriver;
        let r = d.run(&ctx(echo_connector(64 * 1024), 4, 1024)).await;
        assert_eq!(r.driver, "throughput");
        assert!(r.errors.is_empty(), "errors = {:?}", r.errors);
        assert_eq!(r.iterations_attempted, 4);
        assert_eq!(r.iterations_completed, 4);
        assert_eq!(r.payload_size, 1024);
        // bytes_written ≈ 4*1024; bytes_read should equal bytes_written.
        let written = r
            .metrics
            .extras
            .get("bytes_written")
            .copied()
            .unwrap_or(0.0);
        let read_back = r.metrics.extras.get("bytes_read").copied().unwrap_or(0.0);
        assert!((written - 4096.0).abs() < f64::EPSILON);
        assert!((read_back - 4096.0).abs() < f64::EPSILON);
        // throughput_bps should be > 0.
        assert!(r.metrics.throughput_bps.unwrap_or(0.0) > 0.0);
        // started_at is a RFC3339 string.
        assert!(r.started_at.contains('T'));
    }

    #[tokio::test]
    async fn connect_error_recorded_in_errors_vec() {
        let d = ThroughputDriver;
        let r = d.run(&ctx(failing_connector(), 2, 64)).await;
        assert_eq!(r.iterations_completed, 0);
        assert!(!r.errors.is_empty());
        assert!(
            r.errors.iter().any(|s| s.starts_with("connect:")),
            "errors = {:?}",
            r.errors
        );
        // bytes_written remains 0.
        let w = r
            .metrics
            .extras
            .get("bytes_written")
            .copied()
            .unwrap_or(-1.0);
        assert!((w - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn zero_iterations_yields_zero_bytes_no_error() {
        let d = ThroughputDriver;
        let r = d.run(&ctx(echo_connector(8 * 1024), 0, 512)).await;
        assert!(r.errors.is_empty(), "errors = {:?}", r.errors);
        assert_eq!(r.iterations_completed, 0);
        let w = r
            .metrics
            .extras
            .get("bytes_written")
            .copied()
            .unwrap_or(-1.0);
        assert!((w - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn payload_size_one_is_safe_block_size_floor() {
        let d = ThroughputDriver;
        let r = d.run(&ctx(echo_connector(4096), 3, 0)).await;
        // payload_size=0 → block is at least 1 byte (via max(1)).
        // iterations_completed = bytes_written / max(1, block.len()) so ≥ 3.
        assert!(r.errors.is_empty(), "errors = {:?}", r.errors);
        assert!(r.iterations_completed >= 3);
        let w = r
            .metrics
            .extras
            .get("bytes_written")
            .copied()
            .unwrap_or(0.0);
        assert!(w >= 3.0);
    }

    #[tokio::test]
    async fn env_metadata_is_preserved_in_result() {
        let d = ThroughputDriver;
        let r = d.run(&ctx(echo_connector(16 * 1024), 2, 256)).await;
        assert_eq!(r.env.os, "test");
        assert_eq!(r.env.arch, "x86_64");
        assert_eq!(r.env.spt_version, "0.0.0");
    }

    #[tokio::test]
    async fn bytes_target_matches_iterations_times_payload() {
        let d = ThroughputDriver;
        let r = d.run(&ctx(echo_connector(64 * 1024), 5, 1024)).await;
        let target = r.metrics.extras.get("bytes_target").copied().unwrap_or(0.0);
        assert!((target - 5120.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn large_block_size_drives_more_bytes() {
        let d = ThroughputDriver;
        let r = d.run(&ctx(echo_connector(256 * 1024), 2, 8 * 1024)).await;
        assert!(r.errors.is_empty(), "errors = {:?}", r.errors);
        let w = r
            .metrics
            .extras
            .get("bytes_written")
            .copied()
            .unwrap_or(0.0);
        assert!((w - (2.0 * 8.0 * 1024.0)).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn duration_ms_is_recorded_and_finite() {
        let d = ThroughputDriver;
        let r = d.run(&ctx(echo_connector(16 * 1024), 2, 512)).await;
        // duration_ms is always set (u64::MAX is the fallback).
        assert!(r.duration_ms < u64::MAX);
    }
}
