//! Latency driver — measures round-trip time over a forward.
//!
//! Each iteration: dial via the [`Connector`], send a small payload, expect
//! the same payload echoed back, record the elapsed time. The driver assumes
//! the far end echoes (a typical loopback echo or a `tcp echo` test fixture).

use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::driver::{BenchContext, BenchmarkDriver, ImpactLevel};
use crate::result::{BenchResult, MetricSet, Percentiles};

/// Round-trip latency driver.
#[derive(Default, Debug)]
pub struct LatencyDriver;

#[async_trait]
impl BenchmarkDriver for LatencyDriver {
    fn name(&self) -> &str {
        "latency"
    }
    fn impact(&self) -> ImpactLevel {
        ImpactLevel::Synthetic
    }
    async fn run(&self, ctx: &BenchContext) -> BenchResult {
        let mut samples = Vec::with_capacity(ctx.iterations as usize);
        let mut errors = Vec::new();
        let start = Instant::now();
        let payload = vec![0xA5u8; ctx.payload_size.max(1)];
        let mut completed = 0u64;
        let mut attempted = 0u64;

        for _ in 0..ctx.iterations {
            if start.elapsed() >= ctx.max_duration {
                break;
            }
            attempted += 1;
            let conn = (ctx.connector)();
            match conn.await {
                Ok(mut s) => {
                    let t0 = Instant::now();
                    if let Err(e) = s.write_all(&payload).await {
                        errors.push(format!("write: {e}"));
                        continue;
                    }
                    let mut buf = vec![0u8; payload.len()];
                    match s.read_exact(&mut buf).await {
                        Ok(_n) => {
                            let elapsed = t0.elapsed();
                            samples.push(duration_ms(elapsed));
                            completed += 1;
                        }
                        Err(e) => errors.push(format!("read: {e}")),
                    }
                    let _ = s.shutdown().await;
                }
                Err(e) => errors.push(format!("connect: {e}")),
            }
        }

        let percentiles = Percentiles::from_samples(&mut samples);
        BenchResult {
            driver: self.name().into(),
            duration_ms: duration_ms_u64(start.elapsed()),
            iterations_completed: completed,
            iterations_attempted: attempted,
            payload_size: ctx.payload_size,
            errors,
            metrics: MetricSet {
                latency: Some(percentiles),
                ..Default::default()
            },
            throttles_applied: Vec::new(),
            env: ctx.env.clone(),
            started_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

fn duration_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
fn duration_ms_u64(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{BenchContext, BoxedStream, Connector};
    use crate::result::BenchEnv;

    fn echo_connector() -> Connector {
        Box::new(|| {
            Box::pin(async {
                // tokio::io::duplex returns (a, b). We hand `a` to the driver
                // and use `b` to echo bytes back.
                let (a, b) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let (mut r, mut w) = tokio::io::split(b);
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
                let s: BoxedStream = Box::pin(a);
                Ok(s)
            })
        })
    }

    #[tokio::test]
    async fn latency_runs_against_duplex_echo() {
        let ctx = BenchContext {
            iterations: 10,
            payload_size: 32,
            max_duration: Duration::from_secs(5),
            connector: echo_connector(),
            allow_production_impact: false,
            env: BenchEnv {
                os: "test".into(),
                arch: "test".into(),
                spt_version: "0.1.0".into(),
                ..Default::default()
            },
        };
        let res = LatencyDriver.run(&ctx).await;
        assert_eq!(res.iterations_completed, 10, "{res:?}");
        let p = res.metrics.latency.as_ref().unwrap();
        assert!(p.max_ms >= 0.0);
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }
}
