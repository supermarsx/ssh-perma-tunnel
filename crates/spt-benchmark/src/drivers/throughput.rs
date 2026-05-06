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
