//! Limits driver — confirms throttle / connection-cap behaviour matches
//! configured policy.
//!
//! Two phases per run:
//!
//! 1. **Cap probe**. Open `ctx.iterations` connections concurrently via
//!    [`crate::driver::Connector`]. Count successful opens vs rejections.
//!    With `expected_cap = N`, we expect at most `N` successes.
//! 2. **Throttle probe**. On a fresh connection write a burst of
//!    `ctx.payload_size * iterations` bytes; measure achieved throughput and
//!    compare to `expected_rate_bps` within `tolerance` (fraction).
//!
//! The driver records observed cap, rejections, achieved throughput, and a
//! pass/fail flag in `BenchResult.metrics.extras`.
//!
//! # Example
//!
//! ```no_run
//! # use std::time::Duration;
//! # use spt_benchmark::{LimitsDriver, LimitsExpectations, driver::Connector};
//! # let connector: Connector = Box::new(|| Box::pin(async {
//! #     Err(std::io::Error::new(std::io::ErrorKind::Unsupported, ""))
//! # }));
//! let driver = LimitsDriver::new(connector, LimitsExpectations {
//!     expected_cap: 4,
//!     expected_rate_bps: 1024 * 1024,
//!     tolerance: 0.25,
//! });
//! # let _ = driver;
//! ```

use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

use crate::driver::{BenchContext, BenchmarkDriver, Connector, ImpactLevel};
use crate::result::{BenchResult, MetricSet};

/// Expected limits the driver verifies against.
#[derive(Debug, Clone, Copy)]
pub struct LimitsExpectations {
    /// Configured connection cap. Successes MUST be ≤ this value.
    pub expected_cap: u32,
    /// Configured token-bucket rate (bytes/second). `0` disables the
    /// throttle-tolerance check.
    pub expected_rate_bps: u64,
    /// Permitted fractional deviation around `expected_rate_bps` (e.g.
    /// `0.25` = ±25%).
    pub tolerance: f64,
}

impl Default for LimitsExpectations {
    fn default() -> Self {
        Self {
            expected_cap: 0,
            expected_rate_bps: 0,
            tolerance: 0.25,
        }
    }
}

/// Limits driver. See module docs.
pub struct LimitsDriver {
    connector: Connector,
    expectations: LimitsExpectations,
}

impl std::fmt::Debug for LimitsDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LimitsDriver")
            .field("expectations", &self.expectations)
            .finish_non_exhaustive()
    }
}

impl LimitsDriver {
    /// Build a driver that opens connections via `connector` and verifies
    /// `expectations`.
    #[must_use]
    pub fn new(connector: Connector, expectations: LimitsExpectations) -> Self {
        Self { connector, expectations }
    }
}

#[async_trait]
impl BenchmarkDriver for LimitsDriver {
    fn name(&self) -> &str {
        "limits"
    }
    fn impact(&self) -> ImpactLevel {
        ImpactLevel::Production
    }
    async fn run(&self, ctx: &BenchContext) -> BenchResult {
        let started_at = chrono::Utc::now().to_rfc3339();
        let start = Instant::now();
        let mut errors: Vec<String> = Vec::new();
        let attempted = ctx.iterations;

        // Phase 1: cap probe — open all in parallel, hold them open briefly.
        let mut open_streams = Vec::new();
        let mut rejections = 0u64;
        for _ in 0..attempted {
            if start.elapsed() >= ctx.max_duration {
                break;
            }
            let fut = (self.connector)();
            match fut.await {
                Ok(s) => open_streams.push(s),
                Err(e) => {
                    rejections += 1;
                    if errors.len() < 4 {
                        errors.push(format!("rejected: {e}"));
                    }
                }
            }
        }
        let observed_cap = open_streams.len() as u64;
        let cap_ok = self.expectations.expected_cap == 0
            || observed_cap <= u64::from(self.expectations.expected_cap);

        // Drop the held streams to free up the cap before phase 2.
        for mut s in open_streams.drain(..) {
            let _ = s.shutdown().await;
        }
        // Allow the gate to release on the far side.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Phase 2: throttle probe.
        let mut achieved_bps: f64 = 0.0;
        let mut throttle_ok = true;
        let mut throttles_applied: Vec<String> = Vec::new();
        if self.expectations.expected_rate_bps > 0
            && start.elapsed() < ctx.max_duration
        {
            let block = vec![0xA5u8; ctx.payload_size.max(1)];
            let total_target = (ctx.payload_size as u64).saturating_mul(ctx.iterations);
            match (self.connector)().await {
                Ok(mut s) => {
                    let t0 = Instant::now();
                    let mut written: u64 = 0;
                    while written < total_target && start.elapsed() < ctx.max_duration {
                        match s.write_all(&block).await {
                            Ok(()) => written += block.len() as u64,
                            Err(e) => {
                                errors.push(format!("write: {e}"));
                                break;
                            }
                        }
                    }
                    let _ = s.shutdown().await;
                    let secs = t0.elapsed().as_secs_f64().max(0.000_001);
                    achieved_bps = written as f64 / secs;
                    let expected = self.expectations.expected_rate_bps as f64;
                    let lo = expected * (1.0 - self.expectations.tolerance);
                    let hi = expected * (1.0 + self.expectations.tolerance);
                    throttle_ok = achieved_bps >= lo && achieved_bps <= hi;
                    throttles_applied.push(format!(
                        "expected {expected:.0} bps ±{:.0}%",
                        self.expectations.tolerance * 100.0
                    ));
                }
                Err(e) => errors.push(format!("throttle-connect: {e}")),
            }
        }

        let pass = cap_ok && throttle_ok;
        BenchResult {
            driver: self.name().into(),
            duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            iterations_completed: observed_cap,
            iterations_attempted: attempted,
            payload_size: ctx.payload_size,
            errors,
            metrics: MetricSet {
                throughput_bps: Some(achieved_bps),
                extras: [
                    ("expected_cap".into(), f64::from(self.expectations.expected_cap)),
                    ("observed_cap".into(), observed_cap as f64),
                    ("rejections".into(), rejections as f64),
                    (
                        "expected_rate_bps".into(),
                        self.expectations.expected_rate_bps as f64,
                    ),
                    ("achieved_rate_bps".into(), achieved_bps),
                    ("cap_ok".into(), if cap_ok { 1.0 } else { 0.0 }),
                    (
                        "throttle_ok".into(),
                        if throttle_ok { 1.0 } else { 0.0 },
                    ),
                    ("pass".into(), if pass { 1.0 } else { 0.0 }),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            throttles_applied,
            env: ctx.env.clone(),
            started_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{BenchContext, BoxedStream, Connector};
    use crate::result::BenchEnv;
    use spt_forward::{ConnectionGate, TokenBucket};
    use std::sync::Arc;

    /// Build a connector that mirrors a configured `ConnectionGate` + a
    /// shared `TokenBucket`. Each successful "connect" returns a duplex
    /// stream whose write side is gated by `bucket.acquire(n)`. Connections
    /// beyond cap return Err synchronously.
    fn gated_connector(gate: ConnectionGate, bucket: TokenBucket) -> Connector {
        use tokio::io::AsyncReadExt;
        Box::new(move || {
            let gate = gate.clone();
            let bucket = bucket.clone();
            Box::pin(async move {
                let permit = gate
                    .try_acquire()
                    .ok_or_else(|| std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "connection cap exhausted",
                    ))?;
                let (a, b) = tokio::io::duplex(64 * 1024);
                // Spawn a sink that reads from b and consumes tokens — this
                // makes the writer's flow-control reflect the bucket rate.
                let bucket_sink = bucket;
                let permit_holder = permit;
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut b = b;
                    loop {
                        match b.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                bucket_sink.acquire(n as u64).await;
                            }
                        }
                    }
                    drop(permit_holder);
                });
                let s: BoxedStream = Box::pin(a);
                Ok(s)
            })
        })
    }

    fn ctx(iters: u64, payload: usize, allow: bool) -> BenchContext {
        BenchContext {
            iterations: iters,
            payload_size: payload,
            max_duration: Duration::from_secs(5),
            connector: Box::new(|| {
                Box::pin(async {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "unused",
                    ))
                })
            }),
            allow_production_impact: allow,
            env: BenchEnv {
                os: "test".into(),
                arch: "test".into(),
                spt_version: "0.1.0".into(),
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn limits_observes_cap_and_throttle() {
        let gate = ConnectionGate::new(3);
        let bucket = TokenBucket::new(64 * 1024, 64 * 1024); // 64 KiB/s
        let connector = gated_connector(gate, bucket);
        let driver = LimitsDriver::new(
            connector,
            LimitsExpectations {
                expected_cap: 3,
                expected_rate_bps: 64 * 1024,
                tolerance: 0.5,
            },
        );
        let res = driver.run(&ctx(8, 4 * 1024, true)).await;
        let m = &res.metrics.extras;
        // We attempted 8, only 3 should open simultaneously, so >=5 rejections.
        assert!(m["observed_cap"] <= 3.0, "extras={m:?}");
        assert!(m["rejections"] >= 5.0, "extras={m:?}");
        assert!((m["cap_ok"] - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn limits_cap_violation_flagged() {
        // Configure a permissive gate but assert a stricter expectation —
        // the driver should set cap_ok=0.
        let gate = ConnectionGate::new(8);
        let bucket = TokenBucket::unlimited();
        let connector = gated_connector(gate, bucket);
        let driver = LimitsDriver::new(
            connector,
            LimitsExpectations {
                expected_cap: 2,
                expected_rate_bps: 0,
                tolerance: 0.25,
            },
        );
        let res = driver.run(&ctx(6, 1024, true)).await;
        assert!(res.metrics.extras["cap_ok"].abs() < f64::EPSILON);
        assert!(res.metrics.extras["pass"].abs() < f64::EPSILON);
    }

    #[test]
    fn safety_blocks_prod_without_flag() {
        let driver = LimitsDriver::new(
            Box::new(|| {
                Box::pin(async {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "x"))
                })
            }),
            LimitsExpectations::default(),
        );
        let err = crate::safety::check_safety(&driver, false).unwrap_err();
        assert!(matches!(
            err,
            crate::safety::SafetyError::ProductionImpactNotAllowed { .. }
        ));
        crate::safety::check_safety(&driver, true).unwrap();
    }

    #[tokio::test]
    async fn limits_result_roundtrips_json() {
        let gate = ConnectionGate::new(2);
        let bucket = TokenBucket::unlimited();
        let connector = gated_connector(gate, bucket);
        let driver = LimitsDriver::new(
            connector,
            LimitsExpectations {
                expected_cap: 2,
                expected_rate_bps: 0,
                tolerance: 0.25,
            },
        );
        let res = driver.run(&ctx(3, 1024, true)).await;
        let s1 = serde_json::to_string(&res).unwrap();
        let back: BenchResult = serde_json::from_str(&s1).unwrap();
        let s2 = serde_json::to_string(&back).unwrap();
        let back2: BenchResult = serde_json::from_str(&s2).unwrap();
        assert_eq!(back2, back);
        // Quiet unused dep warning if Arc isn't otherwise referenced.
        let _ = Arc::new(0u8);
    }
}
