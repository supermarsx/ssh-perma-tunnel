//! Reconnect driver — measures wall-clock recovery time across induced
//! session drops.
//!
//! Each iteration:
//!  1. Confirm a session is up (T0 = "now").
//!  2. Trigger a session drop (`ReconnectTrigger::trigger_drop`).
//!     The driver records this instant as the "session-down event".
//!  3. Await the next `wait_session_up` and record T1.
//!
//! `T1 - T_drop` is the reconnect time recorded for the iteration.
//! Aggregated over `iterations` iterations to produce p50/p95/max.
//!
//! For tests, an in-memory `MockTrigger` flips a watch channel; for
//! production, spt-bin plugs in a trigger that talks to the real
//! `ProfileSupervisor`.
//!
//! # Example
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use spt_benchmark::{ReconnectDriver, ReconnectTrigger};
//! # struct Trig;
//! # #[async_trait::async_trait]
//! # impl ReconnectTrigger for Trig {
//! #     async fn wait_session_up(&self) -> std::io::Result<()> { Ok(()) }
//! #     async fn trigger_drop(&self) -> std::io::Result<()> { Ok(()) }
//! # }
//! let driver = ReconnectDriver::new(Arc::new(Trig));
//! # let _ = driver;
//! ```

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Instant;

use crate::driver::{BenchContext, BenchmarkDriver, ImpactLevel, ReconnectTrigger};
use crate::result::{BenchResult, MetricSet, Percentiles};

/// Reconnect-recovery driver.
pub struct ReconnectDriver {
    trigger: Arc<dyn ReconnectTrigger>,
}

impl std::fmt::Debug for ReconnectDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReconnectDriver").finish_non_exhaustive()
    }
}

impl ReconnectDriver {
    /// Build a driver that reconnects via `trigger`.
    #[must_use]
    pub fn new(trigger: Arc<dyn ReconnectTrigger>) -> Self {
        Self { trigger }
    }
}

#[async_trait]
impl BenchmarkDriver for ReconnectDriver {
    fn name(&self) -> &str {
        "reconnect"
    }
    fn impact(&self) -> ImpactLevel {
        ImpactLevel::Production
    }
    async fn run(&self, ctx: &BenchContext) -> BenchResult {
        let started_at = chrono::Utc::now().to_rfc3339();
        let start = Instant::now();
        let mut samples = Vec::with_capacity(ctx.iterations as usize);
        let mut errors = Vec::new();
        let mut completed = 0u64;
        let mut attempted = 0u64;

        // Bring the initial session up before the loop.
        if let Err(e) = self.trigger.wait_session_up().await {
            errors.push(format!("initial up: {e}"));
        }

        for _ in 0..ctx.iterations {
            if start.elapsed() >= ctx.max_duration {
                break;
            }
            attempted += 1;
            let t_drop = Instant::now();
            if let Err(e) = self.trigger.trigger_drop().await {
                errors.push(format!("drop: {e}"));
                continue;
            }
            match self.trigger.wait_session_up().await {
                Ok(()) => {
                    let elapsed = t_drop.elapsed();
                    samples.push(elapsed.as_secs_f64() * 1000.0);
                    completed += 1;
                }
                Err(e) => errors.push(format!("up: {e}")),
            }
        }

        let mut sorted = samples.clone();
        let percentiles = Percentiles::from_samples(&mut sorted);
        BenchResult {
            driver: self.name().into(),
            duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
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
            started_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::BenchContext;
    use crate::result::BenchEnv;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use tokio::sync::Notify;

    /// A mock trigger that simulates a session that takes ~5ms to come back
    /// up after a drop, using a Notify pair.
    struct MockTrigger {
        up: Arc<Notify>,
        drops: AtomicU32,
    }

    #[async_trait]
    impl ReconnectTrigger for MockTrigger {
        async fn wait_session_up(&self) -> std::io::Result<()> {
            // First call returns immediately; subsequent calls wait for
            // notification (which `trigger_drop` schedules).
            if self.drops.load(Ordering::SeqCst) == 0 {
                return Ok(());
            }
            self.up.notified().await;
            Ok(())
        }
        async fn trigger_drop(&self) -> std::io::Result<()> {
            self.drops.fetch_add(1, Ordering::SeqCst);
            let n = self.up.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(5)).await;
                n.notify_one();
            });
            Ok(())
        }
    }

    fn ctx(iters: u64, allow: bool) -> BenchContext {
        BenchContext {
            iterations: iters,
            payload_size: 0,
            max_duration: Duration::from_secs(10),
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

    fn trigger() -> Arc<MockTrigger> {
        Arc::new(MockTrigger {
            up: Arc::new(Notify::new()),
            drops: AtomicU32::new(0),
        })
    }

    #[tokio::test]
    async fn reconnect_records_recovery_times() {
        let t = trigger();
        let driver = ReconnectDriver::new(t.clone());
        let res = driver.run(&ctx(5, true)).await;
        assert_eq!(res.iterations_completed, 5, "{res:?}");
        let p = res.metrics.latency.as_ref().unwrap();
        assert!(p.max_ms >= 1.0, "{p:?}");
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }

    #[test]
    fn safety_blocks_prod_without_flag() {
        let driver = ReconnectDriver::new(trigger());
        let err = crate::safety::check_safety(&driver, false).unwrap_err();
        assert!(matches!(
            err,
            crate::safety::SafetyError::ProductionImpactNotAllowed { .. }
        ));
        crate::safety::check_safety(&driver, true).unwrap();
    }

    #[tokio::test]
    async fn reconnect_result_roundtrips_json() {
        let driver = ReconnectDriver::new(trigger());
        let res = driver.run(&ctx(2, true)).await;
        let s1 = serde_json::to_string(&res).unwrap();
        let back: BenchResult = serde_json::from_str(&s1).unwrap();
        let s2 = serde_json::to_string(&back).unwrap();
        let back2: BenchResult = serde_json::from_str(&s2).unwrap();
        assert_eq!(back2, back);
        assert_eq!(back.driver, res.driver);
    }
}
