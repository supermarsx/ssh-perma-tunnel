//! Reconnect driver — kills the session and measures time-to-recover.
//! Stub: needs supervisor handle, wired in t1-e18.

use async_trait::async_trait;

use crate::driver::{BenchContext, BenchmarkDriver, ImpactLevel};
use crate::result::BenchResult;

/// Reconnect-recovery driver. Currently a stub.
#[derive(Default, Debug)]
pub struct ReconnectDriver;

#[async_trait]
impl BenchmarkDriver for ReconnectDriver {
    fn name(&self) -> &str {
        "reconnect"
    }
    fn impact(&self) -> ImpactLevel {
        ImpactLevel::Production
    }
    async fn run(&self, ctx: &BenchContext) -> BenchResult {
        BenchResult {
            driver: self.name().into(),
            iterations_attempted: ctx.iterations,
            payload_size: ctx.payload_size,
            errors: vec!["reconnect driver requires supervisor wiring (t1-e18)".into()],
            env: ctx.env.clone(),
            started_at: chrono::Utc::now().to_rfc3339(),
            ..Default::default()
        }
    }
}
