//! Limits driver — confirms token bucket / connection cap behaviour. Stub.

use async_trait::async_trait;

use crate::driver::{BenchContext, BenchmarkDriver, ImpactLevel};
use crate::result::BenchResult;

/// Limits driver. Currently a stub.
#[derive(Default, Debug)]
pub struct LimitsDriver;

#[async_trait]
impl BenchmarkDriver for LimitsDriver {
    fn name(&self) -> &str {
        "limits"
    }
    fn impact(&self) -> ImpactLevel {
        ImpactLevel::Production
    }
    async fn run(&self, ctx: &BenchContext) -> BenchResult {
        BenchResult {
            driver: self.name().into(),
            iterations_attempted: ctx.iterations,
            payload_size: ctx.payload_size,
            errors: vec!["limits driver requires forward wiring (t1-e18)".into()],
            env: ctx.env.clone(),
            started_at: chrono::Utc::now().to_rfc3339(),
            ..Default::default()
        }
    }
}
