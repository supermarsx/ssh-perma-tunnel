//! DNS query-rate driver. Stub — wired in t1-e18.

use async_trait::async_trait;

use crate::driver::{BenchContext, BenchmarkDriver, ImpactLevel};
use crate::result::BenchResult;

/// DNS load driver. Currently a stub.
#[derive(Default, Debug)]
pub struct DnsDriver;

#[async_trait]
impl BenchmarkDriver for DnsDriver {
    fn name(&self) -> &str {
        "dns"
    }
    fn impact(&self) -> ImpactLevel {
        ImpactLevel::Synthetic
    }
    async fn run(&self, ctx: &BenchContext) -> BenchResult {
        BenchResult {
            driver: self.name().into(),
            iterations_attempted: ctx.iterations,
            payload_size: ctx.payload_size,
            errors: vec!["dns driver requires resolver wiring (t1-e18)".into()],
            env: ctx.env.clone(),
            started_at: chrono::Utc::now().to_rfc3339(),
            ..Default::default()
        }
    }
}
