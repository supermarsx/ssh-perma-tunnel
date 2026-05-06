//! Driver trait + execution context.

use async_trait::async_trait;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::result::BenchResult;

/// A boxed bidirectional async stream produced by a [`Connector`].
pub type BoxedStream =
    Pin<Box<dyn AsyncStream + Send + Unpin>>;

/// Marker trait combining `AsyncRead + AsyncWrite`.
pub trait AsyncStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncStream for T {}

/// Produces a fresh stream for the driver to drive. Returning `Err` aborts
/// the benchmark with a recorded error.
pub type Connector = Box<
    dyn Fn() -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<BoxedStream>> + Send,
            >,
        > + Send
        + Sync,
>;

/// Whether the benchmark may impact a real production system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpactLevel {
    /// Synthetic / loopback only — always safe.
    Synthetic,
    /// Talks over the real tunnel; may apply load.
    Production,
}

/// Per-run knobs threaded into every driver.
pub struct BenchContext {
    /// Total iterations / messages / requests, as the driver interprets it.
    pub iterations: u64,
    /// Per-iteration payload size (bytes).
    pub payload_size: usize,
    /// Maximum wall time. Drivers SHOULD stop early when exceeded.
    pub max_duration: Duration,
    /// Connector that produces a stream per benchmark.
    pub connector: Connector,
    /// True when run by the user with `--unsafe-allow-production-impact`.
    pub allow_production_impact: bool,
    /// Free-form environment metadata recorded into the result.
    pub env: crate::result::BenchEnv,
}

impl std::fmt::Debug for BenchContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BenchContext")
            .field("iterations", &self.iterations)
            .field("payload_size", &self.payload_size)
            .field("max_duration", &self.max_duration)
            .field("allow_production_impact", &self.allow_production_impact)
            .field("env", &self.env)
            .finish_non_exhaustive()
    }
}

/// A benchmark driver. Implementations MUST be cancellation-safe and MUST
/// respect `ctx.max_duration`.
#[async_trait]
pub trait BenchmarkDriver: Send + Sync {
    /// Stable, kebab-case identifier (`latency`, `throughput`, `reconnect`).
    fn name(&self) -> &str;
    /// Whether the driver targets a real production system.
    fn impact(&self) -> ImpactLevel;
    /// Run the driver. Errors are reported in the [`BenchResult::errors`]
    /// vector rather than propagated.
    async fn run(&self, ctx: &BenchContext) -> BenchResult;
}
