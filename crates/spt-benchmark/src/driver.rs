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

// --------------------------------------------------------------------------
// UDP / Reconnect / DNS injection seams (used by the eponymous drivers).
// --------------------------------------------------------------------------

/// A bound UDP socket plus the address of the (echo) target.
///
/// Returned by a [`UdpConnector`]. The driver sends datagrams to `target`
/// and expects them echoed back to `socket`'s local address.
pub struct UdpEndpoint {
    /// Bound socket the driver sends/receives datagrams on.
    pub socket: tokio::net::UdpSocket,
    /// Echo target address.
    pub target: std::net::SocketAddr,
}

/// Produces a UDP endpoint for the [`crate::drivers::UdpDriver`].
///
/// In tests this binds a loopback `UdpSocket` and spawns an in-process
/// echo task. In production it asks the SSH3 backend for a UDP-forwarded
/// endpoint.
pub type UdpConnector = Box<
    dyn Fn() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<UdpEndpoint>> + Send>,
        > + Send
        + Sync,
>;

/// Drives the [`crate::drivers::ReconnectDriver`] across one reconnect cycle.
///
/// The driver flow:
/// 1. [`Self::wait_session_up`] — block until a session is ready, returning T0.
/// 2. [`Self::trigger_drop`] — cause the session to drop (e.g. close the
///    underlying transport). The driver records the time of this call as the
///    "session-down event".
/// 3. [`Self::wait_session_up`] — block until the next session is ready;
///    the elapsed since the drop is the reconnect time.
///
/// Implementations MUST be `Sync` so the driver can call them in a loop.
#[async_trait::async_trait]
pub trait ReconnectTrigger: Send + Sync {
    /// Block until the next session OPEN-handshake completes.
    async fn wait_session_up(&self) -> std::io::Result<()>;
    /// Cause the current session to drop. Returns when the loss has been
    /// signalled (not necessarily when the next reconnect has started).
    async fn trigger_drop(&self) -> std::io::Result<()>;
}

/// Async DNS query injection seam used by [`crate::drivers::DnsDriver`].
#[async_trait::async_trait]
pub trait DnsClient: Send + Sync {
    /// Resolve `name` to one or more IP addresses (as strings, opaque to
    /// the driver). Errors are recorded by the driver as failed queries.
    async fn query(&self, name: &str) -> std::io::Result<Vec<String>>;
}

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
