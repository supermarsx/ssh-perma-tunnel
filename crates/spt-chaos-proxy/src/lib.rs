//! Cross-platform TCP **chaos proxy** for the `spt` reconnect test suite.
//!
//! A `ChaosProxy` listens on a TCP socket, forwards each accepted connection
//! to a configured upstream, and runs the bidirectional copy through a
//! pluggable transformation chosen by [`ChaosBehaviour`]. Behaviours can be
//! swapped at runtime via [`ChaosProxy::set_behaviour`] so a single proxy
//! drives multi-stage scenarios (e.g. "30 s of latency → 5 s partition →
//! pristine").
//!
//! ## Behaviours
//!
//! | Variant | Effect |
//! |---|---|
//! | [`ChaosBehaviour::Pristine`] | Plain bidirectional copy. |
//! | [`ChaosBehaviour::LatencyMs`] | Delay each chunk by `n` ms. |
//! | [`ChaosBehaviour::LossPct`] | Drop a fraction of chunks. |
//! | [`ChaosBehaviour::RstAfterBytes`] | Force an RST after `n` bytes. |
//! | [`ChaosBehaviour::Partition`] | Stop forwarding after `after`. |
//! | [`ChaosBehaviour::DnsAnswerRotation`] | **Deferred to C2** — handled by `MockResolver` (not a TCP-proxy concern). |
//! | [`ChaosBehaviour::HostKeyChurn`] | **Deferred to C2** — handled by `ChurningSshServer` stub in `tests/chaos/src/harness.rs`. |
//!
//! ## Example
//!
//! ```no_run
//! # use spt_chaos_proxy::{ChaosProxy, ChaosBehaviour};
//! # use std::net::SocketAddr;
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let upstream: SocketAddr = "127.0.0.1:22".parse()?;
//! let bind:     SocketAddr = "127.0.0.1:0".parse()?;
//! let proxy = ChaosProxy::bind(bind, upstream, ChaosBehaviour::LatencyMs(50)).await?;
//! let port = proxy.local_addr().port();
//! tokio::spawn(proxy.run());
//! # let _ = port;
//! # Ok(()) }
//! ```
//!
//! ## MSRV
//!
//! Workspace MSRV is **1.85**. The const `std::sync::Mutex::new` and
//! `tokio::net::TcpStream::peer_addr` features used here are 1.63+ and 1.0+
//! respectively.

#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};

pub mod dns;
pub mod hostkey;
pub mod latency;
pub mod loss;
pub mod partition;
pub mod rst;

/// One injectable transformation applied to every accepted connection.
///
/// Cheap to clone (only [`ChaosBehaviour::DnsAnswerRotation`] owns a
/// non-trivial allocation).
#[derive(Clone, Debug)]
pub enum ChaosBehaviour {
    /// Plain bidirectional copy — no chaos.
    Pristine,
    /// Sleep `n` milliseconds between reading a chunk and writing it.
    LatencyMs(u64),
    /// Drop a percentage of chunks, in `[0, 100]`. Clamped on use.
    LossPct(u8),
    /// Forcibly close the connection (RST) after `n` bytes have flowed in
    /// either direction.
    RstAfterBytes(usize),
    /// After `after` has elapsed since the proxy accepted the connection,
    /// stop forwarding bytes in *both* directions. Existing socket pairs
    /// stay open but become silent — the supervisor must rely on its own
    /// keepalive to detect.
    Partition {
        /// How long after accept to begin the partition.
        after: Duration,
    },
    /// **Deferred to C2.** Modeled here so callers can author multi-stage
    /// behaviour sequences without changing the enum later. Handled by a
    /// companion `MockResolver` outside the proxy; the proxy treats this
    /// variant as a `Pristine` passthrough.
    DnsAnswerRotation {
        /// TTL between rotations.
        ttl: Duration,
        /// Pool of answers to rotate through.
        answers: Vec<IpAddr>,
    },
    /// **Deferred to C2.** Modeled here so callers can author multi-stage
    /// behaviour sequences without changing the enum later. Handled by a
    /// server-side `ChurningSshServer` stub in `tests/chaos`. The proxy
    /// treats this variant as a `Pristine` passthrough.
    HostKeyChurn {
        /// Rotate the SSH host key after this delay.
        new_after: Duration,
    },
}

/// The TCP chaos proxy.
#[derive(Debug)]
pub struct ChaosProxy {
    listener: TcpListener,
    upstream: SocketAddr,
    behaviour: Arc<Mutex<ChaosBehaviour>>,
    local: SocketAddr,
}

impl ChaosProxy {
    /// Bind the proxy and resolve its assigned local address.
    ///
    /// Pass `127.0.0.1:0` as `addr` to let the OS pick a free port.
    pub async fn bind(
        addr: SocketAddr,
        upstream: SocketAddr,
        behaviour: ChaosBehaviour,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        Ok(Self {
            listener,
            upstream,
            behaviour: Arc::new(Mutex::new(behaviour)),
            local,
        })
    }

    /// Local address the proxy is listening on (post-bind).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Get a cheap handle for hot-swapping behaviour from another task.
    #[must_use]
    pub fn handle(&self) -> ChaosProxyHandle {
        ChaosProxyHandle {
            behaviour: Arc::clone(&self.behaviour),
            local: self.local,
        }
    }

    /// Swap the current behaviour. Affects future *and* in-flight
    /// connections (each per-direction copy task re-reads the behaviour on
    /// each chunk).
    pub fn set_behaviour(&self, b: ChaosBehaviour) {
        *self.behaviour.lock() = b;
    }

    /// Run the accept loop. This future completes when the listener is
    /// dropped or returns an error.
    pub async fn run(self) -> std::io::Result<()> {
        let upstream = self.upstream;
        let behaviour = self.behaviour.clone();
        loop {
            let (down, peer) = match self.listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::debug!("chaos-proxy accept error: {e}");
                    // Brief pause to avoid hot-spinning on a broken listener.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            tracing::trace!(?peer, "chaos-proxy: accepted");
            let up = match TcpStream::connect(upstream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("chaos-proxy upstream connect failed: {e}");
                    drop(down);
                    continue;
                }
            };
            let behaviour = behaviour.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_pair(down, up, behaviour).await {
                    tracing::trace!("chaos-proxy: connection finished: {e}");
                }
            });
        }
    }
}

/// Lightweight handle for tests: lets you mutate behaviour and inspect the
/// bound address without owning the `ChaosProxy` (which has been moved into
/// a `tokio::spawn(proxy.run())`).
#[derive(Clone, Debug)]
pub struct ChaosProxyHandle {
    behaviour: Arc<Mutex<ChaosBehaviour>>,
    local: SocketAddr,
}

impl ChaosProxyHandle {
    /// See [`ChaosProxy::local_addr`].
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    /// See [`ChaosProxy::set_behaviour`].
    pub fn set_behaviour(&self, b: ChaosBehaviour) {
        *self.behaviour.lock() = b;
    }
    /// Snapshot the current behaviour.
    #[must_use]
    pub fn current(&self) -> ChaosBehaviour {
        self.behaviour.lock().clone()
    }
}

/// One full bidirectional copy with chaos applied symmetrically.
async fn handle_pair(
    down: TcpStream,
    up: TcpStream,
    behaviour: Arc<Mutex<ChaosBehaviour>>,
) -> std::io::Result<()> {
    // Split each side; pair them.
    let (down_r, down_w) = down.into_split();
    let (up_r, up_w) = up.into_split();

    // Per-pair shared counter for RstAfterBytes — bytes summed across both
    // directions, matching how a real RST would interrupt either side.
    // `AtomicUsize` rather than a Mutex so the future stays `Send`.
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let start = std::time::Instant::now();

    let b1 = behaviour.clone();
    let b2 = behaviour.clone();
    let c1 = counter.clone();
    let c2 = counter.clone();

    let d2u = tokio::spawn(async move { copy_with_chaos(down_r, up_w, b1, c1, start).await });
    let u2d = tokio::spawn(async move { copy_with_chaos(up_r, down_w, b2, c2, start).await });

    // Either side finishing tears down the pair.
    tokio::select! {
        r = d2u => match r { Ok(r) => r, Err(_) => Ok(()) },
        r = u2d => match r { Ok(r) => r, Err(_) => Ok(()) },
    }
}

async fn copy_with_chaos<R, W>(
    mut r: R,
    mut w: W,
    behaviour: Arc<Mutex<ChaosBehaviour>>,
    counter: Arc<std::sync::atomic::AtomicUsize>,
    started: std::time::Instant,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0_u8; 8192];
    loop {
        // Pre-read snapshot — covers Partition (a long-duration partition
        // should keep us out of the read entirely).
        {
            let b = behaviour.lock().clone();
            if let ChaosBehaviour::Partition { after } = &b {
                if partition::is_partitioned(started, *after) {
                    partition::idle_forever().await;
                    return Ok(());
                }
            }
        }

        let n = match r.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) => return Err(e),
        };

        // Re-snapshot AFTER the read. set_behaviour() that landed while we
        // were blocked must affect this chunk, and Partition that elapsed
        // mid-read must drop the chunk.
        let b = behaviour.lock().clone();

        if let ChaosBehaviour::Partition { after } = &b {
            if partition::is_partitioned(started, *after) {
                partition::idle_forever().await;
                return Ok(());
            }
        }

        // RstAfterBytes: count, and once we'd exceed the threshold, drop
        // both ends to elicit an RST. Done before the write so the byte
        // never reaches the peer.
        if let ChaosBehaviour::RstAfterBytes(limit) = &b {
            let total = counter.fetch_add(n, Ordering::SeqCst).saturating_add(n);
            if total >= *limit {
                rst::force_rst(&mut w).await;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "chaos: RstAfterBytes",
                ));
            }
        }

        // LossPct: maybe skip the write.
        if let ChaosBehaviour::LossPct(pct) = &b {
            if loss::should_drop(*pct) {
                tracing::trace!(bytes = n, "chaos-proxy: dropping chunk");
                continue;
            }
        }

        // LatencyMs: sleep before forwarding.
        if let ChaosBehaviour::LatencyMs(ms) = &b {
            latency::delay(*ms).await;
        }

        // Dns / HostKey are deferred — fall through to a plain write.
        w.write_all(&buf[..n]).await?;
    }
}
