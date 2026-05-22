//! Shared scaffolding for the 12 t8-C2 reconnect scenarios.
//!
//! C1 left `tests/chaos/src/scenarios/` empty; this module hosts the bits
//! every scenario reuses without touching C1's `lib.rs` / `harness.rs`:
//!
//! * [`TcpProbeProtocol`] — a `TunnelProtocol` that performs a real TCP
//!   probe (`connect` + write+read with a short timeout) against the
//!   chaos proxy. When the proxy injects `Partition`, `RstAfterBytes(0)`,
//!   `LossPct(100)`, etc., the probe fails and the supervisor's reconnect
//!   loop fires — which is what every scenario wants to observe.
//! * [`EchoServer`] — minimal TCP listener echoing one byte and closing.
//!   Lets the probe complete on `Pristine` so we can later flip behaviour
//!   and observe the *transition* into chaos.
//! * [`CountingObserver`] — `ReconnectObserver` impl that records every
//!   `(attempt, delay)` plus success / max-exhausted callbacks.
//! * [`fast_backoff`] / [`spawn_proxy_to`] — small helpers so each
//!   scenario file stays tight.
//!
//! ## Why a fresh `ProfileSupervisor` instead of `ChaosHarness::launch`?
//!
//! `ChaosHarness::launch` is convenience — it spins up a chaos proxy +
//! an accept-and-idle stub SSH server, but does *not* spawn an `spt`
//! subprocess (C1 left that to C2; see the t8-C1 log). For the in-process
//! scenarios we need a real `ProfileSupervisor` so the *production*
//! `Backoff` + `next_backoff` + `notify_attempt` code paths actually
//! execute. The harness's supervisor hook is global, so installing our
//! own `CountingObserver` per scenario works regardless of whether the
//! harness is in play.

#![allow(dead_code)] // each scenario uses a different subset of helpers
#![allow(missing_docs)] // test scaffolding

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use spt_auth::AuthConfig;
use spt_chaos_proxy::{ChaosBehaviour, ChaosProxy, ChaosProxyHandle};
use spt_core::Result as CoreResult;
use spt_protocol::{Endpoint, ProtocolCapabilities, TunnelProtocol, TunnelSession};
use spt_supervisor::reconnect::{
    clear_test_hook, install_test_hook, ReconnectObserver,
};
use spt_supervisor::{BackoffConfig, ProfileSupervisor, ProfileSupervisorConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

// -----------------------------------------------------------------------------
// EchoServer
// -----------------------------------------------------------------------------

/// Minimal TCP echo server. Per-connection: reads up to N bytes, writes
/// one byte back, then closes. Used as the "upstream" the chaos proxy
/// forwards to so the [`TcpProbeProtocol`] can complete a full probe
/// round-trip on `Pristine`.
pub struct EchoServer {
    addr: SocketAddr,
    _task: JoinHandle<()>,
}

impl EchoServer {
    /// Spawn the echo server on a random loopback port.
    pub async fn spawn() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0_u8; 32];
                    // Best-effort: read one chunk, echo one byte, then close.
                    if let Ok(n) = sock.read(&mut buf).await {
                        if n > 0 {
                            let _ = sock.write_all(b"k").await;
                            let _ = sock.shutdown().await;
                        }
                    }
                });
            }
        });
        Ok(Self { addr, _task: task })
    }

    /// Address the echo server is listening on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

// -----------------------------------------------------------------------------
// TcpProbeProtocol
// -----------------------------------------------------------------------------

/// A `TunnelProtocol` whose `connect` performs a real TCP round-trip:
/// `connect → write(b"probe\n") → read 1 byte`, all under a short timeout.
///
/// This makes chaos-injected disconnects (RST, Partition, LossPct(100))
/// actually fail `connect()` — which is the seam the supervisor's reconnect
/// loop observes.
///
/// The returned [`TunnelSession`] is a thin wrapper; the scenarios that
/// need an *established session* path are very limited because
/// `ProfileTask::run_active` (see `crates/spt-supervisor/src/profile.rs:464`)
/// only exits on control messages, not on session-side disconnects. That
/// limitation is documented in `.orchestration/logs/t8-C2.md`.
pub struct TcpProbeProtocol {
    /// Address the probe should connect to. Usually the chaos proxy.
    pub target: SocketAddr,
    /// Per-probe timeout. Override per-scenario via [`Self::with_timeout`].
    pub timeout: Duration,
}

impl TcpProbeProtocol {
    #[must_use]
    pub fn new(target: SocketAddr) -> Self {
        Self {
            target,
            timeout: Duration::from_millis(500),
        }
    }
    #[must_use]
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }
}

#[async_trait]
impl TunnelProtocol for TcpProbeProtocol {
    async fn connect(
        &self,
        _endpoint: &Endpoint,
        _auth: &AuthConfig,
    ) -> CoreResult<Box<dyn TunnelSession>> {
        let res = tokio::time::timeout(self.timeout, async {
            let mut s = TcpStream::connect(self.target).await?;
            s.write_all(b"probe\n").await?;
            let mut b = [0_u8; 1];
            // We expect at least one byte from the EchoServer. On
            // Partition / RstAfterBytes(0) / LossPct(100) the read will
            // hang or fail; the outer `timeout` converts a hang into an
            // error.
            let n = s.read(&mut b).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "probe got 0 bytes",
                ));
            }
            Ok::<_, std::io::Error>(())
        })
        .await;

        match res {
            Ok(Ok(())) => Ok(Box::new(ProbeSession)),
            Ok(Err(e)) => Err(spt_core::Error::NetworkUnreachable(format!(
                "probe: {e}"
            ))),
            Err(_) => Err(spt_core::Error::NetworkUnreachable(
                "probe: timeout".into(),
            )),
        }
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::ssh3()
    }

    fn name(&self) -> &'static str {
        "tcp-probe"
    }
}

struct ProbeSession;

#[async_trait]
impl TunnelSession for ProbeSession {
    fn session_info(&self) -> spt_protocol::SessionInfo {
        spt_protocol::SessionInfo {
            backend: "tcp-probe".into(),
            peer_version: None,
            negotiated: None,
            established_at: 0,
        }
    }
    async fn open_local_forward(
        &mut self,
        _spec: &spt_protocol::LocalForwardSpec,
    ) -> CoreResult<spt_protocol::ForwardHandle> {
        Err(spt_core::Error::RuntimeFailure(
            "tcp-probe has no forwards".into(),
        ))
    }
    async fn open_remote_forward(
        &mut self,
        _spec: &spt_protocol::RemoteForwardSpec,
    ) -> CoreResult<spt_protocol::ForwardHandle> {
        Err(spt_core::Error::RuntimeFailure(
            "tcp-probe has no forwards".into(),
        ))
    }
    async fn open_dynamic_forward(
        &mut self,
        _spec: &spt_protocol::DynamicForwardSpec,
    ) -> CoreResult<spt_protocol::ForwardHandle> {
        Err(spt_core::Error::RuntimeFailure(
            "tcp-probe has no forwards".into(),
        ))
    }
    async fn open_udp_forward(
        &mut self,
        _spec: &spt_protocol::UdpForwardSpec,
    ) -> CoreResult<spt_protocol::ForwardHandle> {
        Err(spt_core::Error::RuntimeFailure(
            "tcp-probe has no forwards".into(),
        ))
    }
    async fn keepalive(&mut self) -> CoreResult<()> {
        Ok(())
    }
    async fn close(self: Box<Self>) -> CoreResult<()> {
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// CountingObserver
// -----------------------------------------------------------------------------

/// Records every observer callback. Snapshot via [`CountingObserver::attempts`],
/// [`CountingObserver::successes`], [`CountingObserver::max_exhausted`].
#[derive(Default, Debug)]
pub struct CountingObserver {
    pub attempts: Mutex<Vec<(u32, Duration)>>,
    pub successes: Mutex<Vec<u32>>,
    pub max_exhausted: Mutex<Vec<u32>>,
}

impl CountingObserver {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    #[must_use]
    pub fn attempt_count(&self) -> usize {
        self.attempts.lock().len()
    }
    #[must_use]
    pub fn attempts_snapshot(&self) -> Vec<(u32, Duration)> {
        self.attempts.lock().clone()
    }
    #[must_use]
    pub fn exhausted_count(&self) -> usize {
        self.max_exhausted.lock().len()
    }
}

impl ReconnectObserver for CountingObserver {
    fn on_attempt(&self, attempt: u32, delay: Duration) {
        self.attempts.lock().push((attempt, delay));
    }
    fn on_success(&self, attempt: u32) {
        self.successes.lock().push(attempt);
    }
    fn on_max_exhausted(&self, attempt: u32) {
        self.max_exhausted.lock().push(attempt);
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Tight backoff config for fast scenario runs. Default workspace
/// backoff (1 s initial, 60 s cap) would make every scenario take minutes.
#[must_use]
pub fn fast_backoff(max_attempts: u32) -> BackoffConfig {
    BackoffConfig {
        initial_delay: Duration::from_millis(20),
        max_delay: Duration::from_millis(200),
        reset_after: Duration::from_secs(2),
        jitter: 1.0,
        max_attempts,
    }
}

/// Spawn a `ChaosProxy` on a random loopback port pointing at `upstream`.
/// Returns the handle (for `set_behaviour`) plus the listening address.
pub async fn spawn_proxy_to(
    upstream: SocketAddr,
    initial: ChaosBehaviour,
) -> (ChaosProxyHandle, SocketAddr, JoinHandle<()>) {
    let proxy = ChaosProxy::bind("127.0.0.1:0".parse().unwrap(), upstream, initial)
        .await
        .expect("chaos proxy bind");
    let addr = proxy.local_addr();
    let handle = proxy.handle();
    let task = tokio::spawn(async move {
        let _ = proxy.run().await;
    });
    (handle, addr, task)
}

/// Build a supervisor wired to `proxy_addr` with `cfg`. Auth is empty
/// (the `TcpProbeProtocol` doesn't use it).
#[must_use]
pub fn spawn_supervisor(
    name: &str,
    proxy_addr: SocketAddr,
    backoff: BackoffConfig,
) -> ProfileSupervisor {
    let proto = Arc::new(TcpProbeProtocol::new(proxy_addr));
    let mut cfg = ProfileSupervisorConfig::default();
    cfg.backoff = backoff;
    ProfileSupervisor::spawn(
        name,
        proto,
        AuthConfig::new("u", vec![]),
        vec![Endpoint::new(proxy_addr.ip().to_string(), proxy_addr.port())],
        vec![],
        cfg,
    )
}

/// Install `obs` as the global reconnect observer for the lifetime of
/// the returned guard; on drop the hook is cleared. Scenarios should
/// keep the guard alive for the duration of their assertion window.
/// Global mutex serialising scenario execution. The supervisor's
/// `install_test_hook` is process-wide, so two scenarios installing
/// observers concurrently would clobber each other's callbacks (this
/// was caught empirically when `max_attempts_exhaustion` raced
/// `rst_storm_100_per_sec` under default cargo-test parallelism — the
/// `rst_storm` observer ate the `max_exhausted` callback). Acquire this
/// guard via [`ObserverGuard::install`].
static SCENARIO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub struct ObserverGuard {
    // Held for the duration of the scenario so other scenarios block.
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl ObserverGuard {
    pub fn install<O>(obs: Arc<O>) -> Self
    where
        O: ReconnectObserver + 'static,
    {
        // `lock()` may surface a poisoned-mutex error if a previous
        // scenario panicked while holding the lock; recover the inner
        // guard so the next scenario can still run.
        let _lock = SCENARIO_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Defensive clear in case a prior scenario left a hook installed.
        let _ = clear_test_hook();
        let _ = install_test_hook(obs as Arc<dyn ReconnectObserver>);
        Self { _lock }
    }
}

impl Drop for ObserverGuard {
    fn drop(&mut self) {
        let _ = clear_test_hook();
    }
}

/// Whether the host has opted into the full chaos suite. PR-time runs see
/// only the deterministic scenarios; the rest stay `#[ignore]`'d.
#[must_use]
pub fn chaos_full_enabled() -> bool {
    std::env::var("SPT_CHAOS_FULL").map(|v| !v.is_empty()).unwrap_or(false)
}
