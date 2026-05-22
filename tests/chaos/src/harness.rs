//! C1 harness: wires a [`ChaosProxy`] in front of a stub SSH server, captures
//! audit-style events through a [`MockAuditSink`], and observes the
//! supervisor's reconnect attempts via [`install_test_hook`].
//!
//! Stubs in C1 are deliberately minimal:
//!
//! * [`SshServer`] is a TCP accept-and-hang fixture — enough to make the
//!   chaos proxy forward to *something*. C2 will replace it with a russh
//!   server harness once the protocol surface stabilises.
//! * [`SptProcess`] is a thin wrapper around `std::process::Child` that
//!   captures stdout/stderr. The C1 [`ChaosHarness::launch`] does NOT
//!   actually spawn `spt` — locating the binary cross-platform / cross-CI
//!   is C2's problem. The field is present so the C2 launcher slots in
//!   without changing the public type signature.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use spt_chaos_proxy::{ChaosBehaviour, ChaosProxy, ChaosProxyHandle};
use spt_supervisor::reconnect::{
    clear_test_hook, install_test_hook, ReconnectObserver,
};

// ---------------------------------------------------------------------------
// Observable event types
// ---------------------------------------------------------------------------

/// One audit-style event captured by the [`MockAuditSink`]. C2 will likely
/// extend this enum (or replace it with a re-export of `spt_events::Event`
/// once that crate's surface settles).
#[derive(Clone, Debug)]
pub enum AuditEvent {
    /// The harness was launched against the listed behaviour.
    HarnessLaunched(String),
    /// The harness observed a reconnect attempt.
    ReconnectAttempted {
        /// 1-based attempt counter.
        attempt: u32,
        /// Backoff delay in ms.
        delay_ms: u64,
    },
    /// The harness observed a successful reconnect.
    ReconnectSucceeded {
        /// Attempt count at which success occurred.
        attempt: u32,
    },
    /// The supervisor reported its backoff was exhausted.
    BackoffExhausted {
        /// Attempt count at exhaustion.
        attempt: u32,
    },
    /// Free-form note (used by scenarios to mark phases).
    Note(String),
}

/// One observed reconnect attempt — what the supervisor told us, captured
/// in order. Returned in batches by
/// [`ChaosHarness::observe_reconnect_attempts`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconnectAttempt {
    /// 1-based attempt counter (matches `ProfileEvent::ReconnectScheduled`).
    pub attempt: u32,
    /// Backoff delay the supervisor selected for this attempt.
    pub delay: Duration,
}

// ---------------------------------------------------------------------------
// MockAuditSink
// ---------------------------------------------------------------------------

/// Thread-safe in-memory audit collector.
///
/// Push events from anywhere; drain with [`MockAuditSink::events`].
#[derive(Clone, Default, Debug)]
pub struct MockAuditSink {
    inner: Arc<Mutex<Vec<AuditEvent>>>,
}

impl MockAuditSink {
    /// Empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Record one event.
    pub fn push(&self, e: AuditEvent) {
        self.inner.lock().push(e);
    }
    /// Snapshot of all recorded events (cheap clone — they're small).
    #[must_use]
    pub fn events(&self) -> Vec<AuditEvent> {
        self.inner.lock().clone()
    }
    /// Clear all recorded events.
    pub fn clear(&self) {
        self.inner.lock().clear();
    }
}

// ---------------------------------------------------------------------------
// Stub SSH server
// ---------------------------------------------------------------------------

/// Minimal TCP fixture that accepts connections and idles. C2 will swap
/// this for a russh server stub once the test plan needs real
/// handshakes.
///
/// Created via [`SshServer::spawn`]; cleaned up on drop.
#[derive(Debug)]
pub struct SshServer {
    addr: SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

impl SshServer {
    /// Spawn an accept-and-idle server on a random loopback port.
    pub async fn spawn() -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let (sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                // Drop on the floor — chaos tests don't need real SSH.
                tokio::spawn(async move {
                    let _keep = sock;
                    std::future::pending::<()>().await;
                });
            }
        });
        Ok(Self { addr, _task: task })
    }
    /// Address the stub server is listening on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

// ---------------------------------------------------------------------------
// SptProcess placeholder
// ---------------------------------------------------------------------------

/// Placeholder for the spawned `spt` subprocess. C1 keeps this as an
/// `Option<Child>` so C2 can wire the launcher without changing the
/// harness's public signature.
#[derive(Debug, Default)]
pub struct SptProcess {
    pub(crate) child: Option<std::process::Child>,
}

impl SptProcess {
    /// `true` if a child process was actually spawned.
    #[must_use]
    pub fn is_spawned(&self) -> bool {
        self.child.is_some()
    }
}

impl Drop for SptProcess {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// Observer wiring
// ---------------------------------------------------------------------------

/// Bridge between the supervisor's `ReconnectObserver` trait and the
/// harness's [`MockAuditSink`] / [`ReconnectAttempt`] log.
struct HarnessObserver {
    audit: MockAuditSink,
    attempts: Arc<Mutex<Vec<ReconnectAttempt>>>,
}

impl ReconnectObserver for HarnessObserver {
    fn on_attempt(&self, attempt: u32, delay: Duration) {
        self.attempts
            .lock()
            .push(ReconnectAttempt { attempt, delay });
        self.audit.push(AuditEvent::ReconnectAttempted {
            attempt,
            delay_ms: delay.as_millis() as u64,
        });
    }
    fn on_success(&self, attempt: u32) {
        self.audit
            .push(AuditEvent::ReconnectSucceeded { attempt });
    }
    fn on_max_exhausted(&self, attempt: u32) {
        self.audit
            .push(AuditEvent::BackoffExhausted { attempt });
    }
}

// ---------------------------------------------------------------------------
// ChaosHarness
// ---------------------------------------------------------------------------

/// Top-level harness binding the chaos proxy, the stub SSH server, the
/// (eventual) `spt` subprocess, and the audit sink together.
#[derive(Debug)]
pub struct ChaosHarness {
    /// Subprocess wrapper; empty in C1. C2 will populate.
    pub spt_bin: SptProcess,
    /// Live handle on the chaos proxy (use to swap behaviour at runtime).
    pub proxy: ChaosProxyHandle,
    /// Stub SSH upstream the proxy forwards to.
    pub ssh_server: SshServer,
    /// Audit-event capture.
    pub audit_sink: MockAuditSink,
    /// Observed reconnect attempts (in order).
    attempts: Arc<Mutex<Vec<ReconnectAttempt>>>,
    /// Background task running the proxy's accept loop.
    _proxy_task: tokio::task::JoinHandle<()>,
}

impl ChaosHarness {
    /// Bring up the chaos proxy + stub SSH server, install the supervisor
    /// reconnect hook, and return a ready-to-drive harness.
    ///
    /// The `spt` subprocess is NOT spawned in C1 — see [`SptProcess`].
    pub async fn launch(behaviour: ChaosBehaviour) -> Self {
        let ssh_server = SshServer::spawn().await.expect("stub SSH server bind");
        let proxy = ChaosProxy::bind(
            "127.0.0.1:0".parse().unwrap(),
            ssh_server.addr(),
            behaviour.clone(),
        )
        .await
        .expect("chaos proxy bind");
        let handle = proxy.handle();

        let audit_sink = MockAuditSink::new();
        audit_sink.push(AuditEvent::HarnessLaunched(format!("{behaviour:?}")));

        let attempts: Arc<Mutex<Vec<ReconnectAttempt>>> = Arc::new(Mutex::new(Vec::new()));
        let observer = Arc::new(HarnessObserver {
            audit: audit_sink.clone(),
            attempts: Arc::clone(&attempts),
        });
        // Replace any prior observer; harness::shutdown restores `None`.
        let _ = install_test_hook(observer);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.run().await;
        });

        Self {
            spt_bin: SptProcess::default(),
            proxy: handle,
            ssh_server,
            audit_sink,
            attempts,
            _proxy_task: proxy_task,
        }
    }

    /// Snapshot of all captured audit events.
    #[must_use]
    pub fn audit_events(&self) -> Vec<AuditEvent> {
        self.audit_sink.events()
    }

    /// Wait up to `timeout` and return any reconnect attempts observed.
    /// Returns immediately with the current set if `timeout` is `ZERO`.
    pub async fn observe_reconnect_attempts(
        &self,
        timeout: Duration,
    ) -> Vec<ReconnectAttempt> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let cur = self.attempts.lock();
                if !cur.is_empty() {
                    return cur.clone();
                }
            }
            if std::time::Instant::now() >= deadline {
                return self.attempts.lock().clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Hot-swap the chaos behaviour.
    pub fn set_behaviour(&self, b: ChaosBehaviour) {
        self.proxy.set_behaviour(b);
    }

    /// Local address of the chaos proxy — what the (eventual) `spt`
    /// subprocess should connect to.
    #[must_use]
    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy.local_addr()
    }

    /// Tear down: kill any subprocess, clear the supervisor hook, drop
    /// the proxy task on the floor (its socket will be closed when the
    /// listener is dropped).
    pub async fn shutdown(self) {
        // SptProcess::drop kills any child.
        let _ = clear_test_hook();
        // _proxy_task is aborted on drop in tokio 1.x via JoinHandle::abort
        // — but we don't strictly need to; closing the listener achieves
        // the same effect.
        drop(self.spt_bin);
        drop(self.audit_sink);
        drop(self.ssh_server);
    }
}
