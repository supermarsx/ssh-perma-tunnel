//! Shared helpers for `spt-e2e-tests`.
//!
//! Hosts the `SharedLogProtocol` / `SharedLogSession` pair used by the
//! `ssh2_*` mock-variant tests. Each test wires a single
//! `Arc<Mutex<Vec<SessionCall>>>` into the protocol; every session it produces
//! pushes its calls into that one log, so the test can observe wiring across
//! reconnects.
//!
//! The corresponding real-libssh2 plumbing is intentionally *not* hosted here
//! — the russh ↔ libssh2 KEX interop bug documented in
//! `crates/spt-ssh2/tests/russh_basic.rs` keeps every real-stack test
//! `#[ignore]`'d, so each `ssh2_*.rs` file inlines its real-stack stub.

#![deny(missing_docs)]

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use spt_auth::AuthConfig;
use spt_core::Result;
use spt_forward::testing::{MockTunnelSession, SessionCall};
use spt_protocol::{
    Endpoint, ForwardHandle, LocalForwardSpec, ProtocolCapabilities, RemoteForwardSpec,
    SessionInfo, TunnelProtocol, TunnelSession, UdpForwardSpec,
};

/// `TunnelProtocol` that hands out [`SharedLogSession`]s wired to a single
/// shared log. Useful for tests that want to observe `open_*_forward` /
/// `keepalive` / `close` calls on the underlying mock session, including
/// across reconnects (where each `connect()` returns a *fresh* session).
pub struct SharedLogProtocol {
    /// Shared log handle. Read-only from the test's perspective.
    pub shared: Arc<Mutex<Vec<SessionCall>>>,
    /// Number of successful `connect()` invocations.
    pub connect_count: Arc<Mutex<u64>>,
    /// If `true`, every `connect()` fails — exercises supervisor backoff.
    pub connect_fails: Arc<Mutex<bool>>,
}

impl SharedLogProtocol {
    /// New protocol with empty log and counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(Vec::new())),
            connect_count: Arc::new(Mutex::new(0)),
            connect_fails: Arc::new(Mutex::new(false)),
        }
    }

    /// Snapshot the recorded call log.
    #[must_use]
    pub fn calls(&self) -> Vec<SessionCall> {
        self.shared.lock().clone()
    }

    /// Number of successful `connect()` invocations.
    #[must_use]
    pub fn connect_count(&self) -> u64 {
        *self.connect_count.lock()
    }

    /// Toggle connect-failure mode.
    pub fn set_connect_fails(&self, fails: bool) {
        *self.connect_fails.lock() = fails;
    }
}

impl Default for SharedLogProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TunnelProtocol for SharedLogProtocol {
    async fn connect(
        &self,
        _endpoint: &Endpoint,
        _auth: &AuthConfig,
    ) -> Result<Box<dyn TunnelSession>> {
        if *self.connect_fails.lock() {
            return Err(spt_core::Error::NetworkUnreachable(
                "shared-log-mock".into(),
            ));
        }
        *self.connect_count.lock() += 1;
        let inner: Box<dyn TunnelSession> = Box::new(MockTunnelSession::new());
        Ok(Box::new(SharedLogSession {
            inner,
            log: Arc::clone(&self.shared),
        }))
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::ssh3()
    }

    fn name(&self) -> &'static str {
        "shared-log-mock"
    }
}

/// `TunnelSession` that records every call into a shared log before delegating
/// to an inner [`MockTunnelSession`].
pub struct SharedLogSession {
    inner: Box<dyn TunnelSession>,
    log: Arc<Mutex<Vec<SessionCall>>>,
}

#[async_trait]
impl TunnelSession for SharedLogSession {
    async fn open_local_forward(&mut self, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
        self.log
            .lock()
            .push(SessionCall::OpenLocal(spec.name.clone()));
        self.inner.open_local_forward(spec).await
    }

    async fn open_remote_forward(&mut self, spec: &RemoteForwardSpec) -> Result<ForwardHandle> {
        self.log
            .lock()
            .push(SessionCall::OpenRemote(spec.name.clone()));
        self.inner.open_remote_forward(spec).await
    }

    async fn open_udp_forward(&mut self, spec: &UdpForwardSpec) -> Result<ForwardHandle> {
        self.log
            .lock()
            .push(SessionCall::OpenUdp(spec.name.clone()));
        self.inner.open_udp_forward(spec).await
    }

    async fn keepalive(&mut self) -> Result<()> {
        self.log.lock().push(SessionCall::Keepalive);
        self.inner.keepalive().await
    }

    async fn close(self: Box<Self>) -> Result<()> {
        self.log.lock().push(SessionCall::Close);
        self.inner.close().await
    }

    fn session_info(&self) -> SessionInfo {
        self.inner.session_info()
    }
}
