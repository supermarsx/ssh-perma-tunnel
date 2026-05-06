//! Test fixtures: an in-memory [`spt_protocol::TunnelProtocol`] / `TunnelSession`
//! pair that proves the runner and the helpers compose without SSH.
//!
//! Exposed from the crate root behind `#[cfg(any(test, feature = "testing"))]`
//! so other crates' tests (notably spt-supervisor) can reuse it.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use spt_auth::AuthConfig;
use spt_core::Result;
use spt_protocol::{
    Endpoint, ForwardHandle, ForwardId as ProtocolForwardId, ForwardState, LocalForwardSpec,
    ProtocolCapabilities, RemoteForwardSpec, SessionInfo, TunnelProtocol, TunnelSession,
    UdpForwardSpec,
};
use tokio::sync::{oneshot, watch};

/// In-memory tunnel protocol useful for tests.
#[derive(Debug, Default, Clone)]
pub struct MockTunnelProtocol {
    /// If `true`, every `connect()` call fails — exercises supervisor backoff.
    pub connect_fails: Arc<Mutex<bool>>,
    /// Counter of successful connects.
    pub connect_count: Arc<Mutex<u64>>,
}

impl MockTunnelProtocol {
    /// New protocol with no failure-injection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Toggle connect-failure mode.
    pub fn set_connect_fails(&self, fails: bool) {
        *self.connect_fails.lock() = fails;
    }

    /// Number of times `connect` returned a session.
    pub fn connect_count(&self) -> u64 {
        *self.connect_count.lock()
    }
}

#[async_trait]
impl TunnelProtocol for MockTunnelProtocol {
    async fn connect(
        &self,
        _endpoint: &Endpoint,
        _auth: &AuthConfig,
    ) -> Result<Box<dyn TunnelSession>> {
        if *self.connect_fails.lock() {
            return Err(spt_core::Error::NetworkUnreachable("mock".into()));
        }
        *self.connect_count.lock() += 1;
        Ok(Box::new(MockTunnelSession::new()))
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::ssh3()
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

/// In-memory tunnel session useful for tests.
#[derive(Debug)]
pub struct MockTunnelSession {
    info: SessionInfo,
    open_forwards: Vec<MockForwardEntry>,
    keepalive_count: u64,
}

#[derive(Debug)]
struct MockForwardEntry {
    _state_tx: watch::Sender<ForwardState>,
    _close_rx_task: tokio::task::JoinHandle<()>,
}

impl Default for MockTunnelSession {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTunnelSession {
    /// Construct a fresh session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            info: SessionInfo {
                backend: "mock".into(),
                peer_version: Some("mock-0".into()),
                negotiated: Some("mock-cipher".into()),
                established_at: 0,
            },
            open_forwards: Vec::new(),
            keepalive_count: 0,
        }
    }

    /// Number of keepalive() calls observed.
    #[must_use]
    pub fn keepalive_count(&self) -> u64 {
        self.keepalive_count
    }

    fn make_handle(&mut self, name: &str) -> ForwardHandle {
        let (state_tx, state_rx) = watch::channel(ForwardState::Active);
        let (close_tx, close_rx) = oneshot::channel();
        let state_tx_for_task = state_tx.clone();
        let task = tokio::spawn(async move {
            let _ = close_rx.await;
            let _ = state_tx_for_task.send(ForwardState::Stopped);
        });
        self.open_forwards.push(MockForwardEntry {
            _state_tx: state_tx,
            _close_rx_task: task,
        });
        ForwardHandle::new(ProtocolForwardId::new(), name.to_owned(), state_rx, close_tx)
    }
}

#[async_trait]
impl TunnelSession for MockTunnelSession {
    async fn open_local_forward(&mut self, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
        Ok(self.make_handle(&spec.name))
    }

    async fn open_remote_forward(&mut self, spec: &RemoteForwardSpec) -> Result<ForwardHandle> {
        Ok(self.make_handle(&spec.name))
    }

    async fn open_udp_forward(&mut self, spec: &UdpForwardSpec) -> Result<ForwardHandle> {
        Ok(self.make_handle(&spec.name))
    }

    async fn keepalive(&mut self) -> Result<()> {
        self.keepalive_count += 1;
        Ok(())
    }

    async fn close(self: Box<Self>) -> Result<()> {
        Ok(())
    }

    fn session_info(&self) -> SessionInfo {
        self.info.clone()
    }
}
