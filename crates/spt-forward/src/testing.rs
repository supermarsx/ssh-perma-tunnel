//! Test fixtures for `spt-forward` consumers.
//!
//! Behind `#[cfg(any(test, feature = "testing"))]` so other crates' tests
//! (notably `spt-supervisor`) can reuse them without copy-paste.
//!
//! Helpers shipped here:
//!
//! * [`MockTunnelProtocol`] / [`MockTunnelSession`] — in-memory implementations
//!   of [`spt_protocol::TunnelProtocol`] / [`spt_protocol::TunnelSession`] that
//!   prove the runner and the helpers compose without SSH.
//! * [`RecordingTunnelSession`] — wraps any [`TunnelSession`] and records every
//!   `open_*_forward` / `keepalive` call, useful when a test needs to assert
//!   *what* the supervisor asked the backend to do.
//! * [`MockUdpEndpoint`] — a paired pair of [`std::collections::VecDeque`]s
//!   over [`parking_lot::Mutex`] that mimics a tiny send/recv UDP queue for
//!   tests that don't want to bind real sockets.
//! * [`assert_no_pending_handles`] — verifies every [`ForwardHandle`] in a
//!   slice has reached a terminal [`ForwardState`].

use std::collections::VecDeque;
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
///
/// Each successful [`TunnelProtocol::connect`] hands back a fresh
/// [`MockTunnelSession`]. Failure injection is opt-in via
/// [`MockTunnelProtocol::set_connect_fails`].
///
/// ```
/// use spt_forward::testing::MockTunnelProtocol;
/// let proto = MockTunnelProtocol::new();
/// assert_eq!(proto.connect_count(), 0);
/// ```
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
///
/// ```
/// use spt_forward::testing::MockTunnelSession;
/// let s = MockTunnelSession::new();
/// assert_eq!(s.keepalive_count(), 0);
/// ```
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
        ForwardHandle::new(
            ProtocolForwardId::new(),
            name.to_owned(),
            state_rx,
            close_tx,
        )
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

// -----------------------------------------------------------------------------
// RecordingTunnelSession
// -----------------------------------------------------------------------------

/// Discriminated record of one `TunnelSession` call, captured by
/// [`RecordingTunnelSession`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCall {
    /// `open_local_forward` invoked with this forward name.
    OpenLocal(String),
    /// `open_remote_forward` invoked with this forward name.
    OpenRemote(String),
    /// `open_udp_forward` invoked with this forward name.
    OpenUdp(String),
    /// `keepalive` invoked.
    Keepalive,
    /// `close` invoked.
    Close,
}

/// Wraps any [`TunnelSession`] and records every method call into a shared
/// [`Vec`].
///
/// Use [`RecordingTunnelSession::calls`] from the test to read the captured
/// trail; the inner [`Vec`] is held under [`parking_lot::Mutex`] and exposed as
/// a clone so the assertion side never blocks the wrapped session.
///
/// ```
/// use spt_forward::testing::{MockTunnelSession, RecordingTunnelSession};
/// let inner = Box::new(MockTunnelSession::new());
/// let rec = RecordingTunnelSession::new(inner);
/// assert!(rec.calls().is_empty());
/// ```
pub struct RecordingTunnelSession {
    inner: Box<dyn TunnelSession>,
    log: Arc<Mutex<Vec<SessionCall>>>,
}

impl std::fmt::Debug for RecordingTunnelSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingTunnelSession")
            .field("calls", &self.log.lock().clone())
            .finish()
    }
}

impl RecordingTunnelSession {
    /// Wrap `inner`; the returned recorder defers every call to it.
    #[must_use]
    pub fn new(inner: Box<dyn TunnelSession>) -> Self {
        Self {
            inner,
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Snapshot of the recorded call log.
    #[must_use]
    pub fn calls(&self) -> Vec<SessionCall> {
        self.log.lock().clone()
    }

    /// Shared handle to the call log — useful when consuming `Box<Self>` into
    /// a `Box<dyn TunnelSession>` and still wanting to read the log later.
    #[must_use]
    pub fn log_handle(&self) -> Arc<Mutex<Vec<SessionCall>>> {
        Arc::clone(&self.log)
    }
}

#[async_trait]
impl TunnelSession for RecordingTunnelSession {
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

// -----------------------------------------------------------------------------
// MockUdpEndpoint
// -----------------------------------------------------------------------------

/// Tiny in-memory paired UDP endpoint useful for tests that need to feed
/// datagrams into a producer/consumer without binding sockets.
///
/// `inbox` is the queue *the test* reads from; `outbox` is the queue *the test*
/// writes to. The wrapped code under test uses the opposite ends — wire two
/// sides via [`MockUdpEndpoint::connected_pair`].
///
/// ```
/// use spt_forward::testing::MockUdpEndpoint;
/// let (a, b) = MockUdpEndpoint::connected_pair();
/// a.send(b"hi".to_vec());
/// assert_eq!(b.recv(), Some(b"hi".to_vec()));
/// ```
#[derive(Debug, Clone, Default)]
pub struct MockUdpEndpoint {
    inbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl MockUdpEndpoint {
    /// Standalone endpoint with empty queues.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a pair of endpoints whose `outbox`/`inbox` are wired such that
    /// `a.send(...)` is observed by `b.recv()` and vice versa.
    #[must_use]
    pub fn connected_pair() -> (Self, Self) {
        let a_to_b: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::default();
        let b_to_a: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::default();
        let a = Self {
            inbox: Arc::clone(&b_to_a),
            outbox: Arc::clone(&a_to_b),
        };
        let b = Self {
            inbox: a_to_b,
            outbox: b_to_a,
        };
        (a, b)
    }

    /// Push a datagram to the peer's inbox.
    pub fn send(&self, datagram: Vec<u8>) {
        self.outbox.lock().push_back(datagram);
    }

    /// Pop the next datagram from this endpoint's inbox, or `None` if empty.
    #[must_use]
    pub fn recv(&self) -> Option<Vec<u8>> {
        self.inbox.lock().pop_front()
    }

    /// Number of datagrams waiting in the inbox.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.inbox.lock().len()
    }
}

// -----------------------------------------------------------------------------
// Assertions
// -----------------------------------------------------------------------------

/// Assert that every handle in `handles` has reached a terminal
/// [`ForwardState`] (i.e. [`ForwardState::is_terminal`] returns `true`).
///
/// Panics with a descriptive message naming each non-terminal handle.
///
/// ```no_run
/// use spt_forward::testing::assert_no_pending_handles;
/// let handles: Vec<spt_protocol::ForwardHandle> = vec![];
/// assert_no_pending_handles(&handles);
/// ```
pub fn assert_no_pending_handles(handles: &[ForwardHandle]) {
    let pending: Vec<_> = handles
        .iter()
        .filter(|h| !h.state().is_terminal())
        .map(|h| format!("{} ({:?})", h.name(), h.state()))
        .collect();
    assert!(
        pending.is_empty(),
        "expected every forward to be terminal; non-terminal: [{}]",
        pending.join(", ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_core::BindAddr;
    use spt_protocol::endpoint::TargetAddr;

    fn local_spec(name: &str) -> LocalForwardSpec {
        LocalForwardSpec {
            name: name.to_owned(),
            listen: BindAddr::Tcp("127.0.0.1:0".parse().unwrap()),
            target: TargetAddr::new("h", 1),
            max_connections: None,
        }
    }

    #[tokio::test]
    async fn recording_session_logs_calls() {
        let inner: Box<dyn TunnelSession> = Box::new(MockTunnelSession::new());
        let mut rec = RecordingTunnelSession::new(inner);
        let _h = rec.open_local_forward(&local_spec("a")).await.unwrap();
        rec.keepalive().await.unwrap();
        let calls = rec.calls();
        assert_eq!(calls[0], SessionCall::OpenLocal("a".into()));
        assert_eq!(calls[1], SessionCall::Keepalive);
    }

    #[test]
    fn udp_endpoint_pair_round_trip() {
        let (a, b) = MockUdpEndpoint::connected_pair();
        a.send(b"x".to_vec());
        a.send(b"yz".to_vec());
        assert_eq!(b.pending(), 2);
        assert_eq!(b.recv().unwrap(), b"x");
        assert_eq!(b.recv().unwrap(), b"yz");
        assert!(b.recv().is_none());
        b.send(b"reply".to_vec());
        assert_eq!(a.recv().unwrap(), b"reply");
    }

    #[tokio::test]
    async fn assert_no_pending_handles_passes_after_close() {
        let mut s = MockTunnelSession::new();
        let h = s.open_local_forward(&local_spec("z")).await.unwrap();
        h.close().await;
        assert_no_pending_handles(&[]);
    }
}
