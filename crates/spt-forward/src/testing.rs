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

    // ---- Extended testing-fixture coverage ----

    fn remote_spec(name: &str) -> RemoteForwardSpec {
        RemoteForwardSpec {
            name: name.to_owned(),
            listen: BindAddr::Tcp("127.0.0.1:0".parse().unwrap()),
            target: TargetAddr::new("h", 1),
            max_connections: None,
        }
    }

    fn udp_spec(name: &str) -> UdpForwardSpec {
        UdpForwardSpec {
            name: name.to_owned(),
            direction: spt_protocol::ForwardDirection::Local,
            listen: BindAddr::Tcp("127.0.0.1:0".parse().unwrap()),
            target: TargetAddr::new("h", 1),
            idle_timeout_secs: 30,
            max_flows: None,
        }
    }

    fn endpoint() -> spt_protocol::Endpoint {
        spt_protocol::Endpoint::new("example.com", 22)
    }

    fn auth() -> spt_auth::AuthConfig {
        spt_auth::AuthConfig::new("alice", Vec::new())
    }

    #[tokio::test]
    async fn protocol_connect_increments_count() {
        let proto = MockTunnelProtocol::new();
        assert_eq!(proto.connect_count(), 0);
        let _s1 = proto.connect(&endpoint(), &auth()).await.unwrap();
        let _s2 = proto.connect(&endpoint(), &auth()).await.unwrap();
        assert_eq!(proto.connect_count(), 2);
    }

    #[tokio::test]
    async fn protocol_connect_fail_mode() {
        let proto = MockTunnelProtocol::new();
        proto.set_connect_fails(true);
        let r = proto.connect(&endpoint(), &auth()).await;
        assert!(r.is_err());
        assert_eq!(proto.connect_count(), 0);
        proto.set_connect_fails(false);
        let _ = proto.connect(&endpoint(), &auth()).await.unwrap();
        assert_eq!(proto.connect_count(), 1);
    }

    #[test]
    fn protocol_metadata() {
        let proto = MockTunnelProtocol::new();
        assert_eq!(proto.name(), "mock");
        let caps = proto.capabilities();
        assert!(caps.local_udp);
        assert!(caps.local_tcp);
    }

    #[test]
    fn protocol_default_is_new() {
        let a = MockTunnelProtocol::new();
        let b = MockTunnelProtocol::default();
        assert_eq!(a.connect_count(), b.connect_count());
    }

    #[test]
    fn session_default_is_new() {
        let a = MockTunnelSession::new();
        let b = MockTunnelSession::default();
        assert_eq!(a.keepalive_count(), b.keepalive_count());
    }

    #[tokio::test]
    async fn session_keepalive_count_increments() {
        let mut s = MockTunnelSession::new();
        assert_eq!(s.keepalive_count(), 0);
        s.keepalive().await.unwrap();
        s.keepalive().await.unwrap();
        assert_eq!(s.keepalive_count(), 2);
    }

    #[tokio::test]
    async fn session_info_round_trip() {
        let s = MockTunnelSession::new();
        let info = s.session_info();
        assert_eq!(info.backend, "mock");
        assert_eq!(info.peer_version.as_deref(), Some("mock-0"));
    }

    #[tokio::test]
    async fn session_close_returns_ok() {
        let s: Box<dyn TunnelSession> = Box::new(MockTunnelSession::new());
        s.close().await.unwrap();
    }

    #[tokio::test]
    async fn session_opens_remote_and_udp() {
        let mut s = MockTunnelSession::new();
        let r = s.open_remote_forward(&remote_spec("r")).await.unwrap();
        let u = s.open_udp_forward(&udp_spec("u")).await.unwrap();
        assert_eq!(r.name(), "r");
        assert_eq!(u.name(), "u");
        assert_eq!(r.state(), ForwardState::Active);
        assert_eq!(u.state(), ForwardState::Active);
        r.close().await;
        u.close().await;
    }

    #[tokio::test]
    async fn recording_session_logs_all_methods() {
        let inner: Box<dyn TunnelSession> = Box::new(MockTunnelSession::new());
        let mut rec = RecordingTunnelSession::new(inner);
        let _l = rec.open_local_forward(&local_spec("L")).await.unwrap();
        let _r = rec.open_remote_forward(&remote_spec("R")).await.unwrap();
        let _u = rec.open_udp_forward(&udp_spec("U")).await.unwrap();
        rec.keepalive().await.unwrap();
        let pre_close = rec.calls();
        assert_eq!(pre_close.len(), 4);
        assert_eq!(pre_close[0], SessionCall::OpenLocal("L".into()));
        assert_eq!(pre_close[1], SessionCall::OpenRemote("R".into()));
        assert_eq!(pre_close[2], SessionCall::OpenUdp("U".into()));
        assert_eq!(pre_close[3], SessionCall::Keepalive);

        let handle = rec.log_handle();
        Box::new(rec).close().await.unwrap();
        let final_log = handle.lock().clone();
        assert!(final_log.contains(&SessionCall::Close));
    }

    #[test]
    fn recording_session_info_delegates() {
        let inner: Box<dyn TunnelSession> = Box::new(MockTunnelSession::new());
        let rec = RecordingTunnelSession::new(inner);
        let info = rec.session_info();
        assert_eq!(info.backend, "mock");
    }

    #[test]
    fn recording_session_debug_includes_calls() {
        let inner: Box<dyn TunnelSession> = Box::new(MockTunnelSession::new());
        let rec = RecordingTunnelSession::new(inner);
        let dbg = format!("{rec:?}");
        assert!(dbg.contains("RecordingTunnelSession"));
        assert!(dbg.contains("calls"));
    }

    #[test]
    fn udp_endpoint_new_and_pending() {
        let ep = MockUdpEndpoint::new();
        assert_eq!(ep.pending(), 0);
        assert!(ep.recv().is_none());
    }

    #[test]
    fn udp_endpoint_clone_shares_state() {
        let ep1 = MockUdpEndpoint::new();
        let ep2 = ep1.clone();
        ep1.send(b"data".to_vec());
        // The clone is shallow over Arc<Mutex<..>>; ep1.outbox is shared with
        // ep2.outbox. Reading from inbox on either side still yields None
        // (standalone endpoint has unwired queues).
        assert!(ep1.recv().is_none());
        assert!(ep2.recv().is_none());
    }

    #[test]
    #[should_panic(expected = "non-terminal")]
    fn assert_no_pending_handles_panics_on_active() {
        let (state_tx, state_rx) = watch::channel(ForwardState::Active);
        let (close_tx, _close_rx) = oneshot::channel::<()>();
        let h = ForwardHandle::new(ProtocolForwardId::new(), "stuck", state_rx, close_tx);
        let _keep = state_tx;
        assert_no_pending_handles(&[h]);
    }

    #[tokio::test]
    async fn assert_no_pending_handles_passes_when_stopped() {
        let (state_tx, state_rx) = watch::channel(ForwardState::Active);
        let (close_tx, _close_rx) = oneshot::channel::<()>();
        let h = ForwardHandle::new(ProtocolForwardId::new(), "ok", state_rx, close_tx);
        state_tx.send(ForwardState::Stopped).unwrap();
        tokio::task::yield_now().await;
        assert_no_pending_handles(&[h]);
    }
}
