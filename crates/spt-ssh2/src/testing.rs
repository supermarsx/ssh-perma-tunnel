//! Test fixtures for [`spt_ssh2`] consumers.
//!
//! Two helpers ship here:
//!
//! * [`MockSsh2Session`] — pure in-memory [`spt_protocol::TunnelSession`]
//!   recording every call. Useful for tests that want to verify *what* the
//!   supervisor asked the SSH2 backend to do without spinning up libssh2.
//! * [`RusshTestServer`] — a builder around an embedded [`russh`] server bound
//!   to ephemeral loopback. Exposed under the `testing` feature so end-to-end
//!   tests in sibling crates can target a real SSH2 endpoint without
//!   re-implementing the russh handler glue.
//!
//! Both helpers live behind `#[cfg(any(test, feature = "testing"))]`.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use spt_core::Result;
use spt_protocol::{
    ForwardHandle, ForwardId, ForwardState, LocalForwardSpec, RemoteForwardSpec, SessionInfo,
    TunnelSession, UdpForwardSpec,
};
use tokio::sync::{oneshot, watch};

// -----------------------------------------------------------------------------
// MockSsh2Session
// -----------------------------------------------------------------------------

/// One recorded `MockSsh2Session` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockSsh2Call {
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

/// In-memory [`TunnelSession`] mimicking the SSH2 backend's API surface
/// without linking libssh2.
///
/// ```
/// use spt_ssh2::testing::MockSsh2Session;
/// let s = MockSsh2Session::new();
/// assert!(s.calls().is_empty());
/// ```
pub struct MockSsh2Session {
    info: SessionInfo,
    calls: Arc<Mutex<Vec<MockSsh2Call>>>,
    open_forwards: Vec<MockForwardEntry>,
}

#[derive(Debug)]
struct MockForwardEntry {
    _state_tx: watch::Sender<ForwardState>,
    _close_rx_task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for MockSsh2Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockSsh2Session")
            .field("info", &self.info)
            .field("calls", &self.calls.lock().clone())
            .field("open_forwards", &self.open_forwards.len())
            .finish()
    }
}

impl Default for MockSsh2Session {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSsh2Session {
    /// New session with default canned [`SessionInfo`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            info: SessionInfo {
                backend: "ssh2".into(),
                peer_version: Some("SSH-2.0-mock_0".into()),
                negotiated: Some("aes256-gcm@openssh.com".into()),
                established_at: 0,
            },
            calls: Arc::new(Mutex::new(Vec::new())),
            open_forwards: Vec::new(),
        }
    }

    /// Override the canned [`SessionInfo`]. Useful when a test asserts on the
    /// `peer_version` / `negotiated` fields.
    #[must_use]
    pub fn with_info(mut self, info: SessionInfo) -> Self {
        self.info = info;
        self
    }

    /// Convenience: tag this session with a different `peer_version` while
    /// keeping every other field at its canned default.
    #[must_use]
    pub fn with_response(mut self, peer_version: impl Into<String>) -> Self {
        self.info.peer_version = Some(peer_version.into());
        self
    }

    /// Snapshot of the recorded call log.
    #[must_use]
    pub fn calls(&self) -> Vec<MockSsh2Call> {
        self.calls.lock().clone()
    }

    /// Shared handle to the call log — useful when the session has been moved
    /// into a `Box<dyn TunnelSession>` and the test still wants to read it.
    #[must_use]
    pub fn log_handle(&self) -> Arc<Mutex<Vec<MockSsh2Call>>> {
        Arc::clone(&self.calls)
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
        ForwardHandle::new(ForwardId::new(), name.to_owned(), state_rx, close_tx)
    }
}

#[async_trait]
impl TunnelSession for MockSsh2Session {
    async fn open_local_forward(&mut self, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
        self.calls
            .lock()
            .push(MockSsh2Call::OpenLocal(spec.name.clone()));
        Ok(self.make_handle(&spec.name))
    }

    async fn open_remote_forward(&mut self, spec: &RemoteForwardSpec) -> Result<ForwardHandle> {
        self.calls
            .lock()
            .push(MockSsh2Call::OpenRemote(spec.name.clone()));
        Ok(self.make_handle(&spec.name))
    }

    async fn open_udp_forward(&mut self, spec: &UdpForwardSpec) -> Result<ForwardHandle> {
        self.calls
            .lock()
            .push(MockSsh2Call::OpenUdp(spec.name.clone()));
        Ok(self.make_handle(&spec.name))
    }

    async fn keepalive(&mut self) -> Result<()> {
        self.calls.lock().push(MockSsh2Call::Keepalive);
        Ok(())
    }

    async fn close(self: Box<Self>) -> Result<()> {
        self.calls.lock().push(MockSsh2Call::Close);
        Ok(())
    }

    fn session_info(&self) -> SessionInfo {
        self.info.clone()
    }
}

/// Convenience: a fresh [`MockSsh2Session`] boxed as a [`TunnelSession`].
///
/// ```
/// use spt_ssh2::testing::fake_session;
/// let s = fake_session();
/// assert_eq!(s.session_info().backend, "ssh2");
/// ```
#[must_use]
pub fn fake_session() -> Box<dyn TunnelSession> {
    Box::new(MockSsh2Session::new())
}

// -----------------------------------------------------------------------------
// RusshTestServer
// -----------------------------------------------------------------------------

/// Builder around an embedded [`russh`] server bound to ephemeral loopback.
///
/// Each call to [`RusshTestServer::start`] binds a fresh `127.0.0.1:0`
/// listener, generates an Ed25519 host key, and accepts every auth method
/// configured on the builder. The handler accepts session channel opens and
/// echoes any data it receives back to the client — enough to exercise SSH2
/// banner/auth + a single channel for transport tests.
///
/// ```no_run
/// # async fn ex() {
/// use spt_ssh2::testing::RusshTestServer;
/// let running = RusshTestServer::new()
///     .with_password("user", "pw")
///     .start()
///     .await
///     .unwrap();
/// let _addr = running.addr;
/// running.shutdown().await;
/// # }
/// ```
#[cfg(feature = "testing")]
pub struct RusshTestServer {
    accepted_password: Option<(String, String)>,
    accept_any_pubkey: bool,
}

#[cfg(feature = "testing")]
impl Default for RusshTestServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "testing")]
impl RusshTestServer {
    /// New server accepting any pubkey by default.
    #[must_use]
    pub fn new() -> Self {
        Self {
            accepted_password: None,
            accept_any_pubkey: true,
        }
    }

    /// Accept the given `(user, password)` tuple via password auth.
    #[must_use]
    pub fn with_password(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.accepted_password = Some((user.into(), password.into()));
        self
    }

    /// Accept any pubkey presented by any user. This is the default; the
    /// method exists so callers can be explicit.
    #[must_use]
    pub fn with_authorized_pubkey_any(mut self) -> Self {
        self.accept_any_pubkey = true;
        self
    }

    /// Build a russh server config with a fresh ed25519 host key and reasonable
    /// timeouts.
    fn build_russh_config() -> russh::server::Config {
        russh::server::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(60)),
            auth_rejection_time: std::time::Duration::from_millis(100),
            auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
            keys: vec![russh_keys::key::KeyPair::generate_ed25519()],
            ..Default::default()
        }
    }

    /// Bind on `127.0.0.1:0`, spawn the accept loop, and return a handle to the
    /// running server.
    pub async fn start(self) -> std::io::Result<RunningRusshServer> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let cfg = Arc::new(Self::build_russh_config());
        let accepted = self.accepted_password;
        let any_pubkey = self.accept_any_pubkey;

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    incoming = listener.accept() => {
                        let Ok((sock, _)) = incoming else { break; };
                        let cfg = cfg.clone();
                        let h = TestHandler {
                            password: accepted.clone(),
                            any_pubkey,
                        };
                        tokio::spawn(russh::server::run_stream(cfg, sock, h));
                    }
                }
            }
        });

        Ok(RunningRusshServer {
            addr,
            host_key_fingerprint: "ed25519/ephemeral".into(),
            shutdown_tx: Some(shutdown_tx),
            task: Some(handle),
        })
    }
}

#[cfg(feature = "testing")]
struct TestHandler {
    password: Option<(String, String)>,
    any_pubkey: bool,
}

#[cfg(feature = "testing")]
#[async_trait]
impl russh::server::Handler for TestHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &russh_keys::key::PublicKey,
    ) -> std::result::Result<russh::server::Auth, Self::Error> {
        if self.any_pubkey {
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> std::result::Result<russh::server::Auth, Self::Error> {
        if let Some((u, p)) = &self.password {
            if u == user && p == password {
                return Ok(russh::server::Auth::Accept);
            }
        }
        Ok(russh::server::Auth::Reject {
            proceed_with_methods: None,
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _session: &mut russh::server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        session.data(channel, russh::CryptoVec::from(data.to_vec()));
        Ok(())
    }
}

/// Handle to a running [`RusshTestServer`].
#[cfg(feature = "testing")]
pub struct RunningRusshServer {
    /// The address the server is listening on (always loopback).
    pub addr: SocketAddr,
    /// Stable label for the host key (the actual key bytes are ephemeral). The
    /// SSH2 backend's trust path is exercised at a higher layer; this string
    /// is here for diagnostic output.
    pub host_key_fingerprint: String,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

#[cfg(feature = "testing")]
impl RunningRusshServer {
    /// Trigger shutdown and wait for the accept loop to exit.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }
}

#[cfg(feature = "testing")]
impl Drop for RunningRusshServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
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
    async fn mock_session_records_round_trip() {
        let mut s = MockSsh2Session::new().with_response("SSH-2.0-pretend");
        let log = s.log_handle();
        let h = s.open_local_forward(&local_spec("a")).await.unwrap();
        s.keepalive().await.unwrap();
        h.close().await;
        let boxed: Box<dyn TunnelSession> = Box::new(s);
        boxed.close().await.unwrap();
        let calls = log.lock().clone();
        assert_eq!(calls[0], MockSsh2Call::OpenLocal("a".into()));
        assert_eq!(calls[1], MockSsh2Call::Keepalive);
        assert_eq!(calls[2], MockSsh2Call::Close);
    }

    #[tokio::test]
    async fn fake_session_is_a_tunnel_session() {
        let s = fake_session();
        assert_eq!(s.session_info().backend, "ssh2");
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn russh_test_server_binds_loopback() {
        let server = RusshTestServer::new()
            .with_password("u", "pw")
            .start()
            .await
            .unwrap();
        assert!(server.addr.ip().is_loopback());
        server.shutdown().await;
    }
}
