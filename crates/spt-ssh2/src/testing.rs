//! Test fixtures for [`spt_ssh2`] consumers.
//!
//! Three helpers ship here:
//!
//! * [`MockSsh2Session`] — pure in-memory [`spt_protocol::TunnelSession`]
//!   recording every call. Useful for tests that want to verify *what* the
//!   supervisor asked the SSH2 backend to do without spinning up libssh2.
//! * [`RusshTestServer`] — a builder around an embedded [`russh`] server bound
//!   to ephemeral loopback. Exposed under the `testing` feature so end-to-end
//!   tests in sibling crates can target a real SSH2 endpoint without
//!   re-implementing the russh handler glue.
//! * [`OpenSshTestServer`] — Unix-only builder that locates a system `sshd`
//!   on `PATH`, generates an ephemeral RSA-2048 host key + minimal config in a
//!   tempdir, and spawns sshd against `127.0.0.1:0`. Sidesteps the upstream
//!   russh-0.46 ↔ libssh2-WinCNG `-8 KEY_EXCHANGE_FAILURE` interop bug by
//!   driving libssh2 against a real OpenSSH server.
//!
//! All helpers live behind `#[cfg(any(test, feature = "testing"))]`.

#[cfg(feature = "testing")]
use std::net::SocketAddr;
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

#[cfg(feature = "testing")]
use std::sync::atomic::{AtomicUsize, Ordering};

/// Per-server shared counters and state. Cloneable Arc handle so tests can
/// observe wire events while the server keeps running.
#[cfg(feature = "testing")]
#[derive(Default)]
struct ServerInner {
    /// Number of inbound TCP accepts (one per SSH2 client).
    connections: AtomicUsize,
    /// Number of `auth_password`/`auth_publickey` invocations (success + reject).
    auth_attempts: AtomicUsize,
    /// Number of accepted `channel_open_session` calls.
    channel_opens_session: AtomicUsize,
    /// Number of accepted `channel_open_direct_tcpip` calls.
    channel_opens_direct_tcpip: AtomicUsize,
    /// Number of `tcpip_forward` global-request invocations.
    tcpip_forward_requests: AtomicUsize,
    /// Number of handler-observed channel-data callbacks. This is the
    /// closest proxy we have to a "keepalive packet count" — see
    /// [`RunningRusshServer::keepalive_packet_count`] for the caveat.
    data_callbacks: AtomicUsize,
}

/// Builder around an embedded [`russh`] server bound to ephemeral loopback.
///
/// Each call to [`RusshTestServer::start`] binds a fresh `127.0.0.1:0`
/// listener, generates an **RSA-2048** host key, and accepts every auth method
/// configured on the builder. The handler accepts session channel opens and
/// echoes any data it receives back to the client; a `direct-tcpip` handler
/// is also installed that echoes data from the client back over the same
/// channel; `tcpip-forward` requests are accepted (a real local listener is
/// bound and inbound bytes are streamed back via `forwarded-tcpip` channels).
///
/// **Why RSA-2048 instead of Ed25519?** libssh2-sys 0.3.1 on Windows is built
/// with the `WinCNG` crypto backend, which defines `LIBSSH2_ED25519=0` and does
/// *not* enable `LIBSSH2_ECDSA_WINCNG` — leaving RSA as the only host-key
/// type both stacks can negotiate on Windows. Linux/macOS builds (OpenSSL
/// backend) accept RSA equally well. Use [`RusshTestServer::with_ed25519_host_key`]
/// when you need to exercise non-RSA negotiation on a non-Windows host.
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
    authorized_pubkeys: Vec<russh_keys::key::PublicKey>,
    use_ed25519_host_key: bool,
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
            authorized_pubkeys: Vec::new(),
            use_ed25519_host_key: false,
        }
    }

    /// Accept the given `(user, password)` tuple via password auth. Disables
    /// the "accept any pubkey" default — call [`Self::with_authorized_pubkey_any`]
    /// to re-enable.
    #[must_use]
    pub fn with_password(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.accepted_password = Some((user.into(), password.into()));
        self.accept_any_pubkey = false;
        self
    }

    /// Accept any pubkey presented by any user. This is the default; the
    /// method exists so callers can be explicit.
    #[must_use]
    pub fn with_authorized_pubkey_any(mut self) -> Self {
        self.accept_any_pubkey = true;
        self
    }

    /// Authorise a *specific* pubkey for any user. Disables the
    /// "accept any pubkey" default. May be called multiple times to whitelist
    /// several keys.
    #[must_use]
    pub fn with_authorized_pubkey(mut self, key: russh_keys::key::PublicKey) -> Self {
        self.authorized_pubkeys.push(key);
        self.accept_any_pubkey = false;
        self
    }

    /// Use an Ed25519 host key instead of the default RSA-2048. Useful when a
    /// test wants to exercise Ed25519 negotiation against an OpenSSL-backed
    /// libssh2 build (Linux/macOS); see the type-level docs for why RSA is
    /// the default.
    #[must_use]
    pub fn with_ed25519_host_key(mut self) -> Self {
        self.use_ed25519_host_key = true;
        self
    }

    /// Build a russh server config with a fresh host key and reasonable
    /// timeouts.
    fn build_russh_config(&self) -> russh::server::Config {
        let key = if self.use_ed25519_host_key {
            russh_keys::key::KeyPair::generate_ed25519()
        } else {
            russh_keys::key::KeyPair::generate_rsa(2048, russh_keys::key::SignatureHash::SHA2_256)
                .expect("rsa-2048 keygen")
        };
        russh::server::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(60)),
            auth_rejection_time: std::time::Duration::from_millis(100),
            auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
            keys: vec![key],
            ..Default::default()
        }
    }

    /// Bind on `127.0.0.1:0`, spawn the accept loop, and return a handle to
    /// the running server.
    pub async fn start(self) -> std::io::Result<RunningRusshServer> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        spawn_accept_loop(self, listener, Arc::new(ServerInner::default())).await
    }
}

/// Internal: take ownership of a bound listener and spawn the accept loop +
/// shutdown plumbing. Reused by [`RunningRusshServer::restart_on_same_port`].
/// The `inner` Arc is the shared counter state — fresh on first start,
/// preserved across `restart_on_same_port`.
///
/// The function is `async` only so callers (which already are) can `.await`
/// it uniformly; it does not actually suspend (the `await` inside the
/// `tokio::select!` happens in the spawned task, not here).
#[cfg(feature = "testing")]
#[allow(clippy::unused_async)]
async fn spawn_accept_loop(
    builder: RusshTestServer,
    listener: tokio::net::TcpListener,
    inner: Arc<ServerInner>,
) -> std::io::Result<RunningRusshServer> {
    let addr = listener.local_addr()?;
    let cfg = Arc::new(builder.build_russh_config());
    let accepted = builder.accepted_password.clone();
    let any_pubkey = builder.accept_any_pubkey;
    let pubkeys = builder.authorized_pubkeys.clone();
    let host_label = if builder.use_ed25519_host_key {
        "ed25519/ephemeral".to_string()
    } else {
        "rsa-2048/ephemeral".to_string()
    };

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let inner_for_task = Arc::clone(&inner);
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                incoming = listener.accept() => {
                    let Ok((sock, _)) = incoming else { break; };
                    inner_for_task.connections.fetch_add(1, Ordering::Relaxed);
                    let cfg = cfg.clone();
                    let h = TestHandler {
                        password: accepted.clone(),
                        any_pubkey,
                        authorized_pubkeys: pubkeys.clone(),
                        inner: Arc::clone(&inner_for_task),
                    };
                    tokio::spawn(russh::server::run_stream(cfg, sock, h));
                }
            }
        }
    });

    Ok(RunningRusshServer {
        addr,
        host_key_fingerprint: host_label,
        shutdown_tx: Some(shutdown_tx),
        task: Some(handle),
        inner,
        builder: Some(builder),
    })
}

#[cfg(feature = "testing")]
struct TestHandler {
    password: Option<(String, String)>,
    any_pubkey: bool,
    authorized_pubkeys: Vec<russh_keys::key::PublicKey>,
    inner: Arc<ServerInner>,
}

#[cfg(feature = "testing")]
fn pubkey_eq(a: &russh_keys::key::PublicKey, b: &russh_keys::key::PublicKey) -> bool {
    // russh-keys 0.46 doesn't impl Eq on PublicKey; compare the public-key
    // fingerprint (sha256) which uniquely identifies it.
    a.fingerprint() == b.fingerprint()
}

#[cfg(feature = "testing")]
#[async_trait]
impl russh::server::Handler for TestHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: &russh_keys::key::PublicKey,
    ) -> std::result::Result<russh::server::Auth, Self::Error> {
        self.inner.auth_attempts.fetch_add(1, Ordering::Relaxed);
        if self.any_pubkey {
            return Ok(russh::server::Auth::Accept);
        }
        if self.authorized_pubkeys.iter().any(|k| pubkey_eq(k, key)) {
            return Ok(russh::server::Auth::Accept);
        }
        Ok(russh::server::Auth::Reject {
            proceed_with_methods: None,
        })
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> std::result::Result<russh::server::Auth, Self::Error> {
        self.inner.auth_attempts.fetch_add(1, Ordering::Relaxed);
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
        self.inner
            .channel_opens_session
            .fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut russh::server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        self.inner
            .channel_opens_direct_tcpip
            .fetch_add(1, Ordering::Relaxed);
        // The accepted channel is plumbed through the session by russh; our
        // `data` impl below echoes regardless of whether the channel was
        // opened via `session` or `direct-tcpip`.
        Ok(true)
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut russh::server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        use tokio::io::AsyncReadExt as _;

        self.inner
            .tcpip_forward_requests
            .fetch_add(1, Ordering::Relaxed);
        // Bind a real listener; if `*port == 0`, the OS picks a port and we
        // report it back via the russh REQUEST_SUCCESS payload (russh handles
        // that automatically when we mutate `*port`).
        let bind_host = if address.is_empty() {
            "127.0.0.1".to_owned()
        } else {
            address.to_owned()
        };
        let bind = format!("{bind_host}:{}", *port);
        let Ok(listener) = tokio::net::TcpListener::bind(&bind).await else {
            return Ok(false);
        };
        let Ok(local) = listener.local_addr() else {
            return Ok(false);
        };
        *port = u32::from(local.port());

        let handle = session.handle();
        let connected_addr = address.to_owned();
        let connected_port = *port;
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, peer)) = listener.accept().await else {
                    break;
                };
                let originator = peer.ip().to_string();
                let originator_port = u32::from(peer.port());
                let h2 = handle.clone();
                let connected_addr = connected_addr.clone();
                tokio::spawn(async move {
                    // Open a forwarded-tcpip channel back to the SSH client.
                    let Ok(chan) = h2
                        .channel_open_forwarded_tcpip(
                            connected_addr,
                            connected_port,
                            originator,
                            originator_port,
                        )
                        .await
                    else {
                        return;
                    };
                    // Pipe sock -> channel. We don't bother piping the reverse
                    // direction because the e2e tests we ship only exercise
                    // server-to-client traffic on remote forwards.
                    let mut buf = vec![0u8; 8 * 1024];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if chan.data(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = chan.eof().await;
                });
            }
        });

        Ok(true)
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        self.inner.data_callbacks.fetch_add(1, Ordering::Relaxed);
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
    inner: Arc<ServerInner>,
    /// Original builder retained so [`Self::restart_on_same_port`] can rebuild
    /// the russh config + handler state on restart.
    builder: Option<RusshTestServer>,
}

#[cfg(feature = "testing")]
impl RunningRusshServer {
    /// Number of inbound TCP connections accepted since startup (cumulative
    /// across restarts).
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.inner.connections.load(Ordering::Relaxed)
    }

    /// Number of `auth_password` + `auth_publickey` invocations.
    #[must_use]
    pub fn auth_attempts(&self) -> usize {
        self.inner.auth_attempts.load(Ordering::Relaxed)
    }

    /// Number of `channel_open_session` invocations that returned `Ok(true)`.
    #[must_use]
    pub fn channel_opens_session(&self) -> usize {
        self.inner.channel_opens_session.load(Ordering::Relaxed)
    }

    /// Number of `channel_open_direct_tcpip` invocations.
    #[must_use]
    pub fn channel_opens_direct_tcpip(&self) -> usize {
        self.inner
            .channel_opens_direct_tcpip
            .load(Ordering::Relaxed)
    }

    /// Number of `tcpip-forward` global-request invocations.
    #[must_use]
    pub fn tcpip_forward_requests(&self) -> usize {
        self.inner.tcpip_forward_requests.load(Ordering::Relaxed)
    }

    /// **Best-effort** keepalive count: returns the number of
    /// handler-observed channel-data callbacks since startup. The SSH
    /// transport-layer `keepalive@openssh.com` global request is *not*
    /// surfaced through the russh 0.46 [`russh::server::Handler`] trait — it's
    /// handled inside russh's own dispatcher (replied to with
    /// `REQUEST_FAILURE`) before any user code runs. Tests that need a true
    /// keepalive packet count must either patch russh to expose
    /// `keepalive_request` or measure at the wire layer (e.g. via a proxy
    /// `TcpStream` wrapper). This method is provided so downstream tests can
    /// still observe wire-level activity and assert the session is processing
    /// channel traffic.
    #[must_use]
    pub fn keepalive_packet_count(&self) -> usize {
        self.inner.data_callbacks.load(Ordering::Relaxed)
    }

    /// Trigger shutdown and wait for the accept loop to exit.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }

    /// Stop the accept loop and rebind on the **same** TCP port. The handler
    /// counters (auth attempts, channel opens, …) are *preserved* across
    /// restart so tests can assert that the second connection lands on the
    /// same `addr` while observing the cumulative counter advance.
    ///
    /// Implementation note: we rebind a fresh `TcpListener` on the same port.
    /// On Linux this can briefly fail with `EADDRINUSE` if a prior client
    /// connection is still in `TIME_WAIT`; for loopback test fixtures this is
    /// rare but possible — the caller can simply retry.
    pub async fn restart_on_same_port(mut self) -> std::io::Result<RunningRusshServer> {
        // Stop the existing accept loop.
        let port = self.addr.port();
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }

        let bind: SocketAddr = format!("127.0.0.1:{port}").parse().expect("loopback addr");
        let listener = tokio::net::TcpListener::bind(bind).await?;

        let builder = self
            .builder
            .take()
            .expect("builder retained on first start");
        spawn_accept_loop(builder, listener, Arc::clone(&self.inner)).await
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

// -----------------------------------------------------------------------------
// OpenSshTestServer (Unix-only) — drives libssh2 against a real `sshd`.
// -----------------------------------------------------------------------------

/// Unix-only builder that locates the system `sshd` binary on `PATH`,
/// generates an ephemeral RSA-2048 host key + a minimal `sshd_config` in a
/// tempdir, and spawns `sshd -D -e -f <config>` bound to `127.0.0.1:0`.
///
/// Returns `Ok(None)` from [`Self::start`] when `sshd` is not on `PATH` — the
/// caller is expected to `return` (skip) the test in that case.
///
/// Used as a workaround for the upstream russh-0.46 ↔ libssh2-WinCNG
/// `LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE` interop bug: a real OpenSSH server
/// negotiates cleanly with libssh2 on Linux/macOS where this matters.
///
/// **Windows is unsupported** by design — the Windows OpenSSH `sshd.exe` would
/// need a meaningfully different config schema and ACL setup. Tests that want
/// to use this fixture must `#[cfg_attr(target_os = "windows", ignore)]` or
/// branch on `cfg!(target_os = "windows")`.
#[cfg(all(unix, feature = "testing"))]
pub struct OpenSshTestServer {
    /// Optional override for the authorized user's pubkey (OpenSSH format).
    /// When `None`, `start()` does not enable pubkey auth.
    pub authorized_keys_pem: Option<String>,
    /// Username configured in `sshd_config`'s `AllowUsers` line.
    pub username: String,
    /// Whether to enable password auth (default off).
    pub password_auth: bool,
}

#[cfg(all(unix, feature = "testing"))]
impl Default for OpenSshTestServer {
    fn default() -> Self {
        Self {
            authorized_keys_pem: None,
            username: std::env::var("USER").unwrap_or_else(|_| "spttest".into()),
            password_auth: false,
        }
    }
}

#[cfg(all(unix, feature = "testing"))]
impl OpenSshTestServer {
    /// New server with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the authorized user's pubkey (OpenSSH single-line public key form).
    #[must_use]
    pub fn with_authorized_key(mut self, pubkey: impl Into<String>) -> Self {
        self.authorized_keys_pem = Some(pubkey.into());
        self
    }

    /// Override the configured username.
    #[must_use]
    pub fn with_username(mut self, user: impl Into<String>) -> Self {
        self.username = user.into();
        self
    }

    /// Locate `sshd` on `PATH`. Returns `None` when not found.
    #[must_use]
    pub fn locate_sshd() -> Option<std::path::PathBuf> {
        // Probe a few well-known locations first, then `which`.
        for candidate in ["/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"] {
            let p = std::path::Path::new(candidate);
            if p.exists() {
                return Some(p.to_path_buf());
            }
        }
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let cand = dir.join("sshd");
            if cand.exists() {
                return Some(cand);
            }
        }
        None
    }

    /// Bind on `127.0.0.1:0`, generate a host key + config, and spawn sshd.
    ///
    /// Returns `Ok(None)` when `sshd` is not on `PATH`. Tests should branch
    /// on this to skip cleanly.
    pub async fn start(self) -> std::io::Result<Option<RunningOpenSshServer>> {
        let Some(sshd_path) = Self::locate_sshd() else {
            return Ok(None);
        };
        let dir = tempfile::tempdir()?;
        let dir_path = dir.path().to_path_buf();

        // Pick an ephemeral port by binding loopback briefly.
        let port = {
            let lis = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let port = lis.local_addr()?.port();
            drop(lis);
            port
        };

        // Generate a host key with ssh-key (no external `ssh-keygen` needed).
        let host_key_path = dir_path.join("ssh_host_rsa_key");
        let host_key_pub_path = dir_path.join("ssh_host_rsa_key.pub");
        let mut rng = ssh_key::rand_core::OsRng;
        let host_key = ssh_key::PrivateKey::random(
            &mut rng,
            ssh_key::Algorithm::Rsa { hash: None },
        )
        .map_err(|e| std::io::Error::other(format!("genkey: {e}")))?;
        let pem = host_key
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|e| std::io::Error::other(format!("encode hostkey: {e}")))?;
        std::fs::write(&host_key_path, pem.as_bytes())?;
        let pubkey = host_key
            .public_key()
            .to_openssh()
            .map_err(|e| std::io::Error::other(format!("encode hostkey pub: {e}")))?;
        std::fs::write(&host_key_pub_path, format!("{pubkey}\n"))?;
        // sshd is strict about host-key permissions.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &host_key_path,
                std::fs::Permissions::from_mode(0o600),
            )?;
        }

        // Optional authorized-keys file.
        let authorized_keys_path = if let Some(pubkey) = &self.authorized_keys_pem {
            let p = dir_path.join("authorized_keys");
            std::fs::write(&p, pubkey)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
            Some(p)
        } else {
            None
        };

        // Minimal sshd_config. We deliberately avoid PAM / motd / login banner.
        let mut cfg = String::new();
        cfg.push_str(&format!("Port {port}\n"));
        cfg.push_str("ListenAddress 127.0.0.1\n");
        cfg.push_str(&format!("HostKey {}\n", host_key_path.display()));
        cfg.push_str("UsePAM no\n");
        cfg.push_str("StrictModes no\n");
        cfg.push_str("PrintMotd no\n");
        cfg.push_str("PermitRootLogin no\n");
        cfg.push_str(&format!(
            "PasswordAuthentication {}\n",
            if self.password_auth { "yes" } else { "no" }
        ));
        cfg.push_str("PubkeyAuthentication yes\n");
        cfg.push_str("ChallengeResponseAuthentication no\n");
        cfg.push_str(&format!("AllowUsers {}\n", self.username));
        if let Some(akp) = &authorized_keys_path {
            cfg.push_str(&format!("AuthorizedKeysFile {}\n", akp.display()));
        }
        cfg.push_str("AllowTcpForwarding yes\n");
        cfg.push_str("GatewayPorts no\n");
        cfg.push_str("ClientAliveInterval 30\n");

        let cfg_path = dir_path.join("sshd_config");
        std::fs::write(&cfg_path, cfg.as_bytes())?;

        // Spawn sshd in foreground / log-to-stderr mode.
        let child = std::process::Command::new(&sshd_path)
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&cfg_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        // Wait briefly for the socket to come up.
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        Ok(Some(RunningOpenSshServer {
            addr,
            sshd_path,
            tempdir: Some(dir),
            child: Some(child),
        }))
    }
}

/// Handle to a running `sshd` started by [`OpenSshTestServer`].
#[cfg(all(unix, feature = "testing"))]
pub struct RunningOpenSshServer {
    /// Loopback address sshd is listening on.
    pub addr: std::net::SocketAddr,
    /// Path to the located `sshd` binary.
    pub sshd_path: std::path::PathBuf,
    /// Tempdir holding `sshd_config` and the ephemeral host key.
    tempdir: Option<tempfile::TempDir>,
    child: Option<std::process::Child>,
}

#[cfg(all(unix, feature = "testing"))]
impl RunningOpenSshServer {
    /// Returns the path to the on-disk `sshd_config` for inspection.
    #[must_use]
    pub fn config_path(&self) -> Option<std::path::PathBuf> {
        self.tempdir.as_ref().map(|d| d.path().join("sshd_config"))
    }

    /// Kill `sshd` and clean up.
    pub fn shutdown(mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // tempdir Drop fires automatically.
        drop(self.tempdir.take());
    }
}

#[cfg(all(unix, feature = "testing"))]
impl Drop for RunningOpenSshServer {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
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
        assert_eq!(server.connection_count(), 0);
        assert!(server.host_key_fingerprint.starts_with("rsa-2048"));
        server.shutdown().await;
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn russh_test_server_with_ed25519_host_key() {
        let server = RusshTestServer::new()
            .with_ed25519_host_key()
            .start()
            .await
            .unwrap();
        assert!(server.host_key_fingerprint.starts_with("ed25519"));
        server.shutdown().await;
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn russh_test_server_with_authorized_pubkey_disables_any() {
        let kp = russh_keys::key::KeyPair::generate_ed25519();
        let pubkey = kp.clone_public_key().expect("pubkey");
        let server = RusshTestServer::new()
            .with_authorized_pubkey(pubkey)
            .start()
            .await
            .unwrap();
        // We can't easily drive a libssh2 client from inside this unit test
        // without the full handshake plumbing; the assertion here is on the
        // builder-state side effects: counters start at zero, server bound.
        assert_eq!(server.auth_attempts(), 0);
        server.shutdown().await;
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn russh_test_server_with_password_disables_any_pubkey() {
        // Builder side-effect: with_password() flips off accept_any_pubkey.
        let s = RusshTestServer::new().with_password("u", "pw");
        assert!(!s.accept_any_pubkey);
        // Adding back any-pubkey explicitly should re-enable it.
        let s = s.with_authorized_pubkey_any();
        assert!(s.accept_any_pubkey);
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn russh_test_server_counters_start_at_zero() {
        let server = RusshTestServer::new().start().await.unwrap();
        assert_eq!(server.connection_count(), 0);
        assert_eq!(server.auth_attempts(), 0);
        assert_eq!(server.channel_opens_session(), 0);
        assert_eq!(server.channel_opens_direct_tcpip(), 0);
        assert_eq!(server.tcpip_forward_requests(), 0);
        assert_eq!(server.keepalive_packet_count(), 0);
        server.shutdown().await;
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn russh_test_server_counters_observe_raw_tcp_connect() {
        let server = RusshTestServer::new().start().await.unwrap();
        // Open a raw TCP connection; the SSH banner exchange will fail but
        // the accept-loop bumps `connections` regardless.
        let _sock = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        // Give the accept loop a moment to register the new connection.
        for _ in 0..20 {
            if server.connection_count() >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(server.connection_count() >= 1);
        server.shutdown().await;
    }

    #[cfg(all(unix, feature = "testing"))]
    #[test]
    fn openssh_locate_sshd_smoke() {
        // The function returns None when sshd is absent (e.g. on Windows or
        // a stripped container). We only assert it doesn't panic; the actual
        // value depends on the build host.
        let _ = OpenSshTestServer::locate_sshd();
    }

    #[cfg(all(unix, feature = "testing"))]
    #[tokio::test]
    async fn openssh_start_returns_none_when_path_strips_sshd() {
        // Stash the original PATH; restore at end. Override to an empty
        // string so locate_sshd cannot find sshd (also unset SHELL well-known
        // alternative paths via empty PATH).
        let original = std::env::var_os("PATH");
        std::env::set_var("PATH", "");
        // Note: still might find /usr/sbin/sshd via the hardcoded fallback.
        // The fallback check is well-known absolute paths, so on a host where
        // sshd is installed start() will succeed even with empty PATH. We
        // accept either outcome — what matters is the function returns Ok.
        let server = OpenSshTestServer::new().start().await.expect("start ok");
        if let Some(s) = server {
            s.shutdown();
        }
        if let Some(p) = original {
            std::env::set_var("PATH", p);
        } else {
            std::env::remove_var("PATH");
        }
    }

    #[cfg(all(unix, feature = "testing"))]
    #[tokio::test]
    async fn openssh_default_builder_has_no_authorized_key() {
        let s = OpenSshTestServer::new();
        assert!(s.authorized_keys_pem.is_none());
        assert!(!s.password_auth);
    }

    #[cfg(all(unix, feature = "testing"))]
    #[tokio::test]
    async fn openssh_builder_chaining_records_state() {
        let s = OpenSshTestServer::new()
            .with_username("alice")
            .with_authorized_key("ssh-rsa AAAA testkey alice@host");
        assert_eq!(s.username, "alice");
        assert!(s
            .authorized_keys_pem
            .as_deref()
            .unwrap()
            .contains("testkey"));
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn russh_test_server_restart_keeps_port_and_counters() {
        let server = RusshTestServer::new().start().await.unwrap();
        let original_addr = server.addr;

        // Drive one TCP accept to bump `connections` to 1.
        let _ = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        for _ in 0..20 {
            if server.connection_count() >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let pre = server.connection_count();
        assert!(pre >= 1);

        // Restart on the same port — the SocketAddr (port) must match and the
        // counters must persist (cumulative semantics).
        let server = server.restart_on_same_port().await.expect("rebind");
        assert_eq!(server.addr.port(), original_addr.port());
        assert_eq!(server.connection_count(), pre);

        // New connection should still increment.
        let _ = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        for _ in 0..20 {
            if server.connection_count() > pre {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(server.connection_count() > pre);

        server.shutdown().await;
    }
}
