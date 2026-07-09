//! [`Ssh3Session`] — the [`TunnelSession`] returned after a successful CONNECT
//! bootstrap.
//!
//! ## Status: spt↔spt channel framing live
//!
//! The per-forward channel framing in `forward.rs` is fully wired for spt↔spt
//! interop:
//!
//! * [`Ssh3Session::open_local_forward`] — TCP local forward over a fresh bidi
//!   QUIC stream with a [`crate::frame::Ssh3FrameKind::DirectTcpRequest`] open
//!   frame.
//! * [`Ssh3Session::open_remote_forward`] — `tcpip-forward`-style request on
//!   the control stream, with inbound bidi streams dispatched by host:port.
//!   Returns [`Error::UnsupportedPlatform`] if the peer's `Settings` did not
//!   advertise `remote_tcp`.
//! * [`Ssh3Session::open_udp_forward`] — UDP datagrams over QUIC datagrams
//!   with `[u32_be flow_id]` prefix. Returns [`Error::UnsupportedPlatform`] if
//!   the peer's `Settings` did not advertise `udp_datagrams` or if the QUIC
//!   negotiation disabled datagrams.
//!
//! **Wire-compat note**: the framing constants are documented in
//! `frame.rs`/`forward.rs` but are NOT bit-compatible with francoismichel/ssh3.
//! Real-server interop is gated on the `SPT_SSH3_TEST_SERVER` integration
//! test (out of scope for this crate's unit tests).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use quinn::{Connection, RecvStream, SendStream};
use spt_auth::AuthConfig;
use spt_core::{Error, Result};
use spt_protocol::forward::{
    DynamicForwardSpec, LocalForwardSpec, RemoteForwardSpec, RemoteUdsForwardSpec, UdpForwardSpec,
    UdsForwardSpec,
};
use spt_protocol::handle::ForwardHandle;
use spt_protocol::session::{SessionInfo, TunnelSession};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, warn};

use crate::config::Ssh3Config;
use crate::forward::{self, SessionState};
use crate::frame::Ssh3Settings;
use crate::transport::{bootstrap, BootstrappedSession};

/// The dial parameters a live [`Ssh3Session`] retains so it can run a fresh
/// connect+auth side-dial for [`TunnelSession::preflight_connect`].
///
/// Mirrors the russh backend, which clones its `connect_inner` inputs for the
/// same purpose (`russh_backend.rs:1346`). Sessions constructed directly from
/// parts (e.g. the loopback test rig) do not carry these and therefore report
/// preflight as unsupported rather than silently passing.
#[derive(Debug, Clone)]
pub struct RedialParams {
    /// Endpoint host the session was bootstrapped against.
    pub host: String,
    /// Endpoint port.
    pub port: u16,
    /// The validated config used for the original bootstrap.
    pub config: Ssh3Config,
    /// The auth config used for the original bootstrap.
    pub auth: AuthConfig,
}

/// Live SSH3 session.
pub struct Ssh3Session {
    connection: Connection,
    info: SessionInfo,
    peer_settings: Ssh3Settings,
    control_send: Arc<AsyncMutex<SendStream>>,
    control_recv: Arc<AsyncMutex<RecvStream>>,
    /// Serializes control-stream *request/response* exchanges (E3-F5).
    ///
    /// The control bidi multiplexes several request/response frame kinds
    /// (forward-open acks, UDP-associate requests) with no per-request
    /// correlation id in the wire format. A full demux would require extending
    /// the frame header, which the wire-compat constraint forbids touching
    /// here. As a scoped mitigation we hold this mutex across the only request
    /// that *does* read a response ([`forward::open_remote`]), so two such
    /// requests can never have their `ForwardOpenResponse` frames mis-routed to
    /// each other. Full correlation-id demux is tracked as a follow-up.
    ///
    /// Note: app-level keepalive pings (F-R2) no longer share this stream — they
    /// run over a dedicated echo stream ([`Self::keepalive_send`]) so their
    /// pong-tracking reader can own its own `RecvStream` without contending with
    /// forward-open responses here.
    control_request: Arc<AsyncMutex<()>>,
    state: Arc<SessionState>,
    next_flow_id: Arc<std::sync::atomic::AtomicU32>,
    /// Dial parameters for [`Self::preflight_connect`]'s fresh side-dial.
    /// `None` for sessions constructed directly from parts (test rig) — those
    /// report preflight as unsupported.
    redial: Option<RedialParams>,
    /// Dedicated bidi stream for app-level keepalive ping/echo liveness (F-R2).
    /// Lazily opened by the first [`TunnelSession::keepalive`] call; `None` until
    /// then, so a session that is never probed opens no extra stream
    /// (behaviour-preserving).
    keepalive_send: Option<SendStream>,
    /// Consecutive keepalive pings written but not yet echoed by the peer.
    /// Bumped once per ping sent and reset to zero by [`keepalive_reader`] on
    /// every echo received; reaching [`MAX_MISSED_KEEPALIVES`] means the peer's
    /// application layer has stopped draining the stream while QUIC stayed up,
    /// so the session is declared dead.
    keepalive_missed: Arc<std::sync::atomic::AtomicU32>,
    /// Background dispatcher tasks (h3 driver + bidi accept + datagram
    /// reader + keepalive echo reader). All `abort()`'ed on `close()`.
    background: Vec<tokio::task::JoinHandle<()>>,
}

/// Consecutive unanswered application-level keepalive pings tolerated before a
/// session is declared dead (F-R2).
///
/// Each [`TunnelSession::keepalive`] call writes one `AppPing` on the dedicated
/// keepalive stream and bumps [`Ssh3Session::keepalive_missed`]; the background
/// [`keepalive_reader`] resets that counter to zero on every echo the peer
/// returns. If the counter reaches this threshold the peer has ignored this many
/// consecutive pings while QUIC stayed up (an application-layer stall), so
/// `keepalive` returns an error and the supervisor reconnects — the same signal
/// a network drop produces. This is a fixed miss count rather than a new config
/// knob: the supervisor already spaces calls by its `keepalive_interval` and
/// wraps each in `keepalive_timeout`, so N misses ≈ N intervals of app-level
/// silence. Kept small so healthy sessions (echo round-trips well inside one
/// interval) never trip.
const MAX_MISSED_KEEPALIVES: u32 = 3;

/// Background reader for a session's dedicated keepalive stream (F-R2).
///
/// Every frame the peer echoes back resets the outstanding-ping counter to
/// zero; a read error (stream reset / connection closed) ends the task. Spawned
/// lazily by the first [`Ssh3Session::keepalive`] call and reaped by [`Drop`]
/// via the session's `background` vector.
async fn keepalive_reader(mut recv: RecvStream, missed: Arc<std::sync::atomic::AtomicU32>) {
    loop {
        match crate::frame::Ssh3Frame::read_async(&mut recv).await {
            Ok(_) => missed.store(0, std::sync::atomic::Ordering::Release),
            Err(e) => {
                debug!(target: "spt_ssh3::session", error = %e, "keepalive echo reader ended");
                break;
            }
        }
    }
}

impl std::fmt::Debug for Ssh3Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ssh3Session")
            .field("info", &self.info)
            .field("peer_settings", &self.peer_settings)
            .field("remote_address", &self.connection.remote_address())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Ssh3Session {
    /// Wrap a freshly-bootstrapped QUIC connection.
    #[must_use]
    pub fn from_bootstrap(bs: BootstrappedSession) -> Self {
        Self::from_bootstrap_with_redial(bs, None)
    }

    /// Wrap a freshly-bootstrapped QUIC connection, retaining the dial
    /// parameters so [`Self::preflight_connect`] can run a fresh connect+auth
    /// side-dial. This is the path `Ssh3Protocol::connect` uses.
    #[must_use]
    pub fn from_bootstrap_with_redial(
        bs: BootstrappedSession,
        redial: Option<RedialParams>,
    ) -> Self {
        let info = SessionInfo {
            backend: "ssh3".to_string(),
            peer_version: bs.peer_version,
            negotiated: bs.negotiated,
            established_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
        };
        Self::from_parts_with_redial(
            bs.connection,
            bs.control_send,
            bs.control_recv,
            bs.peer_settings,
            info,
            Some(bs.h3_driver),
            redial,
        )
    }

    /// Construct directly from a QUIC connection plus an already-exchanged
    /// control-stream pair. Used by tests that drive both ends locally without
    /// going through HTTP/3. The resulting session has no redial parameters, so
    /// [`Self::preflight_connect`] reports unsupported.
    #[must_use]
    pub fn from_parts(
        connection: Connection,
        control_send: SendStream,
        control_recv: RecvStream,
        peer_settings: Ssh3Settings,
        info: SessionInfo,
        h3_driver: Option<tokio::task::JoinHandle<()>>,
    ) -> Self {
        Self::from_parts_with_redial(
            connection,
            control_send,
            control_recv,
            peer_settings,
            info,
            h3_driver,
            None,
        )
    }

    /// Like [`Self::from_parts`] but also retains [`RedialParams`] for
    /// [`Self::preflight_connect`].
    #[must_use]
    pub fn from_parts_with_redial(
        connection: Connection,
        control_send: SendStream,
        control_recv: RecvStream,
        peer_settings: Ssh3Settings,
        info: SessionInfo,
        h3_driver: Option<tokio::task::JoinHandle<()>>,
        redial: Option<RedialParams>,
    ) -> Self {
        // E3-F3: size the inbound-forward concurrency cap from the peer's
        // advertised `max_forwards` so a peer that opens unbounded inbound
        // forwards is bounded.
        let state = Arc::new(SessionState::with_max_forwards(peer_settings.max_forwards));
        let next_flow_id = Arc::new(std::sync::atomic::AtomicU32::new(1));

        let mut background = Vec::new();
        if let Some(h) = h3_driver {
            background.push(h);
        }

        // Inbound bidi-stream dispatch loop (handles peer-initiated remote
        // forwards' forwarded-tcp opens).
        {
            let conn = connection.clone();
            let state2 = state.clone();
            background.push(tokio::spawn(async move {
                loop {
                    match conn.accept_bi().await {
                        Ok((send, recv)) => {
                            let st = state2.clone();
                            tokio::spawn(forward::dispatch_inbound_bidi(st, send, recv));
                        }
                        Err(e) => {
                            debug!(target: "spt_ssh3::session", error = %e, "accept_bi loop ended");
                            break;
                        }
                    }
                }
            }));
        }

        // Inbound datagram dispatch loop (UDP demux by flow-id).
        {
            let conn = connection.clone();
            let state2 = state.clone();
            background.push(tokio::spawn(async move {
                loop {
                    match conn.read_datagram().await {
                        Ok(payload) => {
                            if payload.len() < 4 {
                                warn!(
                                    target: "spt_ssh3::session",
                                    "dropping datagram shorter than flow-id prefix ({} bytes)",
                                    payload.len()
                                );
                                continue;
                            }
                            let flow_id = u32::from_be_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]);
                            let body = payload.slice(4..);
                            if let Some(tx) = state2.udp_flows.get(&flow_id) {
                                // M1: bounded per-flow channel; `try_send` drops
                                // on a full queue (UDP is lossy) so a flooding
                                // peer cannot grow memory without bound. The
                                // DashMap `Ref` is held only across this
                                // non-blocking send (no await under the guard).
                                let _ = tx.value().try_send(body);
                            } else {
                                debug!(
                                    target: "spt_ssh3::session",
                                    flow_id,
                                    "dropping datagram for unknown flow"
                                );
                            }
                        }
                        Err(e) => {
                            debug!(target: "spt_ssh3::session", error = %e, "read_datagram loop ended");
                            break;
                        }
                    }
                }
            }));
        }

        Self {
            connection,
            info,
            peer_settings,
            control_send: Arc::new(AsyncMutex::new(control_send)),
            control_recv: Arc::new(AsyncMutex::new(control_recv)),
            control_request: Arc::new(AsyncMutex::new(())),
            state,
            next_flow_id,
            redial,
            keepalive_send: None,
            keepalive_missed: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            background,
        }
    }

    /// Borrow the peer's advertised settings.
    #[must_use]
    pub fn peer_settings(&self) -> &Ssh3Settings {
        &self.peer_settings
    }
}

impl Drop for Ssh3Session {
    /// H1: abort the background dispatch tasks (h3 driver + `accept_bi` loop +
    /// datagram demux) and best-effort close the QUIC connection on ANY drop.
    ///
    /// Graceful teardown goes through [`TunnelSession::close`], which already
    /// aborts these tasks and awaits `connection.closed()`. But non-graceful
    /// paths drop the session WITHOUT calling `close()` — e.g. the
    /// `ProfileSupervisor::drop` abort backstop, or `Orchestrator` dropping a
    /// displaced session on reload. Without this `Drop` those paths would leak
    /// the background tasks (which each hold a `Connection` clone) and keep the
    /// QUIC connection + UDP FD alive until the idle timeout.
    ///
    /// Idempotent with `close()`: aborting an already-finished handle and
    /// closing an already-closed connection are both harmless no-ops, so
    /// `close()` followed by this `Drop` never double-panics.
    fn drop(&mut self) {
        for h in &self.background {
            h.abort();
        }
        // Cannot `await connection.closed()` in Drop; abort + close + dropping
        // the `Connection` clones is enough to release the socket/FD.
        self.connection.close(0u32.into(), b"spt-ssh3: drop");
    }
}

#[async_trait]
impl TunnelSession for Ssh3Session {
    async fn open_local_forward(&mut self, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
        if !self.peer_settings.direct_tcp {
            return Err(Error::UnsupportedPlatform(
                "ssh3 peer did not advertise direct_tcp capability".into(),
            ));
        }
        forward::open_local(self.connection.clone(), spec).await
    }

    async fn open_remote_forward(&mut self, spec: &RemoteForwardSpec) -> Result<ForwardHandle> {
        forward::open_remote(
            self.connection.clone(),
            self.state.clone(),
            self.control_send.clone(),
            self.control_recv.clone(),
            self.control_request.clone(),
            spec,
            self.peer_settings.remote_tcp,
        )
        .await
    }

    async fn open_dynamic_forward(&mut self, _spec: &DynamicForwardSpec) -> Result<ForwardHandle> {
        Err(Error::UnsupportedPlatform(
            "SSH3 dynamic SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT proxy listeners are not implemented; use an SSH2/russh profile for dynamic proxying".into(),
        ))
    }

    async fn open_udp_forward(&mut self, spec: &UdpForwardSpec) -> Result<ForwardHandle> {
        forward::open_udp(
            self.connection.clone(),
            self.state.clone(),
            self.control_send.clone(),
            self.next_flow_id.clone(),
            spec,
            self.peer_settings.udp_datagrams,
        )
        .await
    }

    async fn open_uds_forward(&mut self, spec: &UdsForwardSpec) -> Result<ForwardHandle> {
        // `local_uds`: bind a client-side AF_UNIX listener and bridge each
        // accepted connection over a fresh UDS channel to the peer, which
        // `UnixStream::connect`s `spec.remote_socket_path`. On `cfg(not(unix))`
        // the forward.rs impl returns `UnsupportedPlatform` (mirrors russh).
        forward::open_uds(self.connection.clone(), spec).await
    }

    async fn open_remote_uds(&mut self, spec: &RemoteUdsForwardSpec) -> Result<ForwardHandle> {
        // `remote_uds`: ask the peer to bind a unix listener on
        // `spec.remote_socket_path`, then bridge each server-opened UDS
        // back-channel to a local `UnixStream::connect(spec.local_socket_path)`.
        // Reuses the inbound-bidi dispatch loop (UDS opens are routed to the
        // remote-uds registration). On `cfg(not(unix))` returns
        // `UnsupportedPlatform`.
        forward::open_remote_uds(
            self.state.clone(),
            self.control_send.clone(),
            self.control_recv.clone(),
            self.control_request.clone(),
            spec,
            self.peer_settings.remote_tcp,
        )
        .await
    }

    async fn preflight_connect(&mut self) -> Result<()> {
        // Mirror the russh contract (russh_backend.rs:1346): open a FRESH
        // QUIC + TLS + Extended-CONNECT + auth side-dial to the SAME endpoint
        // this session targets, then drop it immediately — WITHOUT opening any
        // forwards. A successful bootstrap proves QUIC reachability + TLS trust
        // + CONNECT-200 + auth; that is the whole point of the probe. This
        // never touches the live session (`self.connection` is untouched).
        let Some(redial) = self.redial.as_ref() else {
            return Err(Error::UnsupportedPlatform(
                "ssh3 preflight_connect requires a session created via connect() \
                 (no redial parameters retained)"
                    .into(),
            ));
        };
        let bs = bootstrap(&redial.host, redial.port, &redial.config, &redial.auth).await?;
        // Best-effort graceful teardown of the side connection. The bootstrap
        // already proved reachability + credentials; a close error does not
        // invalidate the successful preflight. Abort the side h3 driver task so
        // it does not outlive this probe.
        bs.h3_driver.abort();
        bs.connection
            .close(0u32.into(), b"spt-ssh3: preflight close");
        Ok(())
    }

    async fn keepalive(&mut self) -> Result<()> {
        // Refresh the QUIC RTT estimate and honour the transport-level backstop:
        // a closed / idle-timed-out connection is unconditionally dead,
        // regardless of the app-layer liveness check below.
        let _ = self.connection.rtt();
        if self.connection.close_reason().is_some() {
            return Err(Error::RuntimeFailure("ssh3 connection closed".into()));
        }

        // F-R2: app-layer liveness. The previous implementation wrote a
        // fire-and-forget `AppPing` on the shared control stream and returned
        // `Ok` without ever confirming the peer processed it — so a peer whose
        // application layer had stalled while its QUIC connection stayed alive
        // was never detected (unlike the ssh2 backend, which does a real
        // channel-open round-trip). We now run pings over a dedicated bidi
        // "keepalive" stream that a healthy peer echoes
        // (`forward::serve_keepalive_stream`) and track how many consecutive
        // pings have gone unanswered.
        //
        // The check is deliberately non-blocking: we never await a pong inside
        // this call. A background reader task ([`keepalive_reader`]) resets the
        // miss counter whenever an echo arrives; each call just writes one ping
        // and inspects the counter. Using a dedicated stream (rather than the
        // control stream) keeps the echo reader from contending with
        // `open_remote`'s `ForwardOpenResponse` reads on `control_recv`.
        if self.keepalive_send.is_none() {
            let (send, recv) =
                self.connection.open_bi().await.map_err(|e| {
                    Error::RuntimeFailure(format!("ssh3 keepalive: open stream: {e}"))
                })?;
            let missed = self.keepalive_missed.clone();
            self.background
                .push(tokio::spawn(keepalive_reader(recv, missed)));
            self.keepalive_send = Some(send);
        }

        let frame =
            crate::frame::Ssh3Frame::new(crate::frame::Ssh3FrameKind::AppPing, bytes::Bytes::new());
        let send = self
            .keepalive_send
            .as_mut()
            .expect("keepalive_send initialized above");
        frame.write_async(send).await?;

        // Count this ping as outstanding. The reader resets the counter to zero
        // on every echo; if it reaches the threshold the peer has ignored
        // MAX_MISSED_KEEPALIVES consecutive pings while QUIC stayed up — treat
        // the session as dead so the supervisor reconnects (the same failure
        // signal a network drop produces via `close_reason` above).
        let missed = self
            .keepalive_missed
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1;
        if missed >= MAX_MISSED_KEEPALIVES {
            return Err(Error::RuntimeFailure(format!(
                "ssh3 keepalive: peer unresponsive ({missed} consecutive app-level pings unanswered)"
            )));
        }
        Ok(())
    }

    async fn close(self: Box<Self>) -> Result<()> {
        for h in &self.background {
            h.abort();
        }
        self.connection.close(0u32.into(), b"spt-ssh3: close");
        self.connection.closed().await;
        Ok(())
    }

    fn session_info(&self) -> SessionInfo {
        self.info.clone()
    }
}

#[cfg(all(test, feature = "testing"))]
mod drop_tests {
    use super::*;
    use crate::testing::test_support::connected_pair_public;
    use crate::transport::{accept_control_stream, open_control_stream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn test_settings() -> Ssh3Settings {
        Ssh3Settings {
            direct_tcp: true,
            remote_tcp: true,
            udp_datagrams: true,
            agent_forwarding: false,
            max_forwards: Some(8),
            version: Some("test/0.1".into()),
            extras: vec![],
        }
    }

    fn test_info() -> SessionInfo {
        SessionInfo {
            backend: "ssh3".into(),
            peer_version: Some("client".into()),
            negotiated: Some("test".into()),
            established_at: 0,
        }
    }

    /// A `pending()`-parked task standing in for the h3 driver. It signals
    /// readiness (so the test can guarantee it was polled, and thus the
    /// drop-sentinel constructed, before aborting) and flips `flag` when its
    /// future is dropped (= the task was aborted).
    fn parked_driver() -> (
        tokio::task::JoinHandle<()>,
        Arc<AtomicBool>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            struct Sentinel(Arc<AtomicBool>);
            impl Drop for Sentinel {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _s = Sentinel(f);
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        (handle, flag, ready_rx)
    }

    async fn build_session(
        driver: Option<tokio::task::JoinHandle<()>>,
    ) -> (Ssh3Session, quinn::Connection) {
        let (client, server) = connected_pair_public().await;
        let (cs, sv) = tokio::join!(
            open_control_stream(&client, test_settings()),
            accept_control_stream(&server, test_settings()),
        );
        let (c_send, c_recv, c_peer) = cs.expect("client handshake");
        let _sv = sv.expect("server handshake");
        let session =
            Ssh3Session::from_parts(client.clone(), c_send, c_recv, c_peer, test_info(), driver);
        (session, server)
    }

    /// H1: dropping a session WITHOUT calling `close()` (the non-graceful
    /// supervisor/orchestrator teardown path) MUST abort the background
    /// dispatch tasks and close the QUIC connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_without_close_aborts_background_and_closes_connection() {
        let (driver, dropped, ready_rx) = parked_driver();
        ready_rx.await.expect("driver started");
        let (session, server) = build_session(Some(driver)).await;

        drop(session); // non-graceful teardown.

        // The injected driver task's future must have been dropped (aborted),
        // proving Drop reaped the `background` handles.
        let mut flipped = false;
        for _ in 0..100 {
            if dropped.load(Ordering::SeqCst) {
                flipped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(flipped, "Drop must abort the background driver task");

        // The peer must observe the connection close promptly (Drop closed it).
        tokio::time::timeout(Duration::from_secs(5), server.closed())
            .await
            .expect("peer must observe close after session drop");
    }

    /// `close()` followed by the implicit `Drop` must be idempotent — no
    /// double-abort/close panic. (`close()` consumes the `Box`, then `Drop`
    /// runs on the same value.)
    #[tokio::test]
    async fn close_then_drop_is_idempotent() {
        let (session, server) = build_session(None).await;
        let boxed: Box<dyn spt_protocol::TunnelSession> = Box::new(session);
        boxed.close().await.expect("graceful close");
        // No panic implies idempotency; the peer is closed either way.
        let _ = tokio::time::timeout(Duration::from_secs(5), server.closed()).await;
    }
}

/// F-R2: app-layer keepalive liveness — a stalled-but-QUIC-alive peer must be
/// detected via unanswered pings, an echoing peer must stay alive, and the QUIC
/// transport backstop must still fire.
#[cfg(all(test, feature = "testing"))]
mod keepalive_tests {
    use super::*;
    use crate::forward::serve_inbound_opens;
    use crate::testing::test_support::connected_pair_public;
    use crate::transport::{accept_control_stream, open_control_stream};
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    fn test_settings() -> Ssh3Settings {
        Ssh3Settings {
            direct_tcp: true,
            remote_tcp: true,
            udp_datagrams: true,
            agent_forwarding: false,
            max_forwards: Some(8),
            version: Some("test/0.1".into()),
            extras: vec![],
        }
    }

    fn test_info() -> SessionInfo {
        SessionInfo {
            backend: "ssh3".into(),
            peer_version: Some("client".into()),
            negotiated: Some("test".into()),
            established_at: 0,
        }
    }

    /// Build a client [`Ssh3Session`] plus the raw server-side QUIC connection so
    /// the test can decide whether to echo keepalive pings (healthy peer) or
    /// ignore them (app-layer stall). The control-stream handshake is completed
    /// so the keepalive stream is the *second* bidi (the control stream is the
    /// first), matching production ordering.
    async fn build_session() -> (Ssh3Session, quinn::Connection) {
        let (client, server) = connected_pair_public().await;
        let (cs, sv) = tokio::join!(
            open_control_stream(&client, test_settings()),
            accept_control_stream(&server, test_settings()),
        );
        let (c_send, c_recv, c_peer) = cs.expect("client handshake");
        let _sv = sv.expect("server handshake");
        let session = Ssh3Session::from_parts(client, c_send, c_recv, c_peer, test_info(), None);
        (session, server)
    }

    /// A peer that echoes keepalive pings (via the production
    /// `serve_inbound_opens` accept loop) keeps the session alive indefinitely:
    /// the outstanding-ping counter is reset by each echo and never approaches
    /// the death threshold.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn answered_keepalive_keeps_session_alive() {
        let (mut session, server) = build_session().await;
        // Production echo responder: `serve_inbound_opens` now echoes AppPing
        // streams (F-R2). The `|_| None` resolver denies every TCP open — only
        // the keepalive path is exercised here.
        let responder = tokio::spawn(serve_inbound_opens(server.clone(), |_| None, |_| false));

        for i in 0..(MAX_MISSED_KEEPALIVES * 3) {
            session
                .keepalive()
                .await
                .unwrap_or_else(|e| panic!("answered keepalive #{i} must stay alive: {e:?}"));
            // Wait for the echo to reset the miss counter before the next ping,
            // so a healthy peer never lets the counter climb toward the death
            // threshold.
            let mut reset = false;
            for _ in 0..200 {
                if session.keepalive_missed.load(Ordering::Acquire) == 0 {
                    reset = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                reset,
                "echo must reset the outstanding-ping counter (iteration {i})"
            );
        }

        responder.abort();
    }

    /// A peer whose application layer never drains / echoes the keepalive stream
    /// — while its QUIC connection stays fully alive — must be detected as dead
    /// after [`MAX_MISSED_KEEPALIVES`] consecutive unanswered pings. This is the
    /// gap F-R2 closes: the pre-fix fire-and-forget keepalive returned `Ok`
    /// forever in exactly this scenario.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unanswered_keepalive_marks_session_lost() {
        // `_server` is held (never dropped) so the QUIC connection stays alive:
        // no responder ever accepts/echoes the keepalive stream (app-layer
        // stall), but the transport is healthy.
        let (mut session, _server) = build_session().await;

        let mut last = Ok(());
        for _ in 0..MAX_MISSED_KEEPALIVES {
            last = session.keepalive().await;
        }

        // Detection must be app-layer, NOT the QUIC backstop: the connection is
        // still open at the moment we declare the session dead.
        assert!(
            session.connection.close_reason().is_none(),
            "QUIC must still be alive — detection is app-layer, not transport"
        );
        let err = last.expect_err("consecutive unanswered pings must mark the session lost");
        assert!(
            matches!(err, Error::RuntimeFailure(_)),
            "expected RuntimeFailure (SessionLost signal), got {err:?}"
        );
    }

    /// The QUIC transport backstop still works: once the peer closes the
    /// connection (or it idle-times-out), `close_reason` is set and `keepalive`
    /// fails regardless of the app-layer miss counter.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn keepalive_errors_when_quic_connection_closed() {
        let (mut session, server) = build_session().await;
        // Close the peer; once the client observes it, `close_reason` is set.
        server.close(0u32.into(), b"bye");
        let mut observed = false;
        for _ in 0..300 {
            if session.connection.close_reason().is_some() {
                observed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(observed, "client must observe the peer close");
        let err = session
            .keepalive()
            .await
            .expect_err("closed QUIC connection must fail keepalive");
        assert!(
            matches!(err, Error::RuntimeFailure(_)),
            "expected RuntimeFailure, got {err:?}"
        );
    }
}
