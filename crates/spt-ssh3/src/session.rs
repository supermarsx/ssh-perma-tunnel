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
    DynamicForwardSpec, LocalForwardSpec, RemoteForwardSpec, UdpForwardSpec,
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
    /// The control bidi multiplexes several frame kinds (forward-open acks,
    /// UDP-associate requests, `AppPing` keepalives) with no per-request
    /// correlation id in the wire format. A full demux would require extending
    /// the frame header, which the wire-compat constraint forbids touching
    /// here. As a scoped mitigation we (a) keep keepalive `AppPing` strictly
    /// fire-and-forget — it never consumes a frame off `control_recv` — and
    /// (b) hold this mutex across the only request that *does* read a response
    /// ([`forward::open_remote`]), so two such requests can never have their
    /// `ForwardOpenResponse` frames mis-routed to each other. Full
    /// correlation-id demux is tracked as a follow-up.
    control_request: Arc<AsyncMutex<()>>,
    state: Arc<SessionState>,
    next_flow_id: Arc<std::sync::atomic::AtomicU32>,
    /// Dial parameters for [`Self::preflight_connect`]'s fresh side-dial.
    /// `None` for sessions constructed directly from parts (test rig) — those
    /// report preflight as unsupported.
    redial: Option<RedialParams>,
    /// Background dispatcher tasks (h3 driver + bidi accept + datagram
    /// reader). All `abort()`'ed on `close()`.
    background: Vec<tokio::task::JoinHandle<()>>,
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
                                let _ = tx.value().send(body);
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
            background,
        }
    }

    /// Borrow the peer's advertised settings.
    #[must_use]
    pub fn peer_settings(&self) -> &Ssh3Settings {
        &self.peer_settings
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
        let _ = self.connection.rtt();
        if self.connection.close_reason().is_some() {
            return Err(Error::RuntimeFailure("ssh3 connection closed".into()));
        }
        // Send an application-level AppPing on the control stream. Best-effort
        // — if the write fails we surface that as a runtime failure.
        let frame =
            crate::frame::Ssh3Frame::new(crate::frame::Ssh3FrameKind::AppPing, bytes::Bytes::new());
        let mut g = self.control_send.lock().await;
        frame.write_async(&mut *g).await?;
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
