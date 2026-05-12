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
use spt_core::{Error, Result};
use spt_protocol::forward::{LocalForwardSpec, RemoteForwardSpec, UdpForwardSpec};
use spt_protocol::handle::ForwardHandle;
use spt_protocol::session::{SessionInfo, TunnelSession};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, warn};

use crate::forward::{self, SessionState};
use crate::frame::Ssh3Settings;
use crate::transport::BootstrappedSession;

/// Live SSH3 session.
pub struct Ssh3Session {
    connection: Connection,
    info: SessionInfo,
    peer_settings: Ssh3Settings,
    control_send: Arc<AsyncMutex<SendStream>>,
    control_recv: Arc<AsyncMutex<RecvStream>>,
    state: Arc<SessionState>,
    next_flow_id: Arc<std::sync::atomic::AtomicU32>,
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
        let info = SessionInfo {
            backend: "ssh3".to_string(),
            peer_version: bs.peer_version,
            negotiated: bs.negotiated,
            established_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
        };
        Self::from_parts(
            bs.connection,
            bs.control_send,
            bs.control_recv,
            bs.peer_settings,
            info,
            Some(bs.h3_driver),
        )
    }

    /// Construct directly from a QUIC connection plus an already-exchanged
    /// control-stream pair. Used by tests that drive both ends locally without
    /// going through HTTP/3.
    #[must_use]
    pub fn from_parts(
        connection: Connection,
        control_send: SendStream,
        control_recv: RecvStream,
        peer_settings: Ssh3Settings,
        info: SessionInfo,
        h3_driver: Option<tokio::task::JoinHandle<()>>,
    ) -> Self {
        let state = Arc::new(SessionState::default());
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
            state,
            next_flow_id,
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
            spec,
            self.peer_settings.remote_tcp,
        )
        .await
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
