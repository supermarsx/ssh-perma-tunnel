//! [`Ssh3Session`] — the [`TunnelSession`] returned after a successful CONNECT
//! bootstrap.
//!
//! ## Status: PARTIAL-REAL
//!
//! - Session-info, keepalive (QUIC PING via [`quinn::Connection::rtt`]
//!   sentinel + transport-level `keep_alive_interval` set in
//!   [`crate::transport::bootstrap`]), and `close()` are real.
//! - `open_local_forward` / `open_remote_forward` / `open_udp_forward`
//!   currently return [`Error::UnsupportedPlatform`] — the SSH3
//!   control-channel framing for these is not yet wired against the
//!   francoismichel/ssh3 reference. See `crate::protocol::PARTIAL_REAL_REASON`.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use spt_core::{Error, Result};
use spt_protocol::forward::{LocalForwardSpec, RemoteForwardSpec, UdpForwardSpec};
use spt_protocol::handle::ForwardHandle;
use spt_protocol::session::{SessionInfo, TunnelSession};

use crate::protocol::PARTIAL_REAL_REASON;
use crate::transport::BootstrappedSession;

/// Live SSH3 session.
pub struct Ssh3Session {
    connection: quinn::Connection,
    info: SessionInfo,
}

impl std::fmt::Debug for Ssh3Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ssh3Session")
            .field("info", &self.info)
            .field("remote_address", &self.connection.remote_address())
            .finish()
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
        Self {
            connection: bs.connection,
            info,
        }
    }
}

#[async_trait]
impl TunnelSession for Ssh3Session {
    async fn open_local_forward(&mut self, _spec: &LocalForwardSpec) -> Result<ForwardHandle> {
        // TODO(spec-clarify): wire direct-tcp open frame on a fresh bidi
        // QUIC stream, then bridge bytes via spt_forward::bidir.
        Err(Error::UnsupportedPlatform(format!(
            "ssh3 local TCP forward: {PARTIAL_REAL_REASON}"
        )))
    }

    async fn open_remote_forward(&mut self, _spec: &RemoteForwardSpec) -> Result<ForwardHandle> {
        // TODO(spec-clarify): wire tcpip-forward request and inbound stream
        // dispatch.
        Err(Error::UnsupportedPlatform(format!(
            "ssh3 remote TCP forward: {PARTIAL_REAL_REASON}"
        )))
    }

    async fn open_udp_forward(&mut self, _spec: &UdpForwardSpec) -> Result<ForwardHandle> {
        // TODO(spec-clarify): wire UDP datagram association on top of QUIC
        // datagrams; demux by flow id.
        Err(Error::UnsupportedPlatform(format!(
            "ssh3 UDP forward: {PARTIAL_REAL_REASON}"
        )))
    }

    async fn keepalive(&mut self) -> Result<()> {
        // QUIC has built-in transport-level keepalive (configured in
        // `transport::bootstrap` via `keep_alive_interval`); the only thing
        // we can do at the session layer is verify the connection is still
        // alive by sampling its current RTT.
        let _ = self.connection.rtt();
        if self.connection.close_reason().is_some() {
            return Err(Error::RuntimeFailure("ssh3 connection closed".into()));
        }
        Ok(())
    }

    async fn close(self: Box<Self>) -> Result<()> {
        self.connection.close(0u32.into(), b"spt-ssh3: close");
        // Wait for the close to flush.
        self.connection.closed().await;
        Ok(())
    }

    fn session_info(&self) -> SessionInfo {
        self.info.clone()
    }
}
