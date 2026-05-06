//! `TunnelSession` — one connected protocol session capable of multiplexing forwards.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use spt_core::Result;

use crate::forward::{LocalForwardSpec, RemoteForwardSpec, UdpForwardSpec};
use crate::handle::ForwardHandle;

/// One live session to a remote endpoint.
///
/// A session may host many concurrent forwards (`multiplex` capability). The
/// supervisor owns at most one session per profile-endpoint at a time.
#[async_trait]
pub trait TunnelSession: Send + Sync {
    /// Open a TCP forward whose listener lives on the local side.
    async fn open_local_forward(&mut self, spec: &LocalForwardSpec) -> Result<ForwardHandle>;

    /// Request the remote peer to open a listener and forward back to us.
    async fn open_remote_forward(&mut self, spec: &RemoteForwardSpec) -> Result<ForwardHandle>;

    /// Open a UDP forward (SSH3 only — backends without UDP capability return
    /// [`spt_core::Error::UnsupportedPlatform`]).
    async fn open_udp_forward(&mut self, spec: &UdpForwardSpec) -> Result<ForwardHandle>;

    /// Send a protocol-level keepalive. May be a no-op for transports with
    /// inherent liveness (QUIC); see spec §11.3.
    async fn keepalive(&mut self) -> Result<()>;

    /// Close the session, draining any in-flight forwards. Consumes the box
    /// because the session must not be used afterwards.
    async fn close(self: Box<Self>) -> Result<()>;

    /// Snapshot of session-level metadata (advertised version, peer info).
    fn session_info(&self) -> SessionInfo;
}

/// Read-only snapshot of session metadata exposed to logs/MCP/diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Backend name (`"ssh2"`, `"ssh3"`).
    pub backend: String,
    /// Peer-advertised version banner / TLS server cert subject / etc.
    pub peer_version: Option<String>,
    /// Negotiated cipher / KEX / key algorithm / TLS suite description.
    pub negotiated: Option<String>,
    /// Time the session was established (seconds since UNIX epoch).
    pub established_at: u64,
}
