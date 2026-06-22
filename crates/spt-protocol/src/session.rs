//! `TunnelSession` — one connected protocol session capable of multiplexing forwards.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use spt_core::Result;

use crate::forward::{
    DynamicForwardSpec, LocalForwardSpec, RemoteForwardSpec, UdpForwardSpec, UdsForwardSpec,
};
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

    /// Open a client-side dynamic TCP proxy listener.
    ///
    /// Backends that support this accept SOCKS4, SOCKS4A, SOCKS5, and/or HTTP
    /// CONNECT on the listener and open one direct TCP channel per requested
    /// target.
    async fn open_dynamic_forward(&mut self, spec: &DynamicForwardSpec) -> Result<ForwardHandle>;

    /// Open a UDP forward (SSH3 only — backends without UDP capability return
    /// [`spt_core::Error::UnsupportedPlatform`]).
    async fn open_udp_forward(&mut self, spec: &UdpForwardSpec) -> Result<ForwardHandle>;

    /// Open a unix-domain-socket forward (`cfg(unix)` capability).
    ///
    /// The default implementation reports the forward as unsupported, so
    /// backends that have not (yet) implemented UDS forwarding compile
    /// unchanged. Implementors that support it override this method.
    async fn open_uds_forward(&mut self, spec: &UdsForwardSpec) -> Result<ForwardHandle> {
        let _ = spec;
        Err(spt_core::Error::UnsupportedPlatform(
            "this backend does not support unix-domain-socket forwards".to_owned(),
        ))
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::UdsForwardSpec;
    use spt_core::Error;

    /// Minimal session implementing only the required methods, relying on the
    /// default `open_uds_forward` to verify it reports unsupported.
    struct NoUdsSession;

    #[async_trait]
    impl TunnelSession for NoUdsSession {
        async fn open_local_forward(&mut self, _spec: &LocalForwardSpec) -> Result<ForwardHandle> {
            unreachable!()
        }
        async fn open_remote_forward(
            &mut self,
            _spec: &RemoteForwardSpec,
        ) -> Result<ForwardHandle> {
            unreachable!()
        }
        async fn open_dynamic_forward(
            &mut self,
            _spec: &DynamicForwardSpec,
        ) -> Result<ForwardHandle> {
            unreachable!()
        }
        async fn open_udp_forward(&mut self, _spec: &UdpForwardSpec) -> Result<ForwardHandle> {
            unreachable!()
        }
        async fn keepalive(&mut self) -> Result<()> {
            Ok(())
        }
        async fn close(self: Box<Self>) -> Result<()> {
            Ok(())
        }
        fn session_info(&self) -> SessionInfo {
            SessionInfo {
                backend: "mock".to_owned(),
                peer_version: None,
                negotiated: None,
                established_at: 0,
            }
        }
    }

    #[tokio::test]
    async fn default_open_uds_forward_is_unsupported() {
        let mut s = NoUdsSession;
        let spec = UdsForwardSpec::default();
        let err = s.open_uds_forward(&spec).await.unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)), "got {err:?}");
    }
}
