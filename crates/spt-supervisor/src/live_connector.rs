//! Live-tunnel connector for the [`spt-benchmark`] drivers.
//!
//! The benchmark `Connector` / `UdpConnector` types want a closure that
//! produces a fresh stream / UDP endpoint per benchmark iteration. To run
//! against the live tunnel we need a stable seam that opens a new stream
//! over a running [`crate::ProfileSupervisor`]'s session — that seam is the
//! [`LiveConnector`] trait defined here.
//!
//! A backend-specific implementation builds an adapter over its
//! [`spt_protocol::TunnelSession`]. Tests use the in-memory adapters in
//! [`crate::live_connector::testing`] (gated on the `testing` feature of
//! `spt-forward`) which return loopback duplex pairs.

use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use spt_core::{Error, Result};
use tokio::io::{AsyncRead, AsyncWrite};

/// Marker trait combining `AsyncRead + AsyncWrite + Send + Unpin`.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> AsyncReadWrite for T {}

/// A boxed bidirectional async stream returned by [`LiveConnector::open_tcp`].
pub type BoxedStream = Pin<Box<dyn AsyncReadWrite>>;

/// A bound UDP socket plus the address of the (echo) target — mirrors
/// `spt_benchmark::UdpEndpoint` so the bench drivers can consume one verbatim.
pub struct UdpEndpoint {
    /// Bound socket the driver sends/receives datagrams on.
    pub socket: tokio::net::UdpSocket,
    /// Echo target address.
    pub target: std::net::SocketAddr,
}

/// Adapter that opens fresh streams over a live tunnel session.
#[async_trait]
pub trait LiveConnector: Send + Sync {
    /// Open a TCP stream to the configured target through the live session.
    ///
    /// The semantics are deliberately backend-defined: SSH2/SSH3 backends
    /// open a fresh channel and dial `host:port` on the remote side; the
    /// in-memory test adapter returns one half of a `tokio::io::duplex` pair
    /// connected to an echo task.
    async fn open_tcp(&self, host: &str, port: u16) -> Result<BoxedStream>;

    /// Open a UDP endpoint through the live session. Backends without UDP
    /// capability return [`spt_core::Error::UnsupportedPlatform`].
    async fn open_udp(&self) -> Result<UdpEndpoint>;
}

/// A [`LiveConnector`] that always errors with the same reason. Returned by
/// [`crate::Orchestrator::live_connector`] when the requested profile is not
/// running.
pub struct UnavailableConnector {
    /// User-readable reason.
    pub reason: String,
}

impl UnavailableConnector {
    /// New unavailable connector.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Convenience: wrap as `Arc<dyn LiveConnector>`.
    #[must_use]
    pub fn arc(reason: impl Into<String>) -> Arc<dyn LiveConnector> {
        Arc::new(Self::new(reason))
    }
}

#[async_trait]
impl LiveConnector for UnavailableConnector {
    async fn open_tcp(&self, _host: &str, _port: u16) -> Result<BoxedStream> {
        Err(Error::InternalError(format!(
            "live connector unavailable: {}",
            self.reason
        )))
    }

    async fn open_udp(&self) -> Result<UdpEndpoint> {
        Err(Error::InternalError(format!(
            "live connector unavailable: {}",
            self.reason
        )))
    }
}

/// In-process [`LiveConnector`] that returns half of a `tokio::io::duplex`
/// pair connected to an echo task. Useful for tests and as a portable
/// reference implementation. Each `open_tcp` call spawns a fresh echo task.
pub struct EchoLiveConnector {
    buffer: usize,
}

impl EchoLiveConnector {
    /// New echo connector with `buffer` bytes per duplex direction.
    #[must_use]
    pub fn new(buffer: usize) -> Self {
        Self { buffer }
    }
}

impl Default for EchoLiveConnector {
    fn default() -> Self {
        Self::new(64 * 1024)
    }
}

#[async_trait]
impl LiveConnector for EchoLiveConnector {
    async fn open_tcp(&self, _host: &str, _port: u16) -> Result<BoxedStream> {
        let (a, b) = tokio::io::duplex(self.buffer);
        // Echo task — every byte written by the caller comes back unchanged.
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(b);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        Ok(Box::pin(a))
    }

    async fn open_udp(&self) -> Result<UdpEndpoint> {
        // Bind a loopback socket and spawn an echo task on a sibling socket.
        let inbound = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| Error::RuntimeFailure(format!("udp bind: {e}")))?;
        let outbound = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| Error::RuntimeFailure(format!("udp bind: {e}")))?;
        let target = outbound
            .local_addr()
            .map_err(|e| Error::RuntimeFailure(format!("udp local_addr: {e}")))?;
        // Echo: any datagram received by `outbound` is sent back to its sender.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, peer)) = outbound.recv_from(&mut buf).await {
                let _ = outbound.send_to(&buf[..n], peer).await;
            }
        });
        Ok(UdpEndpoint {
            socket: inbound,
            target,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn echo_round_trip() {
        let conn = EchoLiveConnector::default();
        let mut s = conn.open_tcp("ignored", 0).await.unwrap();
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn unavailable_errors() {
        let c = UnavailableConnector::new("not running");
        assert!(c.open_tcp("h", 1).await.is_err());
        assert!(c.open_udp().await.is_err());
    }
}
