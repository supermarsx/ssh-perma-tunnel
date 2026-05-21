//! [`ObfsTransport`] trait and the [`AsyncReadWrite`] alias the russh client
//! expects to handshake over.

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use spt_core::Result;

/// Convenience marker for the duplex byte stream returned by
/// [`ObfsTransport::connect`].
///
/// `russh::client::connect_stream` expects an `AsyncRead + AsyncWrite + Send +
/// Unpin + 'static`, so this trait collects those bounds in one name and
/// auto-implements for every type that satisfies them.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncReadWrite for T {}

/// Pluggable obfuscation transport.
///
/// Implementations encapsulate the wire-protocol handshake (obfs4 NTOR, meek
/// HTTP CONNECT, WebSocket upgrade, Shadowsocks AEAD framing) and yield a
/// duplex byte stream the SSH client then handshakes over.
#[async_trait]
pub trait ObfsTransport: Send {
    /// Establish the obfuscated connection to `target`.
    ///
    /// `target` is the canonical `host:port` of the SSH endpoint. The
    /// transport is responsible for any DNS resolution, TLS termination,
    /// fronting, and per-protocol framing.
    async fn connect(&mut self, target: &str) -> Result<Box<dyn AsyncReadWrite>>;

    /// Static transport identifier — used by the audit hook and the
    /// `tracing` instrumentation. Must match [`crate::config::ObfsConfig::name`].
    fn name(&self) -> &'static str;
}
