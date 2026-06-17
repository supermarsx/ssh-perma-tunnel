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
//! the `testing` module (gated on the `testing` feature of `spt-forward`)
//! which return loopback duplex pairs.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use spt_core::{Error, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::profile::ProfileSupervisor;

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

/// A TCP stream to a live-tunnel benchmark forward that keeps the forward open
/// for the lifetime of the stream.
///
/// Holding `_guard` (the [`crate::control::BenchForward`] drop-guard) means the
/// supervisor tears the per-bench forward down only once this stream is
/// dropped. All I/O delegates to the inner [`tokio::net::TcpStream`].
struct BenchStream {
    inner: tokio::net::TcpStream,
    _guard: tokio::sync::oneshot::Sender<()>,
}

impl AsyncRead for BenchStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for BenchStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Live [`LiveConnector`] backed by a running [`ProfileSupervisor`].
///
/// `open_tcp` asks the supervisor to open a fresh `local` forward through the
/// **live** session and returns a [`tokio::net::TcpStream`] connected to that
/// forward's loopback listener — so bytes the bench driver writes traverse the
/// live tunnel channel (latency / throughput / limits drivers).
///
/// `open_udp` is **structurally unsupported**: the [`TunnelSession`] API
/// exposes no raw datagram channel (only `open_udp_forward`, which binds a
/// listener and proxies, with no port readback). Even on a UDP-capable (SSH3)
/// backend there is no in-process seam to obtain a datagram endpoint, so this
/// returns a clear [`Error::UnsupportedPlatform`] rather than a misleading
/// "unavailable". See `bench1.md` for the protocol-layer work that would lift
/// this.
pub struct SupervisorLiveConnector {
    sup: Arc<ProfileSupervisor>,
}

impl SupervisorLiveConnector {
    /// Wrap a running supervisor as a live bench connector.
    #[must_use]
    pub fn new(sup: Arc<ProfileSupervisor>) -> Self {
        Self { sup }
    }

    /// Convenience: wrap as `Arc<dyn LiveConnector>`.
    #[must_use]
    pub fn arc(sup: Arc<ProfileSupervisor>) -> Arc<dyn LiveConnector> {
        Arc::new(Self::new(sup))
    }
}

#[async_trait]
impl LiveConnector for SupervisorLiveConnector {
    async fn open_tcp(&self, _host: &str, _port: u16) -> Result<BoxedStream> {
        // Open a fresh local forward over the live session. `host`/`port` are
        // informational — the forward's ingress is the loopback listener the
        // supervisor binds; the configured forward target governs the far end.
        let bench = self.sup.open_bench_forward().await?;
        let inner = tokio::net::TcpStream::connect(bench.local_addr)
            .await
            .map_err(|e| {
                Error::RuntimeFailure(format!(
                    "connect to live bench forward {}: {e}",
                    bench.local_addr
                ))
            })?;
        Ok(Box::pin(BenchStream {
            inner,
            _guard: bench.guard,
        }))
    }

    async fn open_udp(&self) -> Result<UdpEndpoint> {
        Err(Error::UnsupportedPlatform(
            if self.sup.supports_udp() {
                "live UDP benchmarking is not wired: the SSH3 backend advertises UDP forwards \
                 but the TunnelSession API exposes no in-process datagram channel (only \
                 open_udp_forward, which binds a proxy listener with no port readback). \
                 Run the UDP driver against the synthetic loopback connector instead."
            } else {
                "live UDP benchmarking is unsupported on this protocol: the backend has no UDP \
                 forward capability (SSH2 is TCP-only per spec §10.4). Use SSH3 for UDP, or run \
                 the UDP driver against the synthetic loopback connector."
            }
            .to_owned(),
        ))
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

    // ── SupervisorLiveConnector: live-session bench forward ────────────────

    use crate::profile::{ProfileSupervisor, ProfileSupervisorConfig};
    use crate::state_machine::ProfileStateName;
    use spt_auth::AuthConfig;
    use spt_core::Result as SptResult;
    use spt_protocol::{
        Endpoint, ForwardHandle, LocalForwardSpec, ProtocolCapabilities, SessionInfo,
        TunnelProtocol, TunnelSession,
    };
    use std::time::Duration;

    /// A session whose `open_local_forward` binds a REAL loopback echo listener
    /// at `spec.listen` — so a `SupervisorLiveConnector` connecting to that
    /// address gets bytes echoed, modelling a live tunnel that round-trips.
    struct EchoForwardSession {
        info: SessionInfo,
    }

    #[async_trait]
    impl TunnelSession for EchoForwardSession {
        async fn open_local_forward(
            &mut self,
            spec: &LocalForwardSpec,
        ) -> SptResult<ForwardHandle> {
            let addr = match &spec.listen {
                spt_core::BindAddr::Tcp(a) => *a,
                other => return Err(Error::RuntimeFailure(format!("unexpected bind {other:?}"))),
            };
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| Error::RuntimeFailure(format!("echo bind {addr}: {e}")))?;
            tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let (mut r, mut w) = sock.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
            });
            let (state_tx, state_rx) =
                tokio::sync::watch::channel(spt_protocol::ForwardState::Active);
            let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
            let handle = ForwardHandle::new(
                spt_protocol::ForwardId::new(),
                spec.name.clone(),
                state_rx,
                close_tx,
            );
            // Drive the handle to a terminal state when close() fires, so
            // ForwardHandle::close() returns instead of hanging.
            tokio::spawn(async move {
                let _ = close_rx.await;
                let _ = state_tx.send(spt_protocol::ForwardState::Stopped);
            });
            Ok(handle)
        }
        async fn open_remote_forward(
            &mut self,
            _spec: &spt_protocol::RemoteForwardSpec,
        ) -> SptResult<ForwardHandle> {
            Err(Error::RuntimeFailure("no remote".into()))
        }
        async fn open_dynamic_forward(
            &mut self,
            _spec: &spt_protocol::DynamicForwardSpec,
        ) -> SptResult<ForwardHandle> {
            Err(Error::RuntimeFailure("no dynamic".into()))
        }
        async fn open_udp_forward(
            &mut self,
            _spec: &spt_protocol::UdpForwardSpec,
        ) -> SptResult<ForwardHandle> {
            Err(Error::RuntimeFailure("no udp".into()))
        }
        async fn keepalive(&mut self) -> SptResult<()> {
            Ok(())
        }
        async fn close(self: Box<Self>) -> SptResult<()> {
            Ok(())
        }
        fn session_info(&self) -> SessionInfo {
            self.info.clone()
        }
    }

    #[derive(Debug)]
    struct EchoForwardProto {
        caps: ProtocolCapabilities,
    }

    #[async_trait]
    impl TunnelProtocol for EchoForwardProto {
        async fn connect(
            &self,
            _endpoint: &Endpoint,
            _auth: &AuthConfig,
        ) -> SptResult<Box<dyn TunnelSession>> {
            Ok(Box::new(EchoForwardSession {
                info: SessionInfo {
                    backend: "echo".into(),
                    peer_version: None,
                    negotiated: None,
                    established_at: 0,
                },
            }))
        }
        fn capabilities(&self) -> ProtocolCapabilities {
            self.caps
        }
        fn name(&self) -> &'static str {
            "echo"
        }
    }

    async fn spawn_active(caps: ProtocolCapabilities) -> Arc<ProfileSupervisor> {
        let proto = Arc::new(EchoForwardProto { caps });
        let sup = Arc::new(ProfileSupervisor::spawn(
            "p",
            proto,
            AuthConfig::new("u", vec![]),
            vec![Endpoint::new("h", 22)],
            vec![],
            ProfileSupervisorConfig::default(),
        ));
        let mut rx = sup.watch_state();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while *rx.borrow() != ProfileStateName::Active {
            assert!(
                tokio::time::Instant::now() < deadline,
                "never reached Active"
            );
            let _ = tokio::time::timeout(Duration::from_millis(100), rx.changed()).await;
        }
        sup
    }

    #[tokio::test]
    async fn live_connector_tcp_round_trips_through_session() {
        // latency/throughput/limits drivers consume open_tcp; prove a live
        // forward opened through the session yields a working echo stream.
        let sup = spawn_active(ProtocolCapabilities::ssh2()).await;
        let conn = SupervisorLiveConnector::new(sup.clone());
        let mut s = conn.open_tcp("bench", 0).await.unwrap();
        s.write_all(b"livebench").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 9];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"livebench");
        drop(s);
        sup.stop().await;
    }

    #[tokio::test]
    async fn live_connector_udp_unsupported_is_structured() {
        // udp driver: structurally unsupported on both SSH2 and SSH3 paths.
        for caps in [ProtocolCapabilities::ssh2(), ProtocolCapabilities::ssh3()] {
            let sup = spawn_active(caps).await;
            let conn = SupervisorLiveConnector::new(sup.clone());
            match conn.open_udp().await {
                Err(Error::UnsupportedPlatform(_)) => {}
                Err(other) => panic!("expected UnsupportedPlatform, got {other:?}"),
                Ok(_) => panic!("expected UnsupportedPlatform, got Ok"),
            }
            sup.stop().await;
        }
    }

    #[tokio::test]
    async fn live_connector_errors_when_not_active() {
        // No supervisor session up → structured "no live session" error.
        let proto = Arc::new(EchoForwardProto {
            caps: ProtocolCapabilities::ssh2(),
        });
        // Spawn but immediately stop so the control channel rejects / no session.
        let sup = Arc::new(ProfileSupervisor::spawn(
            "p",
            proto,
            AuthConfig::new("u", vec![]),
            vec![Endpoint::new("h", 22)],
            vec![],
            ProfileSupervisorConfig::default(),
        ));
        sup.stop().await;
        let conn = SupervisorLiveConnector::new(sup);
        assert!(conn.open_tcp("bench", 0).await.is_err());
    }
}
