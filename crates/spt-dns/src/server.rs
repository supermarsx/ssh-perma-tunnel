//! UDP+TCP listener wired to the [`crate::SplitHorizonHandler`].
//!
//! `DnsServer::run` binds a UDP socket and a TCP listener, hands them to a
//! `hickory_server::ServerFuture`, and returns a [`DnsHandle`] that owns the
//! server-future task and its shutdown signal.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use hickory_server::ServerFuture;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tracing::info;

use crate::error::{DnsError, Result};
use crate::health::{HealthSource, NoHealth};
use crate::split_horizon::SplitHorizonHandler;
use crate::zone::ManagedZone;

const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// Builder for [`DnsServer`].
pub struct DnsServerBuilder {
    bind: Option<SocketAddr>,
    upstream: Vec<SocketAddr>,
    zones: Vec<ManagedZone>,
    health: Arc<dyn HealthSource>,
    tcp_timeout: Duration,
}

impl Default for DnsServerBuilder {
    fn default() -> Self {
        Self {
            bind: None,
            upstream: Vec::new(),
            zones: Vec::new(),
            health: Arc::new(NoHealth),
            tcp_timeout: DEFAULT_TCP_TIMEOUT,
        }
    }
}

impl DnsServerBuilder {
    /// Start a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Address to bind the UDP and TCP listeners on. Required.
    #[must_use]
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind = Some(addr);
        self
    }

    /// Set the upstream resolver list. An empty list disables the forwarder
    /// path (queries for unmanaged names yield `REFUSED`).
    #[must_use]
    pub fn upstream(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.upstream = addrs;
        self
    }

    /// Append a managed zone.
    #[must_use]
    pub fn add_zone(mut self, zone: ManagedZone) -> Self {
        self.zones.push(zone);
        self
    }

    /// Set the health source consulted for `AnswerWhen{Listening,Healthy}`.
    #[must_use]
    pub fn health_source(mut self, src: Arc<dyn HealthSource>) -> Self {
        self.health = src;
        self
    }

    /// Override the TCP per-request timeout (default 5s).
    #[must_use]
    pub fn tcp_timeout(mut self, d: Duration) -> Self {
        self.tcp_timeout = d;
        self
    }

    /// Bind sockets and start the server.
    ///
    /// Returns a [`DnsHandle`] that controls the lifetime; dropping the
    /// handle aborts the server.
    pub async fn run(self) -> Result<DnsHandle> {
        let bind = self
            .bind
            .ok_or_else(|| DnsError::Config("DnsServerBuilder requires a bind address".into()))?;

        let upstream = if self.upstream.is_empty() {
            None
        } else {
            let group = NameServerConfigGroup::from_ips_clear(
                &self.upstream.iter().map(SocketAddr::ip).collect::<Vec<_>>(),
                self.upstream[0].port(),
                true,
            );
            let cfg = ResolverConfig::from_parts(None, vec![], group);
            let mut opts = ResolverOpts::default();
            opts.timeout = Duration::from_secs(3);
            opts.attempts = 1;
            Some(Arc::new(TokioAsyncResolver::tokio(cfg, opts)))
        };

        let handler = SplitHorizonHandler::new(self.zones, upstream, self.health);
        let mut server = ServerFuture::new(handler);

        let udp = UdpSocket::bind(bind).await?;
        let local_udp = udp.local_addr()?;
        server.register_socket(udp);

        let tcp = TcpListener::bind(bind).await?;
        let local_tcp = tcp.local_addr()?;
        server.register_listener(tcp, self.tcp_timeout);

        info!(udp = %local_udp, tcp = %local_tcp, "spt-dns server bound");

        let task = tokio::spawn(async move {
            if let Err(e) = server.block_until_done().await {
                tracing::warn!(error = %e, "dns server stopped with error");
            }
        });

        Ok(DnsHandle {
            local_udp,
            local_tcp,
            task: Some(task),
        })
    }
}

/// A running DNS server. Drop or `shutdown()` to stop it.
pub struct DnsHandle {
    local_udp: SocketAddr,
    local_tcp: SocketAddr,
    task: Option<JoinHandle<()>>,
}

impl DnsHandle {
    /// Bound UDP listener address (with concrete port if `:0` was requested).
    #[must_use]
    pub fn udp_addr(&self) -> SocketAddr {
        self.local_udp
    }

    /// Bound TCP listener address.
    #[must_use]
    pub fn tcp_addr(&self) -> SocketAddr {
        self.local_tcp
    }

    /// Stop the server (aborts the underlying task).
    pub async fn shutdown(mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
            let _ = t.await;
        }
    }
}

impl Drop for DnsHandle {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

/// Convenience type alias mirroring the spec wording (`DnsServer` runs a
/// transparent resolver).
pub type DnsServer = DnsHandle;
