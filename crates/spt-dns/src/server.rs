//! UDP+TCP listener wired to the [`crate::SplitHorizonHandler`].
//!
//! `DnsServer::run` binds a UDP socket and a TCP listener, hands them to a
//! `hickory_server::Server`, and returns a [`DnsHandle`] that owns the
//! server-future task and its shutdown signal.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ProtocolConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use hickory_server::Server;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tracing::info;

use crate::error::{DnsError, Result};
use crate::health::{HealthSource, NoHealth};
use crate::mode::DnsMode;
use crate::split_horizon::SplitHorizonHandler;
use crate::zone::ManagedZone;

const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-connection outgoing response buffer size for the TCP listener.
///
/// hickory 0.26's `Server::register_listener` gained this third argument; 32
/// matches hickory's own internal test default and is ample for a stub
/// resolver that answers one query per connection.
const DEFAULT_TCP_RESPONSE_BUFFER: usize = 32;

/// Build a Tokio resolver fronting every configured upstream (UDP+TCP).
///
/// hickory 0.26 removed `NameServerConfigGroup::from_ips_clear`; we assemble a
/// [`NameServerConfig`] per upstream socket address, each carrying its own
/// port on UDP and TCP `ConnectionConfig`s, then build through
/// `Resolver::builder_with_config`.
fn build_upstream_resolver(upstream: &[SocketAddr], timeout: Duration) -> Result<TokioResolver> {
    let name_servers = upstream
        .iter()
        .map(|addr| {
            let mut udp = hickory_resolver::config::ConnectionConfig::new(ProtocolConfig::Udp);
            udp.port = addr.port();
            let mut tcp = hickory_resolver::config::ConnectionConfig::new(ProtocolConfig::Tcp);
            tcp.port = addr.port();
            NameServerConfig::new(addr.ip(), true, vec![udp, tcp])
        })
        .collect::<Vec<_>>();

    let cfg = ResolverConfig::from_parts(None, vec![], name_servers);
    let mut builder = Resolver::builder_with_config(cfg, TokioRuntimeProvider::default());
    {
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 1;
        opts.use_hosts_file = ResolveHosts::Never;
    }
    builder
        .build()
        .map_err(|e| DnsError::Upstream(e.to_string()))
}

/// Builder for [`DnsServer`].
pub struct DnsServerBuilder {
    bind: Option<SocketAddr>,
    upstream: Vec<SocketAddr>,
    zones: Vec<ManagedZone>,
    health: Arc<dyn HealthSource>,
    tcp_timeout: Duration,
    mode: DnsMode,
}

impl Default for DnsServerBuilder {
    fn default() -> Self {
        Self {
            bind: None,
            upstream: Vec::new(),
            zones: Vec::new(),
            health: Arc::new(NoHealth),
            tcp_timeout: DEFAULT_TCP_TIMEOUT,
            mode: DnsMode::default(),
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

    /// Set the runtime [`DnsMode`] (defaults to
    /// [`DnsMode::TransparentForwarder`]).
    ///
    /// In [`DnsMode::SyntheticOnly`] the listener never recurses upstream:
    /// unmanaged names are `NXDOMAIN` even if [`upstream`](Self::upstream) was
    /// populated. The binary maps the `[dns] mode` config string via
    /// [`DnsMode::from_config_str`] and only calls [`run`](Self::run) for the
    /// listener modes (`disabled` / `hosts_file` start no server).
    #[must_use]
    pub fn mode(mut self, mode: DnsMode) -> Self {
        self.mode = mode;
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
            // hickory 0.26: build one resolver fronting every configured
            // upstream. `NameServerConfigGroup::from_ips_clear` was removed in
            // the 0.25 rework; we assemble a `NameServerConfig` per upstream
            // (UDP+TCP, with each upstream's own port) directly.
            let resolver = build_upstream_resolver(&self.upstream, Duration::from_secs(3))?;
            Some(Arc::new(resolver))
        };

        let handler = SplitHorizonHandler::with_mode(self.zones, upstream, self.health, self.mode);
        let mut server = Server::new(handler);

        let udp = UdpSocket::bind(bind).await?;
        let local_udp = udp.local_addr()?;
        server.register_socket(udp);

        let tcp = TcpListener::bind(bind).await?;
        let local_tcp = tcp.local_addr()?;
        // hickory 0.26 `register_listener` gained a third arg: the per-conn
        // outgoing response buffer size. 32 matches hickory's own test default.
        server.register_listener(tcp, self.tcp_timeout, DEFAULT_TCP_RESPONSE_BUFFER);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::{ManagedZone, Record};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn builder_default_and_new_match() {
        let _b = DnsServerBuilder::new();
        let _b2 = DnsServerBuilder::default();
        // Both compile and accept the fluent chain below.
    }

    #[test]
    fn builder_run_without_bind_returns_config_error() {
        rt().block_on(async {
            let res = DnsServerBuilder::new().run().await;
            match res {
                Err(DnsError::Config(msg)) => {
                    assert!(msg.contains("bind"));
                }
                Err(other) => panic!("expected Config error, got {other:?}"),
                Ok(_) => panic!("expected Config error, got Ok"),
            }
        });
    }

    #[test]
    fn builder_fluent_methods_threaded() {
        rt().block_on(async {
            let mut zone = ManagedZone::new("tunnel.local.");
            zone.add(Record::a(
                "a.tunnel.local.",
                "10.0.0.1".parse().unwrap(),
                Duration::from_secs(60),
            ))
            .unwrap();
            let handle = DnsServerBuilder::new()
                .bind("127.0.0.1:0".parse().unwrap())
                .upstream(vec![]) // empty -> no upstream wired
                .add_zone(zone)
                .health_source(Arc::new(NoHealth))
                .tcp_timeout(Duration::from_millis(500))
                .run()
                .await
                .unwrap();
            // Sanity: ports allocated.
            assert!(handle.udp_addr().port() > 0);
            assert_eq!(handle.udp_addr().ip(), handle.tcp_addr().ip());
            handle.shutdown().await;
        });
    }

    #[test]
    fn builder_run_with_upstream_list_starts_ok() {
        rt().block_on(async {
            let handle = DnsServerBuilder::new()
                .bind("127.0.0.1:0".parse().unwrap())
                .upstream(vec!["127.0.0.1:5353".parse().unwrap()])
                .run()
                .await
                .unwrap();
            assert!(handle.udp_addr().port() > 0);
            handle.shutdown().await;
        });
    }

    #[test]
    fn handle_drop_aborts_task_without_panic() {
        rt().block_on(async {
            let handle = DnsServerBuilder::new()
                .bind("127.0.0.1:0".parse().unwrap())
                .run()
                .await
                .unwrap();
            // Cause Drop without explicit shutdown.
            drop(handle);
        });
    }

    #[test]
    fn handle_udp_and_tcp_addrs_accessible() {
        rt().block_on(async {
            let handle = DnsServerBuilder::new()
                .bind("127.0.0.1:0".parse().unwrap())
                .run()
                .await
                .unwrap();
            let udp = handle.udp_addr();
            let tcp = handle.tcp_addr();
            assert_eq!(udp.ip(), tcp.ip());
            handle.shutdown().await;
        });
    }
}
