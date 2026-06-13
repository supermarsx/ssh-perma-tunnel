//! Public test facilities for `spt-dns` (gated behind `feature = "testing"`).
//!
//! These helpers let downstream crates and integration tests spin up a real
//! split-horizon DNS server on `127.0.0.1:0`, populate managed zones with a
//! fluent builder, and substitute a fake [`crate::HealthSource`].

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::health::{ForwardHealth, HealthSource};
use crate::server::{DnsHandle, DnsServerBuilder};
use crate::zone::{ManagedZone, Record};
use crate::Result;

const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Fluent builder for a [`ManagedZone`].
///
/// ```
/// use spt_dns::testing::FakeZone;
///
/// let zone = FakeZone::new("tunnel.local.")
///     .a("mail.tunnel.local.", "10.0.0.7".parse().unwrap())
///     .txt("info.tunnel.local.", "hello")
///     .build();
/// assert_eq!(zone.records.len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct FakeZone {
    suffix: String,
    records: Vec<Record>,
    ttl: Duration,
}

impl FakeZone {
    /// Start a builder rooted at `suffix` (FQDN, with or without trailing dot).
    pub fn new(suffix: impl Into<String>) -> Self {
        Self {
            suffix: suffix.into(),
            records: Vec::new(),
            ttl: DEFAULT_TTL,
        }
    }

    /// Override the default TTL applied to subsequently-added records.
    #[must_use]
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Append an `A` record.
    #[must_use]
    pub fn a(mut self, name: impl Into<String>, ipv4: Ipv4Addr) -> Self {
        self.records.push(Record::a(name, ipv4, self.ttl));
        self
    }

    /// Append a `AAAA` record.
    #[must_use]
    pub fn aaaa(mut self, name: impl Into<String>, ipv6: Ipv6Addr) -> Self {
        self.records.push(Record::aaaa(name, ipv6, self.ttl));
        self
    }

    /// Append a `SRV` record.
    #[must_use]
    pub fn srv(
        mut self,
        name: impl Into<String>,
        target: impl Into<String>,
        port: u16,
        priority: u16,
        weight: u16,
    ) -> Self {
        let target = target.into();
        self.records
            .push(Record::srv(name, priority, weight, port, target, self.ttl));
        self
    }

    /// Append a `TXT` record.
    #[must_use]
    pub fn txt(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.records.push(Record::txt(name, value, self.ttl));
        self
    }

    /// Materialize the [`ManagedZone`].
    #[must_use]
    pub fn build(self) -> ManagedZone {
        ManagedZone {
            suffix: self.suffix,
            records: self.records,
        }
    }
}

/// A running DNS server bound on `127.0.0.1:0` for tests.
///
/// Constructed with [`LocalhostResolver::start`]. Drop runs the underlying
/// `DnsHandle::Drop` (aborts the server task).
///
/// ```no_run
/// # async fn doc() {
/// use spt_dns::testing::{FakeZone, LocalhostResolver};
///
/// let zone = FakeZone::new("tunnel.local.")
///     .a("mail.tunnel.local.", "10.0.0.7".parse().unwrap())
///     .build();
/// let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
/// assert!(resolver.port() > 0);
/// resolver.shutdown().await;
/// # }
/// ```
pub struct LocalhostResolver {
    handle: DnsHandle,
}

impl LocalhostResolver {
    /// Bind a [`crate::DnsServer`] on `127.0.0.1:0` with `zones`.
    pub async fn start(zones: Vec<ManagedZone>) -> Result<Self> {
        let mut b = DnsServerBuilder::new().bind("127.0.0.1:0".parse().unwrap());
        for z in zones {
            b = b.add_zone(z);
        }
        let handle = b.run().await?;
        Ok(Self { handle })
    }

    /// Bind with a custom [`HealthSource`].
    pub async fn start_with_health(
        zones: Vec<ManagedZone>,
        health: Arc<dyn HealthSource>,
    ) -> Result<Self> {
        let mut b = DnsServerBuilder::new()
            .bind("127.0.0.1:0".parse().unwrap())
            .health_source(health);
        for z in zones {
            b = b.add_zone(z);
        }
        let handle = b.run().await?;
        Ok(Self { handle })
    }

    /// Bound UDP port (also the TCP port — both share the bind addr).
    #[must_use]
    pub fn port(&self) -> u16 {
        self.handle.udp_addr().port()
    }

    /// Bound UDP socket address.
    #[must_use]
    pub fn udp_addr(&self) -> std::net::SocketAddr {
        self.handle.udp_addr()
    }

    /// Bound TCP socket address.
    #[must_use]
    pub fn tcp_addr(&self) -> std::net::SocketAddr {
        self.handle.tcp_addr()
    }

    /// Stop the server and await the underlying task.
    pub async fn shutdown(self) {
        self.handle.shutdown().await;
    }
}

/// Constant [`HealthSource`] returning the configured `(listening, healthy)`
/// pair for every forward id.
///
/// ```
/// use spt_dns::testing::FakeHealthSource;
/// use spt_dns::HealthSource;
///
/// let rt = tokio::runtime::Builder::new_current_thread()
///     .build()
///     .unwrap();
/// rt.block_on(async {
///     let h = FakeHealthSource(true);
///     assert!(h.forward_health("p/f").await.healthy);
///     let h = FakeHealthSource(false);
///     assert!(!h.forward_health("p/f").await.healthy);
/// });
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FakeHealthSource(pub bool);

#[async_trait]
impl HealthSource for FakeHealthSource {
    async fn forward_health(&self, _forward_id: &str) -> ForwardHealth {
        if self.0 {
            ForwardHealth::up()
        } else {
            ForwardHealth::down()
        }
    }
}

/// Pre-built fixtures.
pub mod fixtures {
    use super::{FakeZone, ManagedZone};

    /// A minimal loopback zone with two A records under `tunnel.local.`.
    ///
    /// ```
    /// let z = spt_dns::testing::fixtures::loopback_zone();
    /// assert_eq!(z.suffix, "tunnel.local.");
    /// assert!(z.records.len() >= 2);
    /// ```
    #[must_use]
    pub fn loopback_zone() -> ManagedZone {
        FakeZone::new("tunnel.local.")
            .a("alpha.tunnel.local.", "127.0.0.1".parse().unwrap())
            .a("beta.tunnel.local.", "127.0.0.2".parse().unwrap())
            .txt("info.tunnel.local.", "spt-test")
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::RecordKind;
    use hickory_proto::rr::{RData, RecordType};
    use hickory_resolver::config::ResolveHosts;

    #[test]
    fn fake_zone_builder_collects_records() {
        let z = FakeZone::new("tunnel.local.")
            .a("a.tunnel.local.", "10.0.0.1".parse().unwrap())
            .aaaa("a6.tunnel.local.", "fd00::1".parse().unwrap())
            .srv("_smtp._tcp.tunnel.local.", "mail.tunnel.local.", 25, 10, 5)
            .txt("info.tunnel.local.", "hello")
            .build();
        assert_eq!(z.records.len(), 4);
        assert!(z.records.iter().any(|r| r.kind == RecordKind::A));
        assert!(z.records.iter().any(|r| r.kind == RecordKind::AAAA));
        assert!(z.records.iter().any(|r| r.kind == RecordKind::SRV));
        assert!(z.records.iter().any(|r| r.kind == RecordKind::TXT));
    }

    #[tokio::test]
    async fn localhost_resolver_answers_managed_name() {
        let zone = fixtures::loopback_zone();
        let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
        let port = resolver.port();
        assert!(port > 0);

        // hickory 0.26: build the test client through the crate's shared
        // `build_tokio_resolver` helper (the old `NameServerConfigGroup` +
        // `TokioAsyncResolver::tokio` construction was removed in the 0.25
        // rework).
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let client =
            crate::build_tokio_resolver(addr, Duration::from_secs(2), ResolveHosts::Never).unwrap();

        let lookup = client
            .lookup("alpha.tunnel.local.", RecordType::A)
            .await
            .expect("query resolves");
        let mut found = false;
        for rec in lookup.answers() {
            if let RData::A(a) = &rec.data {
                assert_eq!(a.0, Ipv4Addr::new(127, 0, 0, 1));
                found = true;
            }
        }
        assert!(found, "expected A record");

        resolver.shutdown().await;
    }

    #[tokio::test]
    async fn fake_health_source_returns_configured_state() {
        let up = FakeHealthSource(true).forward_health("x/y").await;
        assert!(up.healthy && up.listening);
        let down = FakeHealthSource(false).forward_health("x/y").await;
        assert!(!down.healthy && !down.listening);
    }

    #[test]
    fn fake_zone_ttl_setter_applies_to_subsequent_records() {
        let custom = Duration::from_secs(7);
        let z = FakeZone::new("tunnel.local.")
            .ttl(custom)
            .a("a.tunnel.local.", "10.0.0.1".parse().unwrap())
            .build();
        assert_eq!(z.records[0].ttl, custom);
    }

    #[test]
    fn loopback_zone_fixture_contents() {
        let z = fixtures::loopback_zone();
        assert_eq!(z.suffix, "tunnel.local.");
        assert!(z.records.iter().any(|r| r.kind == RecordKind::A));
        assert!(z.records.iter().any(|r| r.kind == RecordKind::TXT));
    }

    #[tokio::test]
    async fn localhost_resolver_with_health_starts() {
        let zone = fixtures::loopback_zone();
        let r = LocalhostResolver::start_with_health(vec![zone], Arc::new(FakeHealthSource(true)))
            .await
            .unwrap();
        assert!(r.port() > 0);
        assert_eq!(r.udp_addr().ip(), r.tcp_addr().ip());
        r.shutdown().await;
    }
}
