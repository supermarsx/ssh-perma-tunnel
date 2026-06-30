//! Transparent DNS resolver and hosts-file manager for `spt`.
//!
//! This crate implements spec §13.8: a built-in DNS server (disabled by
//! default) with **split-horizon** semantics — managed names from the active
//! `[dns]` zone are answered locally, everything else is forwarded to the
//! configured upstreams. It also owns the hosts-file render/apply/restore
//! lifecycle, with a managed-block marker so it never clobbers user-authored
//! lines outside the markers.
//!
//! Public surface:
//! - [`server::DnsServer`] / [`server::DnsServerBuilder`] — listener + handler.
//!   The builder takes a [`mode::DnsMode`] so the configured `[dns] mode` is
//!   honored at runtime (forwarder vs authoritative/synthetic-only).
//! - [`mode::DnsMode`] — runtime listener posture mapped from the `[dns] mode`
//!   config string (`DnsMode::from_config_str`).
//! - [`zone::ManagedZone`] / [`zone::Record`] — managed-zone description.
//! - [`srv::synthesize_srv_records`] / [`srv::auto_records_from_forwards`] —
//!   auto-derive A/AAAA/SRV records from a forward's `dns_names` (the
//!   `[dns] auto_records` behavior), mixed into a [`zone::ManagedZone`].
//! - [`split_horizon::SplitHorizonHandler`] — the [`hickory_server::server::RequestHandler`]
//!   implementation, exposed in case callers want to host their own server.
//! - [`health::HealthSource`] — trait wired to `spt-supervisor` at runtime so
//!   `AnswerWhenListening` / `AnswerWhenHealthy` policies can consult live
//!   forward state. [`health::NoHealth`] / [`health::AlwaysHealthy`] are the
//!   default seams when no supervisor source is injected.
//! - [`hosts::HostsManager`] / [`hosts::HostsApplyReport`] — hosts-file
//!   render/apply/restore.
//!
//! See the module docs for the individual building blocks.

#![warn(missing_docs)]

pub mod error;
pub mod forward_acl;
pub mod health;
pub mod hosts;
pub mod mode;
pub mod server;
pub mod split_horizon;
pub mod srv;
pub mod zone;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use error::{DnsError, Result};
pub use forward_acl::ForwardScope;
pub use health::{AlwaysHealthy, ForwardHealth, HealthSource, NoHealth};
pub use hosts::{HostsApplyReport, HostsEntry, HostsManager, HOSTS_BEGIN_MARKER, HOSTS_END_MARKER};
pub use mode::DnsMode;
pub use server::{DnsHandle, DnsServer, DnsServerBuilder};
pub use split_horizon::SplitHorizonHandler;
pub use srv::{
    auto_records_from_forwards, synthesize_srv_records, ForwardAddr, ForwardDnsSource, SrvSource,
};
pub use zone::{AnswerPolicy, ManagedZone, Record, RecordKind};

// ---------------------------------------------------------------------------
// CLI-facing helpers used by `spt dns query` and friends.
// ---------------------------------------------------------------------------

use std::net::SocketAddr;
use std::time::Duration;

/// Result of a one-shot DNS query.
///
/// Mirrors the answer-section data that `spt dns query` formats. The
/// strings are already rendered (`A` → dotted-quad, `AAAA` → colon-hex,
/// `SRV` → `priority weight port target`, `TXT` → joined chunks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    /// Record kind that was answered.
    pub kind: RecordKind,
    /// Rendered value.
    pub value: String,
    /// TTL as advertised by the resolver.
    pub ttl: Duration,
}

/// Issue a one-shot DNS query against a specific resolver address.
///
/// Used by the `spt dns query` CLI to talk to a running spt's loopback
/// resolver, but useful in tests too — a short timeout (2s) and a single
/// attempt mean the call returns quickly when the resolver is unreachable.
///
/// Returns the answer section as a list of [`DnsAnswer`]. An empty vector
/// means `NXDOMAIN` / no records of the requested type — this is **not**
/// an error.
pub async fn query_resolver(
    addr: SocketAddr,
    name: &str,
    kind: RecordKind,
) -> Result<Vec<DnsAnswer>> {
    use hickory_proto::rr::RData;
    use hickory_resolver::config::ResolveHosts;

    // hickory 0.26: the resolver is built via `Resolver::builder_with_config`
    // + a `TokioRuntimeProvider`; `TokioAsyncResolver::tokio`/
    // `NameServerConfigGroup` were removed in the 0.25 rework.
    let resolver = build_tokio_resolver(addr, Duration::from_secs(2), ResolveHosts::Never)?;

    let lookup = match resolver.lookup(name, kind.to_record_type()).await {
        Ok(l) => l,
        Err(e) => {
            // NXDOMAIN / NoRecordsFound is empty-answer, not an error.
            if e.is_no_records_found() {
                return Ok(Vec::new());
            }
            return Err(map_resolve_error(&e));
        }
    };

    let mut out = Vec::new();
    for rec in lookup.answers() {
        let ttl = Duration::from_secs(u64::from(rec.ttl));
        let rdata = &rec.data;
        let value = match (kind, rdata) {
            (RecordKind::A, RData::A(a)) => a.0.to_string(),
            (RecordKind::AAAA, RData::AAAA(a)) => a.0.to_string(),
            (RecordKind::SRV, RData::SRV(s)) => {
                format!("{} {} {} {}", s.priority, s.weight, s.port, s.target)
            }
            (RecordKind::TXT, RData::TXT(t)) => t
                .txt_data
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect::<String>(),
            _ => continue,
        };
        out.push(DnsAnswer { kind, value, ttl });
    }
    Ok(out)
}

fn map_resolve_error(e: &hickory_resolver::net::NetError) -> DnsError {
    DnsError::Upstream(e.to_string())
}

/// Build a single-upstream Tokio resolver pointed at `addr`.
///
/// Centralizes the hickory 0.26 builder dance so `query_resolver`, the
/// [`server`] forwarder, and tests share one construction path. The 0.26
/// resolver is generic over a runtime provider and built through
/// `Resolver::builder_with_config` (the old `TokioAsyncResolver::tokio` +
/// `NameServerConfigGroup::from_ips_clear` constructors were removed in the
/// 0.25 rework). A `NameServerConfig` is assembled directly from the IP with
/// UDP+TCP `ConnectionConfig`s carrying the requested port.
pub(crate) fn build_tokio_resolver(
    addr: SocketAddr,
    timeout: Duration,
    use_hosts_file: hickory_resolver::config::ResolveHosts,
) -> Result<hickory_resolver::TokioResolver> {
    use hickory_resolver::config::{NameServerConfig, ProtocolConfig, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::Resolver;

    let ns = NameServerConfig::new(
        addr.ip(),
        true,
        vec![
            connection_on_port(ProtocolConfig::Udp, addr.port()),
            connection_on_port(ProtocolConfig::Tcp, addr.port()),
        ],
    );
    let cfg = ResolverConfig::from_parts(None, vec![], vec![ns]);

    let mut builder = Resolver::builder_with_config(cfg, TokioRuntimeProvider::default());
    {
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 1;
        opts.use_hosts_file = use_hosts_file;
    }
    builder
        .build()
        .map_err(|e| DnsError::Upstream(e.to_string()))
}

/// Helper: a [`ConnectionConfig`](hickory_resolver::config::ConnectionConfig)
/// for `protocol` bound to a non-default `port`.
fn connection_on_port(
    protocol: hickory_resolver::config::ProtocolConfig,
    port: u16,
) -> hickory_resolver::config::ConnectionConfig {
    let mut c = hickory_resolver::config::ConnectionConfig::new(protocol);
    c.port = port;
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeZone, LocalhostResolver};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn query_resolver_a_record() {
        rt().block_on(async {
            let zone = FakeZone::new("tunnel.local.")
                .a("a.tunnel.local.", "10.0.0.1".parse().unwrap())
                .build();
            let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
            let addr = resolver.udp_addr();
            let answers = query_resolver(addr, "a.tunnel.local.", RecordKind::A)
                .await
                .unwrap();
            assert_eq!(answers.len(), 1);
            assert_eq!(answers[0].kind, RecordKind::A);
            assert_eq!(answers[0].value, "10.0.0.1");
            assert!(answers[0].ttl >= Duration::from_secs(1));
            resolver.shutdown().await;
        });
    }

    #[test]
    fn query_resolver_aaaa_record() {
        rt().block_on(async {
            let zone = FakeZone::new("tunnel.local.")
                .aaaa("v6.tunnel.local.", "fd00::1".parse().unwrap())
                .build();
            let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
            let addr = resolver.udp_addr();
            let answers = query_resolver(addr, "v6.tunnel.local.", RecordKind::AAAA)
                .await
                .unwrap();
            assert_eq!(answers.len(), 1);
            assert_eq!(answers[0].kind, RecordKind::AAAA);
            assert!(answers[0].value.contains("fd00"));
            resolver.shutdown().await;
        });
    }

    #[test]
    fn query_resolver_srv_record() {
        rt().block_on(async {
            let zone = FakeZone::new("tunnel.local.")
                .srv("_smtp._tcp.tunnel.local.", "mail.tunnel.local.", 25, 10, 5)
                .build();
            let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
            let addr = resolver.udp_addr();
            let answers = query_resolver(addr, "_smtp._tcp.tunnel.local.", RecordKind::SRV)
                .await
                .unwrap();
            assert_eq!(answers.len(), 1);
            assert_eq!(answers[0].kind, RecordKind::SRV);
            assert!(answers[0].value.starts_with("10 5 25 "));
            assert!(answers[0].value.contains("mail.tunnel.local"));
            resolver.shutdown().await;
        });
    }

    #[test]
    fn query_resolver_txt_record() {
        rt().block_on(async {
            let zone = FakeZone::new("tunnel.local.")
                .txt("info.tunnel.local.", "spt-test-value")
                .build();
            let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
            let addr = resolver.udp_addr();
            let answers = query_resolver(addr, "info.tunnel.local.", RecordKind::TXT)
                .await
                .unwrap();
            assert_eq!(answers.len(), 1);
            assert_eq!(answers[0].kind, RecordKind::TXT);
            assert_eq!(answers[0].value, "spt-test-value");
            resolver.shutdown().await;
        });
    }

    #[test]
    fn query_resolver_missing_name_returns_empty_not_error() {
        rt().block_on(async {
            let zone = FakeZone::new("tunnel.local.")
                .a("a.tunnel.local.", "10.0.0.1".parse().unwrap())
                .build();
            let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
            let addr = resolver.udp_addr();
            let answers = query_resolver(addr, "ghost.tunnel.local.", RecordKind::A)
                .await
                .unwrap();
            assert!(answers.is_empty());
            resolver.shutdown().await;
        });
    }

    #[test]
    fn query_resolver_unreachable_port_does_not_panic() {
        rt().block_on(async {
            let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
            let res = query_resolver(addr, "example.com.", RecordKind::A).await;
            match res {
                Ok(v) => assert!(v.is_empty(), "expected empty answer set on unreachable"),
                Err(DnsError::Upstream(_)) => {}
                Err(other) => panic!("unexpected error variant: {other:?}"),
            }
        });
    }

    #[test]
    fn map_resolve_error_produces_upstream_variant() {
        rt().block_on(async {
            use hickory_resolver::config::ResolveHosts;
            let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
            let resolver =
                build_tokio_resolver(addr, Duration::from_millis(50), ResolveHosts::Never).unwrap();
            if let Err(e) = resolver
                .lookup("example.invalid.", hickory_proto::rr::RecordType::A)
                .await
            {
                let mapped = map_resolve_error(&e);
                assert!(matches!(mapped, DnsError::Upstream(_)));
                let _ = format!("{mapped}");
            }
        });
    }

    #[test]
    fn dns_answer_equality_and_debug() {
        let a = DnsAnswer {
            kind: RecordKind::A,
            value: "1.2.3.4".into(),
            ttl: Duration::from_secs(60),
        };
        let b = a.clone();
        assert_eq!(a, b);
        let _ = format!("{a:?}");
    }
}
