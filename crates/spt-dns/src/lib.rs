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
//! - [`zone::ManagedZone`] / [`zone::Record`] — managed-zone description.
//! - [`split_horizon::SplitHorizonHandler`] — the [`hickory_server::server::RequestHandler`]
//!   implementation, exposed in case callers want to host their own server.
//! - [`health::HealthSource`] — trait wired to `spt-supervisor` at runtime so
//!   `AnswerWhenListening` / `AnswerWhenHealthy` policies can consult live
//!   forward state.
//! - [`hosts::HostsManager`] / [`hosts::HostsApplyReport`] — hosts-file
//!   render/apply/restore.
//!
//! See the module docs for the individual building blocks.

#![warn(missing_docs)]

pub mod error;
pub mod health;
pub mod hosts;
pub mod server;
pub mod split_horizon;
pub mod srv;
pub mod zone;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use error::{DnsError, Result};
pub use health::{ForwardHealth, HealthSource, NoHealth};
pub use hosts::{HostsApplyReport, HostsEntry, HostsManager, HOSTS_BEGIN_MARKER, HOSTS_END_MARKER};
pub use server::{DnsHandle, DnsServer, DnsServerBuilder};
pub use split_horizon::SplitHorizonHandler;
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
    use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
    use hickory_resolver::error::ResolveErrorKind;
    use hickory_resolver::TokioAsyncResolver;

    let group = NameServerConfigGroup::from_ips_clear(&[addr.ip()], addr.port(), true);
    let cfg = ResolverConfig::from_parts(None, vec![], group);
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 1;
    opts.use_hosts_file = false;
    let resolver = TokioAsyncResolver::tokio(cfg, opts);

    let lookup = match resolver.lookup(name, kind.to_record_type()).await {
        Ok(l) => l,
        Err(e) => {
            // NXDOMAIN / NoRecordsFound is empty-answer, not an error.
            if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                return Ok(Vec::new());
            }
            return Err(map_resolve_error(&e));
        }
    };

    let mut out = Vec::new();
    for rec in lookup.records() {
        let ttl = Duration::from_secs(u64::from(rec.ttl()));
        let Some(rdata) = rec.data() else { continue };
        let value = match (kind, rdata) {
            (RecordKind::A, RData::A(a)) => a.0.to_string(),
            (RecordKind::AAAA, RData::AAAA(a)) => a.0.to_string(),
            (RecordKind::SRV, RData::SRV(s)) => format!(
                "{} {} {} {}",
                s.priority(),
                s.weight(),
                s.port(),
                s.target()
            ),
            (RecordKind::TXT, RData::TXT(t)) => t
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect::<String>(),
            _ => continue,
        };
        out.push(DnsAnswer { kind, value, ttl });
    }
    Ok(out)
}

fn map_resolve_error(e: &hickory_resolver::error::ResolveError) -> DnsError {
    DnsError::Upstream(e.to_string())
}
