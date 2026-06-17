//! SRV-record synthesis from forward configurations.
//!
//! The spec (§13.8) allows the resolver to auto-publish SRV records derived
//! from forwards — e.g. an SMTP forward exposing port 25 can be advertised as
//! `_smtp._tcp.<zone>`. We make this **configurable rather than automatic**:
//! callers describe a [`SrvSource`] (forward name, transport, target port,
//! target host) and ask [`synthesize_srv_records`] for records to mix into a
//! [`crate::ManagedZone`].
//!
//! The implementer of `spt-bin` is responsible for assembling these from the
//! `[[profiles.forwards]]` table; this crate only owns the rendering.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::zone::{normalize_name, AnswerPolicy, Record};

/// Description of a single SRV-emitting forward.
#[derive(Debug, Clone)]
pub struct SrvSource {
    /// Service label (e.g. `smtp`, `imap`, `submissions`). Must NOT include
    /// the leading underscore — that is added by the synthesizer.
    pub service: String,
    /// Transport label: `tcp` or `udp`. Must NOT include the leading
    /// underscore.
    pub transport: String,
    /// Target host name (must be in the same zone — the synthesizer does not
    /// verify this, callers do).
    pub target: String,
    /// Target port number on the listener.
    pub port: u16,
    /// SRV priority (lower is preferred).
    pub priority: u16,
    /// SRV weight (relative weight among equal priorities).
    pub weight: u16,
    /// TTL applied to the synthesized record.
    pub ttl: Duration,
    /// Answer-policy for the synthesized record.
    pub answer_policy: AnswerPolicy,
    /// Forward identifier for health-source gating.
    pub forward_id: Option<String>,
}

/// Synthesize one [`Record`] for each [`SrvSource`] under the given zone
/// suffix. The owner name is `_<service>._<transport>.<zone>.`.
#[must_use]
pub fn synthesize_srv_records(zone_suffix: &str, sources: &[SrvSource]) -> Vec<Record> {
    let zone = normalize_name(zone_suffix);
    sources
        .iter()
        .map(|s| {
            let owner = format!("_{}._{}.{}", s.service, s.transport, zone);
            let mut rec = Record::srv(owner, s.priority, s.weight, s.port, &s.target, s.ttl);
            rec.answer_policy = s.answer_policy;
            rec.forward_id.clone_from(&s.forward_id);
            rec
        })
        .collect()
}

/// The address a forward's listener is reachable at, used to synthesize the
/// address record that backs an auto-derived `dns_name`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardAddr {
    /// IPv4 listener address (synthesizes an `A` record).
    V4(Ipv4Addr),
    /// IPv6 listener address (synthesizes a `AAAA` record).
    V6(Ipv6Addr),
}

/// Description of a single forward whose `dns_names` should be auto-published.
///
/// This is the runtime equivalent of one `[[profiles.forwards]]` entry, as
/// consumed when `[dns] auto_records = true`. The binary (Wave 2) builds one
/// of these per forward from its `dns_names`, its resolved listener address,
/// and (for service-style forwards) optional SRV coordinates, then feeds the
/// slice to [`auto_records_from_forwards`]. `spt-dns` only owns the rendering
/// — it does not read the config or the supervisor.
#[derive(Debug, Clone)]
pub struct ForwardDnsSource {
    /// `dns_names` declared on the forward (`Forward::dns_names`). Each name
    /// gets one address record pointing at [`addr`](Self::addr).
    pub dns_names: Vec<String>,
    /// Listener address the names resolve to. `None` skips address-record
    /// synthesis (e.g. a forward that only contributes an SRV record).
    pub addr: Option<ForwardAddr>,
    /// Optional SRV coordinates. When present, an SRV record is synthesized in
    /// addition to the address records.
    pub srv: Option<SrvSource>,
    /// TTL applied to synthesized address records.
    pub ttl: Duration,
    /// Answer-policy for the synthesized address records (the SRV record
    /// carries its own policy via [`SrvSource::answer_policy`]).
    pub answer_policy: AnswerPolicy,
    /// Forward identifier (`<profile>/<forward>`) for health-source gating of
    /// the address records.
    pub forward_id: Option<String>,
}

/// Auto-synthesize the records for a set of forwards under `zone_suffix`.
///
/// This implements the `[dns] auto_records` behavior at runtime: for each
/// forward, every `dns_name` that falls inside the managed zone yields an
/// address record (`A`/`AAAA`) pointing at the forward's listener, and any
/// declared [`SrvSource`] yields an SRV record. Names outside the zone suffix
/// are skipped (the resolver only answers for names it owns) — the caller does
/// not have to pre-filter.
///
/// The records carry the per-source [`AnswerPolicy`] and `forward_id`, so when
/// they are added to a [`crate::ManagedZone`] the live handler health-gates
/// them through the wired [`crate::HealthSource`] exactly like static records.
#[must_use]
pub fn auto_records_from_forwards(zone_suffix: &str, forwards: &[ForwardDnsSource]) -> Vec<Record> {
    let zone = normalize_name(zone_suffix);
    let mut out = Vec::new();
    for fwd in forwards {
        if let Some(addr) = fwd.addr {
            for name in &fwd.dns_names {
                let owner = normalize_name(name);
                // Only own names inside our zone — the resolver is not
                // authoritative for anything else.
                if owner != zone && !owner.ends_with(&format!(".{zone}")) {
                    continue;
                }
                let mut rec = match addr {
                    ForwardAddr::V4(ip) => Record::a(owner, ip, fwd.ttl),
                    ForwardAddr::V6(ip) => Record::aaaa(owner, ip, fwd.ttl),
                };
                rec.answer_policy = fwd.answer_policy;
                rec.forward_id.clone_from(&fwd.forward_id);
                out.push(rec);
            }
        }
        if let Some(srv) = &fwd.srv {
            out.extend(synthesize_srv_records(
                zone_suffix,
                std::slice::from_ref(srv),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::RecordKind;

    #[test]
    fn synthesize_smtp_srv() {
        let sources = vec![SrvSource {
            service: "smtp".into(),
            transport: "tcp".into(),
            target: "mail.tunnel.local.".into(),
            port: 25,
            priority: 10,
            weight: 5,
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: Some("svc/smtp".into()),
        }];
        let recs = synthesize_srv_records("tunnel.local", &sources);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].name, "_smtp._tcp.tunnel.local.");
        assert_eq!(recs[0].kind, RecordKind::SRV);
        let (p, w, port, target) = recs[0].srv_parts().unwrap();
        assert_eq!(
            (p, w, port, target.as_str()),
            (10, 5, 25, "mail.tunnel.local.")
        );
        assert_eq!(recs[0].forward_id.as_deref(), Some("svc/smtp"));
    }

    fn fwd_v4(names: &[&str], ip: &str) -> ForwardDnsSource {
        ForwardDnsSource {
            dns_names: names.iter().map(|s| (*s).to_string()).collect(),
            addr: Some(ForwardAddr::V4(ip.parse().unwrap())),
            srv: None,
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: Some("svc/web".into()),
        }
    }

    #[test]
    fn auto_records_synthesizes_a_records_for_dns_names() {
        let fwds = vec![fwd_v4(
            &["web.tunnel.local", "api.tunnel.local"],
            "10.0.0.5",
        )];
        let recs = auto_records_from_forwards("tunnel.local", &fwds);
        assert_eq!(recs.len(), 2);
        assert!(recs.iter().all(|r| r.kind == RecordKind::A));
        assert!(recs.iter().any(|r| r.name == "web.tunnel.local."));
        assert!(recs.iter().any(|r| r.name == "api.tunnel.local."));
        assert!(recs.iter().all(|r| r.value == "10.0.0.5"));
        assert!(recs
            .iter()
            .all(|r| r.forward_id.as_deref() == Some("svc/web")));
    }

    #[test]
    fn auto_records_skips_names_outside_zone() {
        // `evil.example.com` is outside `tunnel.local`; must be dropped.
        let fwds = vec![fwd_v4(
            &["web.tunnel.local", "evil.example.com"],
            "10.0.0.5",
        )];
        let recs = auto_records_from_forwards("tunnel.local", &fwds);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].name, "web.tunnel.local.");
    }

    #[test]
    fn auto_records_synthesizes_aaaa_for_v6_addr() {
        let fwds = vec![ForwardDnsSource {
            dns_names: vec!["v6.tunnel.local".into()],
            addr: Some(ForwardAddr::V6("fd00::9".parse().unwrap())),
            srv: None,
            ttl: Duration::from_secs(30),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        }];
        let recs = auto_records_from_forwards("tunnel.local.", &fwds);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].kind, RecordKind::AAAA);
        assert_eq!(recs[0].name, "v6.tunnel.local.");
    }

    #[test]
    fn auto_records_emits_both_address_and_srv() {
        let fwds = vec![ForwardDnsSource {
            dns_names: vec!["mail.tunnel.local".into()],
            addr: Some(ForwardAddr::V4("10.0.0.7".parse().unwrap())),
            srv: Some(SrvSource {
                service: "smtp".into(),
                transport: "tcp".into(),
                target: "mail.tunnel.local.".into(),
                port: 25,
                priority: 10,
                weight: 5,
                ttl: Duration::from_secs(60),
                answer_policy: AnswerPolicy::AnswerWhenHealthy,
                forward_id: Some("mx/smtp".into()),
            }),
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AnswerWhenHealthy,
            forward_id: Some("mx/smtp".into()),
        }];
        let recs = auto_records_from_forwards("tunnel.local", &fwds);
        assert_eq!(recs.len(), 2);
        assert!(recs.iter().any(|r| r.kind == RecordKind::A));
        let srv = recs.iter().find(|r| r.kind == RecordKind::SRV).unwrap();
        assert_eq!(srv.name, "_smtp._tcp.tunnel.local.");
        assert_eq!(srv.answer_policy, AnswerPolicy::AnswerWhenHealthy);
    }

    #[test]
    fn auto_records_address_carries_health_policy() {
        let fwds = vec![ForwardDnsSource {
            dns_names: vec!["gated.tunnel.local".into()],
            addr: Some(ForwardAddr::V4("10.0.0.8".parse().unwrap())),
            srv: None,
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AnswerWhenHealthy,
            forward_id: Some("p/f".into()),
        }];
        let recs = auto_records_from_forwards("tunnel.local", &fwds);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].answer_policy, AnswerPolicy::AnswerWhenHealthy);
        assert_eq!(recs[0].forward_id.as_deref(), Some("p/f"));
    }

    #[test]
    fn auto_records_no_addr_skips_address_records() {
        let fwds = vec![ForwardDnsSource {
            dns_names: vec!["x.tunnel.local".into()],
            addr: None,
            srv: None,
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        }];
        assert!(auto_records_from_forwards("tunnel.local", &fwds).is_empty());
    }
}
