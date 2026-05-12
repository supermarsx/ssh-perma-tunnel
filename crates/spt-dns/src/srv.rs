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
}
