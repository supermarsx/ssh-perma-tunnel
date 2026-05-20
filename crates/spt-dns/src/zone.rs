//! Managed-zone model.
//!
//! A [`ManagedZone`] is the in-memory equivalent of a `[dns]` block plus its
//! `[[dns.records]]` entries from the spec (§9.4 / §13.8). Each [`Record`]
//! carries an [`AnswerPolicy`] that controls whether the resolver actually
//! answers the request — `AnswerWhenListening` and `AnswerWhenHealthy` consult
//! the wired-in [`crate::HealthSource`].

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{DnsError, Result};

/// Resource-record kind. A subset of hickory's `RecordType` covering the four
/// types the spec mandates support for: A / AAAA / SRV / TXT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)] // DNS RRTYPE wire names are upper-case.
pub enum RecordKind {
    /// IPv4 address.
    A,
    /// IPv6 address.
    AAAA,
    /// Service location (priority/weight/port/target).
    SRV,
    /// Free-form text.
    TXT,
}

impl RecordKind {
    /// Map to a hickory `RecordType`.
    #[must_use]
    pub fn to_record_type(self) -> hickory_proto::rr::RecordType {
        match self {
            Self::A => hickory_proto::rr::RecordType::A,
            Self::AAAA => hickory_proto::rr::RecordType::AAAA,
            Self::SRV => hickory_proto::rr::RecordType::SRV,
            Self::TXT => hickory_proto::rr::RecordType::TXT,
        }
    }
}

/// Whether to answer a managed record at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum AnswerPolicy {
    /// Always synthesize an answer.
    #[default]
    AlwaysAnswer,
    /// Only answer if the underlying forward has an active listener bound.
    AnswerWhenListening,
    /// Only answer if the forward is fully healthy (running with a live
    /// session and at least one healthy connection / heartbeat).
    AnswerWhenHealthy,
}

/// A single managed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Owner name (FQDN with or without trailing dot — both accepted).
    pub name: String,
    /// Record kind.
    pub kind: RecordKind,
    /// Record value. Format depends on `kind`:
    ///
    /// - `A` — dotted IPv4 (`10.0.0.1`).
    /// - `AAAA` — IPv6 (`fd00::1`).
    /// - `SRV` — `priority weight port target` (whitespace-separated). The
    ///   convenience builder [`Record::srv`] produces the canonical form.
    /// - `TXT` — opaque string; will be split into 255-byte segments at
    ///   serialization time as required by RFC 1035.
    pub value: String,
    /// TTL applied to answers for this record.
    pub ttl: Duration,
    /// Answer-policy gate.
    pub answer_policy: AnswerPolicy,
    /// Optional forward identifier — used by `AnswerWhenListening` /
    /// `AnswerWhenHealthy` to query the [`crate::HealthSource`].
    ///
    /// Format: `"<profile>/<forward>"`.
    pub forward_id: Option<String>,
}

impl Record {
    /// Build an A record with [`AnswerPolicy::AlwaysAnswer`].
    pub fn a(name: impl Into<String>, addr: Ipv4Addr, ttl: Duration) -> Self {
        Self {
            name: name.into(),
            kind: RecordKind::A,
            value: addr.to_string(),
            ttl,
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        }
    }

    /// Build a AAAA record with [`AnswerPolicy::AlwaysAnswer`].
    pub fn aaaa(name: impl Into<String>, addr: Ipv6Addr, ttl: Duration) -> Self {
        Self {
            name: name.into(),
            kind: RecordKind::AAAA,
            value: addr.to_string(),
            ttl,
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        }
    }

    /// Build a SRV record. `priority weight port target` is encoded into
    /// `value`.
    pub fn srv(
        name: impl Into<String>,
        priority: u16,
        weight: u16,
        port: u16,
        target: impl AsRef<str>,
        ttl: Duration,
    ) -> Self {
        Self {
            name: name.into(),
            kind: RecordKind::SRV,
            value: format!("{priority} {weight} {port} {}", target.as_ref()),
            ttl,
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        }
    }

    /// Build a TXT record.
    pub fn txt(name: impl Into<String>, text: impl Into<String>, ttl: Duration) -> Self {
        Self {
            name: name.into(),
            kind: RecordKind::TXT,
            value: text.into(),
            ttl,
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        }
    }

    /// Set the answer policy and (optionally) the forward this record is
    /// associated with for health gating.
    #[must_use]
    pub fn with_policy(mut self, policy: AnswerPolicy, forward_id: Option<String>) -> Self {
        self.answer_policy = policy;
        self.forward_id = forward_id;
        self
    }

    /// Validate the record (used by [`ManagedZone::add`]).
    pub fn validate(&self) -> Result<()> {
        match self.kind {
            RecordKind::A => {
                self.value
                    .parse::<Ipv4Addr>()
                    .map(|_| ())
                    .map_err(|e| DnsError::InvalidValue {
                        kind: self.kind,
                        value: self.value.clone(),
                        reason: e.to_string(),
                    })
            }
            RecordKind::AAAA => {
                self.value
                    .parse::<Ipv6Addr>()
                    .map(|_| ())
                    .map_err(|e| DnsError::InvalidValue {
                        kind: self.kind,
                        value: self.value.clone(),
                        reason: e.to_string(),
                    })
            }
            RecordKind::SRV => {
                let parts: Vec<&str> = self.value.split_whitespace().collect();
                if parts.len() != 4 {
                    return Err(DnsError::InvalidValue {
                        kind: self.kind,
                        value: self.value.clone(),
                        reason: "SRV value must be `priority weight port target`".into(),
                    });
                }
                for (idx, label) in ["priority", "weight", "port"].iter().enumerate() {
                    parts[idx]
                        .parse::<u16>()
                        .map_err(|e| DnsError::InvalidValue {
                            kind: self.kind,
                            value: self.value.clone(),
                            reason: format!("invalid {label}: {e}"),
                        })?;
                }
                Ok(())
            }
            RecordKind::TXT => Ok(()),
        }
    }

    /// SRV-only accessor: `(priority, weight, port, target)`.
    pub(crate) fn srv_parts(&self) -> Option<(u16, u16, u16, String)> {
        if self.kind != RecordKind::SRV {
            return None;
        }
        let parts: Vec<&str> = self.value.split_whitespace().collect();
        if parts.len() != 4 {
            return None;
        }
        Some((
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].parse().ok()?,
            parts[3].to_string(),
        ))
    }
}

/// A zone tree of [`Record`]s rooted at `suffix` (e.g. `tunnel.local.`).
///
/// `ManagedZone` is **not** a hickory `Authority` — the split-horizon handler
/// looks up records directly in the zone, which keeps the trait surface small
/// and policy filters easy to apply.
#[derive(Debug, Clone, Default)]
pub struct ManagedZone {
    /// Zone suffix (FQDN, with or without trailing dot).
    pub suffix: String,
    /// Records belonging to this zone.
    pub records: Vec<Record>,
}

impl ManagedZone {
    /// Create an empty zone with the given suffix.
    pub fn new(suffix: impl Into<String>) -> Self {
        Self {
            suffix: suffix.into(),
            records: Vec::new(),
        }
    }

    /// Append a record after validating it.
    pub fn add(&mut self, record: Record) -> Result<()> {
        record.validate()?;
        self.records.push(record);
        Ok(())
    }

    /// Returns true if `name` (FQDN, dot-insensitive) belongs to this zone.
    #[must_use]
    pub fn contains_name(&self, name: &str) -> bool {
        let n = normalize_name(name);
        let s = normalize_name(&self.suffix);
        n == s || n.ends_with(&format!(".{s}"))
    }

    /// Lookup all records for `name` of the given `kind`.
    #[must_use]
    pub fn lookup<'a>(&'a self, name: &str, kind: RecordKind) -> Vec<&'a Record> {
        let n = normalize_name(name);
        self.records
            .iter()
            .filter(|r| r.kind == kind && normalize_name(&r.name) == n)
            .collect()
    }
}

/// Lower-case + ensure a trailing dot for FQDN comparisons.
pub(crate) fn normalize_name(name: &str) -> String {
    let mut s = name.trim().to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_validate_a() {
        let r = Record::a(
            "foo.tunnel.",
            "10.0.0.1".parse().unwrap(),
            Duration::from_secs(60),
        );
        assert!(r.validate().is_ok());
    }

    #[test]
    fn record_validate_a_bad() {
        let r = Record {
            name: "foo.tunnel.".into(),
            kind: RecordKind::A,
            value: "not-an-ip".into(),
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn srv_parts_roundtrip() {
        let r = Record::srv(
            "_smtp._tcp.tunnel.",
            10,
            20,
            25,
            "mail.tunnel.",
            Duration::from_secs(60),
        );
        let (p, w, port, target) = r.srv_parts().unwrap();
        assert_eq!((p, w, port, target.as_str()), (10, 20, 25, "mail.tunnel."));
    }

    #[test]
    fn zone_contains_name() {
        let z = ManagedZone::new("tunnel.local.");
        assert!(z.contains_name("foo.tunnel.local"));
        assert!(z.contains_name("tunnel.local."));
        assert!(!z.contains_name("example.com"));
    }

    #[test]
    fn zone_lookup_case_insensitive() {
        let mut z = ManagedZone::new("tunnel.local.");
        z.add(Record::a(
            "Foo.tunnel.local.",
            "10.0.0.1".parse().unwrap(),
            Duration::from_secs(60),
        ))
        .unwrap();
        assert_eq!(z.lookup("foo.tunnel.local", RecordKind::A).len(), 1);
        assert_eq!(z.lookup("FOO.TUNNEL.LOCAL.", RecordKind::A).len(), 1);
    }

    #[test]
    fn record_validate_aaaa_good_and_bad() {
        let good = Record::aaaa(
            "v6.tunnel.",
            "fd00::1".parse().unwrap(),
            Duration::from_secs(60),
        );
        assert!(good.validate().is_ok());
        let bad = Record {
            name: "v6.tunnel.".into(),
            kind: RecordKind::AAAA,
            value: "not-an-ipv6".into(),
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        };
        let err = bad.validate().unwrap_err();
        assert!(matches!(
            err,
            DnsError::InvalidValue {
                kind: RecordKind::AAAA,
                ..
            }
        ));
    }

    #[test]
    fn record_validate_srv_wrong_arity() {
        let r = Record {
            name: "_svc.".into(),
            kind: RecordKind::SRV,
            value: "10 20 25".into(), // missing target
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        };
        let err = r.validate().unwrap_err();
        match err {
            DnsError::InvalidValue { reason, .. } => {
                assert!(reason.contains("priority weight port target"));
            }
            other => panic!("unexpected err: {other:?}"),
        }
    }

    #[test]
    fn record_validate_srv_bad_port() {
        let r = Record {
            name: "_svc.".into(),
            kind: RecordKind::SRV,
            value: "10 20 not-a-port mail.".into(),
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        };
        let err = r.validate().unwrap_err();
        match err {
            DnsError::InvalidValue { reason, .. } => assert!(reason.contains("invalid port")),
            other => panic!("unexpected err: {other:?}"),
        }
    }

    #[test]
    fn record_validate_srv_bad_priority() {
        let r = Record {
            name: "_svc.".into(),
            kind: RecordKind::SRV,
            value: "abc 20 25 mail.".into(),
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        };
        let err = r.validate().unwrap_err();
        match err {
            DnsError::InvalidValue { reason, .. } => assert!(reason.contains("invalid priority")),
            other => panic!("unexpected err: {other:?}"),
        }
    }

    #[test]
    fn record_txt_validate_always_ok() {
        let r = Record::txt("t.tunnel.", "any contents", Duration::from_secs(60));
        assert!(r.validate().is_ok());
    }

    #[test]
    fn record_srv_constructor_yields_valid_value() {
        let r = Record::srv(
            "_svc.tunnel.",
            1,
            2,
            3,
            "target.tunnel.",
            Duration::from_secs(30),
        );
        assert!(r.validate().is_ok());
        assert_eq!(r.kind, RecordKind::SRV);
    }

    #[test]
    fn srv_parts_none_for_non_srv() {
        let r = Record::a(
            "a.tunnel.",
            "1.2.3.4".parse().unwrap(),
            Duration::from_secs(60),
        );
        assert!(r.srv_parts().is_none());
    }

    #[test]
    fn srv_parts_none_for_malformed_srv() {
        let r = Record {
            name: "x.".into(),
            kind: RecordKind::SRV,
            value: "garbage".into(), // wrong arity
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        };
        assert!(r.srv_parts().is_none());
    }

    #[test]
    fn srv_parts_none_for_unparseable_numbers() {
        let r = Record {
            name: "x.".into(),
            kind: RecordKind::SRV,
            value: "abc def ghi jkl".into(),
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        };
        assert!(r.srv_parts().is_none());
    }

    #[test]
    fn with_policy_threads_through() {
        let r = Record::a(
            "a.tunnel.",
            "1.2.3.4".parse().unwrap(),
            Duration::from_secs(60),
        )
        .with_policy(AnswerPolicy::AnswerWhenListening, Some("p/f".into()));
        assert_eq!(r.answer_policy, AnswerPolicy::AnswerWhenListening);
        assert_eq!(r.forward_id.as_deref(), Some("p/f"));
    }

    #[test]
    fn record_kind_to_record_type() {
        use hickory_proto::rr::RecordType;
        assert_eq!(RecordKind::A.to_record_type(), RecordType::A);
        assert_eq!(RecordKind::AAAA.to_record_type(), RecordType::AAAA);
        assert_eq!(RecordKind::SRV.to_record_type(), RecordType::SRV);
        assert_eq!(RecordKind::TXT.to_record_type(), RecordType::TXT);
    }

    #[test]
    fn answer_policy_default_is_always_answer() {
        assert_eq!(AnswerPolicy::default(), AnswerPolicy::AlwaysAnswer);
    }

    #[test]
    fn normalize_name_lowercases_and_appends_dot() {
        assert_eq!(normalize_name("EXAMPLE.com"), "example.com.");
        assert_eq!(normalize_name("example.com."), "example.com.");
        assert_eq!(normalize_name("  spaced.example  "), "spaced.example.");
    }

    #[test]
    fn managed_zone_add_rejects_invalid_record() {
        let mut z = ManagedZone::new("tunnel.local.");
        let bad = Record {
            name: "bad.tunnel.local.".into(),
            kind: RecordKind::A,
            value: "not-an-ip".into(),
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        };
        assert!(z.add(bad).is_err());
        assert!(z.records.is_empty());
    }

    #[test]
    fn managed_zone_contains_name_dot_insensitive() {
        let z = ManagedZone::new("tunnel.local"); // no trailing dot
        assert!(z.contains_name("foo.tunnel.local"));
        assert!(z.contains_name("foo.tunnel.local."));
        assert!(z.contains_name("tunnel.local"));
        // suffix-only must not match a subdomain that ends similarly:
        assert!(!z.contains_name("nottunnel.local"));
    }
}
