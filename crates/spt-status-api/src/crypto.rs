//! Negotiated-crypto overlay for the status API.
//!
//! `spt status` (`/v1/status`, `/v1/sessions`) re-serializes
//! [`spt_state::status::StatusSnapshot`] / `SessionStatus` **verbatim**, and
//! `spt-state` is out of this crate's ownership — it has no free-form field
//! for negotiated cryptographic parameters. Mechanism 3 of the observability
//! plan (surface the negotiated crypto per session over the status API) is
//! therefore delivered as an **additive overlay** owned by this crate:
//!
//! * [`NegotiatedCrypto`] — the consumer-side struct. It is produced by
//!   parsing the canonical token string that the ssh2/ssh3 transports write
//!   into `spt_protocol::session::SessionInfo.negotiated`.
//! * [`NegotiatedCryptoRegistry`] — a cheaply-clonable, side-table handle
//!   (`Arc<RwLock<HashMap<session-id, NegotiatedCrypto>>>`) held in
//!   `AppState`, populated by `spt-bin` at session establishment, and merged
//!   into the `/v1/sessions` and `/v1/status` JSON responses by the handlers,
//!   keyed by session id.
//!
//! ## Canonical token-string contract
//!
//! Producers (ssh2/ssh3) write `SessionInfo.negotiated` as space-separated
//! `key=value` tokens, `transport=` first, absent params omitted, values have
//! no spaces. Reserved keys:
//!
//! ```text
//! transport, kex, hostkey, cipher, mac_c2s, mac_s2c, comp_c2s, comp_s2c,
//! pq_offered, tls_version, cipher_suite, kex_group, alpn, sni
//! ```
//!
//! ssh2 sample:
//! ```text
//! transport=ssh2 kex=mlkem768x25519-sha256 hostkey=ssh-ed25519 \
//!   cipher=chacha20-poly1305@openssh.com mac_c2s=hmac-sha2-256-etm@openssh.com \
//!   mac_s2c=hmac-sha2-256-etm@openssh.com comp_c2s=none comp_s2c=none pq_offered=true
//! ```
//! ssh3 sample:
//! ```text
//! transport=ssh3 tls_version=TLS1.3 alpn=h3 sni=example.com
//! ```
//!
//! The token `hostkey` maps to the struct field `host_key_algo`. `pq_offered`
//! parses to `Option<bool>`; everything else is `Option<String>`. A parseable
//! payload MUST carry a `transport=` token — legacy free-text such as
//! `"russh negotiated algorithms"` has none and is ignored (parse => `None`).

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Negotiated cryptographic parameters for a single session.
///
/// Populated by parsing the canonical token string (see module docs). Fields
/// left unset by the producer stay `None` and are omitted from JSON via
/// `skip_serializing_if`.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct NegotiatedCrypto {
    /// Transport family (`ssh2` / `ssh3`). Always present in a parsed value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Key-exchange algorithm (ssh2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kex: Option<String>,
    /// Host-key / server host-key signature algorithm (ssh2). Parsed from the
    /// `hostkey=` token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key_algo: Option<String>,
    /// Symmetric cipher (ssh2 negotiates a single cipher for both directions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    /// Client-to-server MAC (ssh2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_c2s: Option<String>,
    /// Server-to-client MAC (ssh2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_s2c: Option<String>,
    /// Client-to-server compression (ssh2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comp_c2s: Option<String>,
    /// Server-to-client compression (ssh2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comp_s2c: Option<String>,
    /// Whether a post-quantum KEX was offered (ssh2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_offered: Option<bool>,
    /// TLS version (ssh3 — always `TLS1.3`, QUIC mandates it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    /// TLS cipher suite (reserved; not reachable via quinn's public API today).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    /// TLS key-exchange group (reserved; not reachable via quinn today).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kex_group: Option<String>,
    /// Negotiated ALPN protocol (ssh3, e.g. `h3`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// Server Name Indication (ssh3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
}

impl NegotiatedCrypto {
    /// Parse the canonical space-separated `key=value` token string.
    ///
    /// Returns `None` when no `transport=` token is present, so legacy
    /// free-text carriers (e.g. `"russh negotiated algorithms"`) are ignored.
    /// Unknown keys are tolerated (silently skipped) and missing keys stay
    /// `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut nc = NegotiatedCrypto::default();
        let mut saw_transport = false;
        for token in s.split_whitespace() {
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            match key {
                "transport" => {
                    saw_transport = true;
                    nc.transport = Some(value.to_string());
                }
                "kex" => nc.kex = Some(value.to_string()),
                "hostkey" => nc.host_key_algo = Some(value.to_string()),
                "cipher" => nc.cipher = Some(value.to_string()),
                "mac_c2s" => nc.mac_c2s = Some(value.to_string()),
                "mac_s2c" => nc.mac_s2c = Some(value.to_string()),
                "comp_c2s" => nc.comp_c2s = Some(value.to_string()),
                "comp_s2c" => nc.comp_s2c = Some(value.to_string()),
                "pq_offered" => nc.pq_offered = Some(value.eq_ignore_ascii_case("true")),
                "tls_version" => nc.tls_version = Some(value.to_string()),
                "cipher_suite" => nc.cipher_suite = Some(value.to_string()),
                "kex_group" => nc.kex_group = Some(value.to_string()),
                "alpn" => nc.alpn = Some(value.to_string()),
                "sni" => nc.sni = Some(value.to_string()),
                // Unknown/reserved-future keys are tolerated.
                _ => {}
            }
        }
        if saw_transport {
            Some(nc)
        } else {
            None
        }
    }

    /// Emit `(key, value)` pairs for each populated field, using stable key
    /// names matching the token contract. Intended for bus-event / log field
    /// emission by `spt-bin`.
    #[must_use]
    pub fn fields(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = Vec::new();
        if let Some(v) = &self.transport {
            out.push(("transport", v.clone()));
        }
        if let Some(v) = &self.kex {
            out.push(("kex", v.clone()));
        }
        if let Some(v) = &self.host_key_algo {
            out.push(("host_key", v.clone()));
        }
        if let Some(v) = &self.cipher {
            out.push(("cipher", v.clone()));
        }
        if let Some(v) = &self.mac_c2s {
            out.push(("mac_c2s", v.clone()));
        }
        if let Some(v) = &self.mac_s2c {
            out.push(("mac_s2c", v.clone()));
        }
        if let Some(v) = &self.comp_c2s {
            out.push(("comp_c2s", v.clone()));
        }
        if let Some(v) = &self.comp_s2c {
            out.push(("comp_s2c", v.clone()));
        }
        if let Some(v) = self.pq_offered {
            out.push(("pq_offered", v.to_string()));
        }
        if let Some(v) = &self.tls_version {
            out.push(("tls_version", v.clone()));
        }
        if let Some(v) = &self.cipher_suite {
            out.push(("cipher_suite", v.clone()));
        }
        if let Some(v) = &self.kex_group {
            out.push(("kex_group", v.clone()));
        }
        if let Some(v) = &self.alpn {
            out.push(("alpn", v.clone()));
        }
        if let Some(v) = &self.sni {
            out.push(("sni", v.clone()));
        }
        out
    }
}

/// Cheaply-clonable handle over a session-id -> [`NegotiatedCrypto`] side
/// table.
///
/// This is the additive overlay described in the module docs: `spt-bin`
/// [`insert`](NegotiatedCryptoRegistry::insert)s negotiated crypto keyed by
/// session id at establishment; the status-API handlers merge a
/// [`snapshot`](NegotiatedCryptoRegistry::snapshot) of it into the sessions
/// JSON. Cloning shares the same underlying map (`Arc`).
#[derive(Clone, Default)]
pub struct NegotiatedCryptoRegistry {
    inner: Arc<RwLock<HashMap<String, NegotiatedCrypto>>>,
}

impl NegotiatedCryptoRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or overwrite) the negotiated crypto for `session_id`.
    pub fn insert(&self, session_id: impl Into<String>, nc: NegotiatedCrypto) {
        self.inner.write().insert(session_id.into(), nc);
    }

    /// Remove the entry for `session_id`, if any (e.g. on session teardown).
    pub fn remove(&self, session_id: &str) {
        self.inner.write().remove(session_id);
    }

    /// Snapshot the whole table (cloned) for the handler to merge.
    #[must_use]
    pub fn snapshot(&self) -> HashMap<String, NegotiatedCrypto> {
        self.inner.read().clone()
    }

    /// Look up a single session's negotiated crypto (cloned).
    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<NegotiatedCrypto> {
        self.inner.read().get(session_id).cloned()
    }

    /// Number of tracked sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSH2_SAMPLE: &str = "transport=ssh2 kex=mlkem768x25519-sha256 hostkey=ssh-ed25519 \
         cipher=chacha20-poly1305@openssh.com mac_c2s=hmac-sha2-256-etm@openssh.com \
         mac_s2c=hmac-sha2-256-etm@openssh.com comp_c2s=none comp_s2c=none pq_offered=true";

    const SSH3_SAMPLE: &str = "transport=ssh3 tls_version=TLS1.3 alpn=h3 sni=example.com";

    #[test]
    fn parse_ssh2_sample_round_trips_all_fields() {
        let nc = NegotiatedCrypto::parse(SSH2_SAMPLE).expect("ssh2 sample parses");
        assert_eq!(nc.transport.as_deref(), Some("ssh2"));
        assert_eq!(nc.kex.as_deref(), Some("mlkem768x25519-sha256"));
        // `hostkey=` token -> `host_key_algo` field.
        assert_eq!(nc.host_key_algo.as_deref(), Some("ssh-ed25519"));
        assert_eq!(nc.cipher.as_deref(), Some("chacha20-poly1305@openssh.com"));
        assert_eq!(nc.mac_c2s.as_deref(), Some("hmac-sha2-256-etm@openssh.com"));
        assert_eq!(nc.mac_s2c.as_deref(), Some("hmac-sha2-256-etm@openssh.com"));
        assert_eq!(nc.comp_c2s.as_deref(), Some("none"));
        assert_eq!(nc.comp_s2c.as_deref(), Some("none"));
        assert_eq!(nc.pq_offered, Some(true));
        // ssh3-only fields absent.
        assert!(nc.tls_version.is_none());
        assert!(nc.alpn.is_none());
        assert!(nc.sni.is_none());
    }

    #[test]
    fn parse_ssh3_sample_round_trips_all_fields() {
        let nc = NegotiatedCrypto::parse(SSH3_SAMPLE).expect("ssh3 sample parses");
        assert_eq!(nc.transport.as_deref(), Some("ssh3"));
        assert_eq!(nc.tls_version.as_deref(), Some("TLS1.3"));
        assert_eq!(nc.alpn.as_deref(), Some("h3"));
        assert_eq!(nc.sni.as_deref(), Some("example.com"));
        // ssh2-only fields absent.
        assert!(nc.kex.is_none());
        assert!(nc.cipher.is_none());
        assert!(nc.pq_offered.is_none());
    }

    #[test]
    fn parse_rejects_legacy_free_text_without_transport() {
        assert!(NegotiatedCrypto::parse("russh negotiated algorithms").is_none());
        assert!(NegotiatedCrypto::parse("TLS1.3 + QUIC + h3 (raw bootstrap)").is_none());
        assert!(NegotiatedCrypto::parse("").is_none());
    }

    #[test]
    fn parse_tolerates_unknown_and_missing_keys() {
        let nc = NegotiatedCrypto::parse("transport=ssh2 novel_key=whatever kex=curve25519-sha256")
            .expect("still parses with a transport token");
        assert_eq!(nc.transport.as_deref(), Some("ssh2"));
        assert_eq!(nc.kex.as_deref(), Some("curve25519-sha256"));
        assert!(nc.cipher.is_none());
    }

    #[test]
    fn pq_offered_false_parses() {
        let nc = NegotiatedCrypto::parse("transport=ssh2 pq_offered=false").expect("parses");
        assert_eq!(nc.pq_offered, Some(false));
    }

    #[test]
    fn fields_emit_stable_key_names() {
        let nc = NegotiatedCrypto::parse(SSH2_SAMPLE).expect("parses");
        let fields = nc.fields();
        assert!(fields.contains(&("transport", "ssh2".to_string())));
        // host_key_algo is emitted under the contract key `host_key`.
        assert!(fields.contains(&("host_key", "ssh-ed25519".to_string())));
        assert!(fields.contains(&("pq_offered", "true".to_string())));
        // No key for an absent field.
        assert!(!fields.iter().any(|(k, _)| *k == "alpn"));
    }

    #[test]
    fn absent_fields_omitted_from_json() {
        let nc = NegotiatedCrypto::parse(SSH3_SAMPLE).expect("parses");
        let v = serde_json::to_value(&nc).expect("serializes");
        let obj = v.as_object().expect("object");
        assert!(obj.contains_key("transport"));
        assert!(obj.contains_key("tls_version"));
        // ssh2-only fields must not clutter the ssh3 object.
        assert!(!obj.contains_key("kex"));
        assert!(!obj.contains_key("cipher"));
        assert!(!obj.contains_key("pq_offered"));
    }

    #[test]
    fn json_round_trips_through_serde() {
        let nc = NegotiatedCrypto::parse(SSH2_SAMPLE).expect("parses");
        let raw = serde_json::to_string(&nc).expect("serialize");
        let back: NegotiatedCrypto = serde_json::from_str(&raw).expect("deserialize");
        assert_eq!(nc, back);
    }

    #[test]
    fn registry_insert_snapshot_and_get() {
        let reg = NegotiatedCryptoRegistry::new();
        assert!(reg.is_empty());
        let nc = NegotiatedCrypto::parse(SSH2_SAMPLE).expect("parses");
        reg.insert("session-1", nc.clone());
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.get("session-1"), Some(nc.clone()));
        assert_eq!(reg.snapshot().get("session-1"), Some(&nc));
        assert!(reg.get("missing").is_none());
        reg.remove("session-1");
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_clone_shares_storage() {
        let a = NegotiatedCryptoRegistry::new();
        let b = a.clone();
        let nc = NegotiatedCrypto::parse(SSH3_SAMPLE).expect("parses");
        a.insert("s", nc.clone());
        // Clone observes the same underlying map.
        assert_eq!(b.get("s"), Some(nc));
    }
}
