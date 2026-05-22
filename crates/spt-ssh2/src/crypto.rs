//! Crypto policy: cipher / KEX / MAC / host-key allow-lists.
//!
//! Spec §9.13.1 mandates that a profile's `crypto` table acts as an
//! allow-list. Pre-t7 this module rendered the allow-lists into libssh2
//! `method_pref` comma-strings; the russh backend now consumes the typed
//! [`russh::Preferred`] struct directly (see
//! [`crate::russh_backend::build_preferred`]). What survives in this file
//! is the typed [`CryptoPolicy`] config struct plus the
//! deprecated-algorithm warning helper that fires once per profile load.

use serde::{Deserialize, Serialize};

/// Algorithms classified as "deprecated" by spec §9.13.1; we emit a warning
/// when any of these are seen on the wire.
const DEPRECATED: &[&str] = &[
    "ssh-rsa",
    "ssh-dss",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "hmac-sha1",
    "hmac-sha1-96",
    "hmac-md5",
    "hmac-md5-96",
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
];

/// Post-quantum or hybrid post-quantum SSH KEX method names recognized by
/// config validation and diagnostics.
///
/// **t8-B1 update:** the vendored russh fork (`vendor/russh-fork`) now
/// implements `mlkem768x25519-sha256` natively (see
/// `russh::kex::MLKEM768X25519_SHA256`). Profiles selecting that algorithm
/// will negotiate successfully against any peer that also speaks it
/// (OpenSSH ≥ 9.9). Other entries in this list remain config-recognized
/// but not yet wired in russh; selecting them still fails negotiation.
pub const POST_QUANTUM_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "mlkem768x25519-sha256@openssh.com",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
];

/// ML-KEM hybrid SSH KEX method names recognized by config validation and
/// diagnostics. See [`POST_QUANTUM_KEX`] for the russh 0.46 caveat.
pub const ML_KEM_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "mlkem768x25519-sha256@openssh.com",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384",
];

/// Allow-lists per algorithm category. Empty list = "library default".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CryptoPolicy {
    /// Symmetric ciphers (client-to-server and server-to-client).
    #[serde(default)]
    pub ciphers: Vec<String>,
    /// Key-exchange algorithms.
    #[serde(default)]
    pub kex: Vec<String>,
    /// MAC algorithms.
    #[serde(default)]
    pub macs: Vec<String>,
    /// Server host-key types accepted from the peer.
    #[serde(default)]
    pub host_keys: Vec<String>,
    /// Compression algorithms (`none`, `zlib@openssh.com`).
    #[serde(default)]
    pub compression: Vec<String>,
}

impl CryptoPolicy {
    /// Yield warnings for any deprecated algorithm present in the policy.
    pub fn deprecated_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        for cat in [
            ("cipher", &self.ciphers),
            ("kex", &self.kex),
            ("mac", &self.macs),
            ("hostkey", &self.host_keys),
        ] {
            for algo in cat.1 {
                if DEPRECATED.iter().any(|d| d.eq_ignore_ascii_case(algo)) {
                    warnings.push(format!(
                        "deprecated {} algorithm `{}` is allowed by crypto policy (spec §9.13.1)",
                        cat.0, algo
                    ));
                }
            }
        }
        warnings
    }

    /// Whether the policy explicitly requests a recognized post-quantum KEX.
    #[must_use]
    pub fn has_post_quantum_kex(&self) -> bool {
        self.kex
            .iter()
            .any(|algo| contains_ignore_ascii_case(POST_QUANTUM_KEX, algo))
    }

    /// Whether the policy explicitly requests a recognized ML-KEM KEX.
    #[must_use]
    pub fn has_ml_kem_kex(&self) -> bool {
        self.kex
            .iter()
            .any(|algo| contains_ignore_ascii_case(ML_KEM_KEX, algo))
    }
}

fn contains_ignore_ascii_case(values: &[&str], needle: &str) -> bool {
    values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_warnings_empty() {
        let p = CryptoPolicy::default();
        assert!(p.deprecated_warnings().is_empty());
    }

    #[test]
    fn warns_on_legacy_ciphers() {
        let p = CryptoPolicy {
            ciphers: vec!["aes128-cbc".into(), "aes256-gcm@openssh.com".into()],
            host_keys: vec!["ssh-rsa".into()],
            ..Default::default()
        };
        let w = p.deprecated_warnings();
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w.iter().any(|s| s.contains("aes128-cbc")));
        assert!(w.iter().any(|s| s.contains("ssh-rsa")));
    }

    #[test]
    fn modern_set_clean() {
        let p = CryptoPolicy {
            ciphers: vec!["aes256-gcm@openssh.com".into()],
            kex: vec!["curve25519-sha256".into()],
            macs: vec!["hmac-sha2-512-etm@openssh.com".into()],
            host_keys: vec!["ssh-ed25519".into()],
            compression: vec!["none".into()],
        };
        assert!(p.deprecated_warnings().is_empty());
    }

    #[test]
    fn classifies_post_quantum_kex() {
        let p = CryptoPolicy {
            kex: vec!["curve25519-sha256".into(), "mlkem768x25519-sha256".into()],
            ..Default::default()
        };
        assert!(p.has_post_quantum_kex());
        assert!(p.has_ml_kem_kex());
    }

    #[test]
    fn classifies_sntrup_as_pq_not_ml_kem() {
        let p = CryptoPolicy {
            kex: vec!["sntrup761x25519-sha512@openssh.com".into()],
            ..Default::default()
        };
        assert!(p.has_post_quantum_kex());
        assert!(!p.has_ml_kem_kex());
    }
}
