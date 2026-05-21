//! Crypto policy: cipher / KEX / MAC / host-key allow-lists translated to
//! libssh2 `method_pref` strings.
//!
//! Spec §9.13.1 mandates that a profile's `crypto` table acts as an
//! allow-list. This module renders allow-lists into the comma-separated
//! algorithm strings libssh2 expects (no order change — first preference is
//! first listed) and emits a `tracing::warn!` when a deprecated algorithm is
//! present.

use serde::{Deserialize, Serialize};
use ssh2::MethodType;

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
pub const POST_QUANTUM_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "mlkem768x25519-sha256@openssh.com",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
];

/// ML-KEM hybrid SSH KEX method names recognized by config validation and
/// diagnostics.
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
    /// Translate the policy into a list of `(MethodType, comma-string)`
    /// suitable for `Session::method_pref`. Empty categories are omitted.
    #[must_use]
    pub fn to_method_prefs(&self) -> Vec<(MethodType, String)> {
        let mut out = Vec::new();
        let cipher_csv = comma(&self.ciphers);
        if !cipher_csv.is_empty() {
            out.push((MethodType::CryptCs, cipher_csv.clone()));
            out.push((MethodType::CryptSc, cipher_csv));
        }
        if !self.kex.is_empty() {
            out.push((MethodType::Kex, comma(&self.kex)));
        }
        let mac_csv = comma(&self.macs);
        if !mac_csv.is_empty() {
            out.push((MethodType::MacCs, mac_csv.clone()));
            out.push((MethodType::MacSc, mac_csv));
        }
        if !self.host_keys.is_empty() {
            out.push((MethodType::HostKey, comma(&self.host_keys)));
        }
        let comp_csv = comma(&self.compression);
        if !comp_csv.is_empty() {
            out.push((MethodType::CompCs, comp_csv.clone()));
            out.push((MethodType::CompSc, comp_csv));
        }
        out
    }

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

fn comma(v: &[String]) -> String {
    v.join(",")
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
    fn empty_policy_emits_no_prefs() {
        let p = CryptoPolicy::default();
        assert!(p.to_method_prefs().is_empty());
        assert!(p.deprecated_warnings().is_empty());
    }

    #[test]
    fn ciphers_split_into_cs_and_sc() {
        let p = CryptoPolicy {
            ciphers: vec![
                "aes256-gcm@openssh.com".into(),
                "chacha20-poly1305@openssh.com".into(),
            ],
            ..Default::default()
        };
        let prefs = p.to_method_prefs();
        // Both directions present.
        assert_eq!(prefs.len(), 2);
        assert!(prefs.iter().any(|(t, _)| matches!(t, MethodType::CryptCs)));
        assert!(prefs.iter().any(|(t, _)| matches!(t, MethodType::CryptSc)));
        for (_, s) in &prefs {
            assert_eq!(s, "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com");
        }
    }

    #[test]
    fn kex_and_macs_and_hostkeys_render() {
        let p = CryptoPolicy {
            kex: vec![
                "curve25519-sha256".into(),
                "diffie-hellman-group14-sha256".into(),
            ],
            macs: vec!["hmac-sha2-256-etm@openssh.com".into()],
            host_keys: vec!["ssh-ed25519".into(), "rsa-sha2-512".into()],
            ..Default::default()
        };
        let prefs = p.to_method_prefs();
        let kex = prefs
            .iter()
            .find(|(t, _)| matches!(t, MethodType::Kex))
            .unwrap();
        assert_eq!(kex.1, "curve25519-sha256,diffie-hellman-group14-sha256");
        let hk = prefs
            .iter()
            .find(|(t, _)| matches!(t, MethodType::HostKey))
            .unwrap();
        assert_eq!(hk.1, "ssh-ed25519,rsa-sha2-512");
        // Both MAC directions:
        let mac_cnt = prefs
            .iter()
            .filter(|(t, _)| matches!(t, MethodType::MacCs | MethodType::MacSc))
            .count();
        assert_eq!(mac_cnt, 2);
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
