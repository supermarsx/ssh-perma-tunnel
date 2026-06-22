//! Crypto policy: cipher / KEX / MAC / host-key allow-lists.
//!
//! Spec §9.13.1 mandates that a profile's `crypto` table acts as an
//! allow-list. Pre-t7 this module rendered the allow-lists into libssh2
//! `method_pref` comma-strings; the russh backend now consumes the typed
//! [`russh::Preferred`] struct directly (see
//! `crate::russh_backend::build_preferred`). What survives in this file
//! is the typed [`CryptoPolicy`] config struct plus the
//! deprecated-algorithm warning helper that fires once per profile load.

use serde::{Deserialize, Serialize};
use spt_core::{Error, Result};

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
/// (OpenSSH ≥ 9.9).
///
/// **t8-B2 update (partial):** `sntrup761x25519-sha512` and its legacy
/// `@openssh.com`-suffixed alias are now registered in the russh fork's
/// `KEXES` table (see `russh::kex::SNTRUP761X25519_SHA512`) and the wire-
/// format / hybrid-KDF skeleton is in place — but the sntrup761 KEM
/// primitive itself is **not yet wired**. Negotiating either sntrup name
/// today succeeds at the algorithm-list step but fails at `client_dh` /
/// `server_dh` with `russh::Error::Kex`. Three operator-decidable resume
/// paths are documented in `vendor/russh-fork/russh/src/kex/sntrup761.rs`
/// and `.orchestration/logs/t8-B2.md`.
///
/// Other entries in this list remain config-recognized but not yet wired
/// in russh; selecting them still fails negotiation.
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

// ---------------------------------------------------------------------------
// Crypto policy presets (spec §9.13.1)
// ---------------------------------------------------------------------------
//
// Each preset is a per-category allow-list. The factory's `build_crypto_policy`
// calls [`resolve_crypto_policy`]: any category the operator left empty is
// filled from the selected preset; explicitly-listed categories override it.
// MODERN excludes every algorithm in [`DEPRECATED`]; INTEROP adds the
// widely-deployed but non-PQ classics; LEGACY additionally re-admits a handful
// of deprecated algorithms for talking to ancient servers (and therefore only
// resolves cleanly with `allow_deprecated = true`).

/// Modern, deprecation-free preset. No algorithm here appears in
/// [`DEPRECATED`].
pub const MODERN: CryptoPreset = CryptoPreset {
    ciphers: &[
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
    ],
    kex: &[
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
    ],
    macs: &[
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
    ],
    host_keys: &[
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ],
    compression: &["none"],
};

/// Interop preset: MODERN plus the broadly-deployed non-deprecated classics
/// (CTR ciphers, group14-sha256, plain SHA-2 MACs) for talking to slightly
/// older but still-secure servers. Still deprecation-free.
pub const INTEROP: CryptoPreset = CryptoPreset {
    ciphers: &[
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
    ],
    kex: &[
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256",
    ],
    macs: &[
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
    ],
    host_keys: &[
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ],
    compression: &["none", "zlib@openssh.com"],
};

/// Legacy preset: INTEROP plus deprecated algorithms (SHA-1 KEX/MAC, CBC
/// ciphers, `ssh-rsa`) needed to reach ancient servers. Because it includes
/// [`DEPRECATED`] entries it only resolves when `allow_deprecated = true`.
pub const LEGACY: CryptoPreset = CryptoPreset {
    ciphers: &[
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
        "aes256-cbc",
        "aes128-cbc",
        "3des-cbc",
    ],
    kex: &[
        "curve25519-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    ],
    macs: &[
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1",
    ],
    host_keys: &[
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
    ],
    compression: &["none", "zlib@openssh.com"],
};

/// A named crypto preset: a per-category allow-list resolved into a
/// [`CryptoPolicy`] by [`resolve_crypto_policy`]. The well-known presets are
/// [`MODERN`], [`INTEROP`] and [`LEGACY`].
#[derive(Debug, Clone, Copy)]
pub struct CryptoPreset {
    /// Symmetric cipher allow-list.
    pub ciphers: &'static [&'static str],
    /// Key-exchange allow-list.
    pub kex: &'static [&'static str],
    /// MAC allow-list.
    pub macs: &'static [&'static str],
    /// Host-key-type allow-list.
    pub host_keys: &'static [&'static str],
    /// Compression allow-list.
    pub compression: &'static [&'static str],
}

impl CryptoPreset {
    /// Look a preset up by its config name (`"modern"` / `"interop"` /
    /// `"legacy"`, case-insensitive). Returns `None` for an unknown name so
    /// the caller can emit a config diagnostic naming the valid set.
    #[must_use]
    pub fn by_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "modern" => Some(MODERN),
            "interop" => Some(INTEROP),
            "legacy" => Some(LEGACY),
            _ => None,
        }
    }
}

/// True when `algo` is classified as deprecated by spec §9.13.1.
#[must_use]
pub fn is_deprecated(algo: &str) -> bool {
    DEPRECATED.iter().any(|d| d.eq_ignore_ascii_case(algo))
}

/// Best-effort safer replacement to name in a deprecation warning. Used only
/// for operator-facing diagnostics, not for selection.
fn safer_replacement(algo: &str) -> &'static str {
    let a = algo.to_ascii_lowercase();
    match a.as_str() {
        "ssh-rsa" => "rsa-sha2-256 / rsa-sha2-512",
        "ssh-dss" => "ssh-ed25519",
        "diffie-hellman-group1-sha1"
        | "diffie-hellman-group14-sha1"
        | "diffie-hellman-group-exchange-sha1" => "curve25519-sha256",
        "hmac-sha1" | "hmac-sha1-96" | "hmac-md5" | "hmac-md5-96" => {
            "hmac-sha2-256-etm@openssh.com"
        }
        "3des-cbc" | "aes128-cbc" | "aes192-cbc" | "aes256-cbc" | "blowfish-cbc"
        | "cast128-cbc" => "aes256-gcm@openssh.com / chacha20-poly1305@openssh.com",
        "arcfour" | "arcfour128" | "arcfour256" => "aes256-gcm@openssh.com",
        _ => "a modern algorithm (see spec §9.13.1)",
    }
}

/// Resolve a profile's `crypto` config into the effective [`CryptoPolicy`] the
/// russh backend's `build_preferred` consumes — the function the factory's
/// `build_crypto_policy` calls.
///
/// Inputs:
/// * `preset` — selected preset name (`"modern"` / `"interop"` / `"legacy"`).
///   `None` selects [`MODERN`].
/// * `explicit` — the operator's explicitly-configured per-category lists. Any
///   category left **empty** falls back to the preset's list; a non-empty
///   category overrides the preset entirely for that category.
/// * `allow_deprecated` — when `false`, a selected algorithm that is in
///   [`DEPRECATED`] is a hard error ([`Error::InvalidConfig`]). When `true`,
///   deprecated algorithms are permitted.
/// * `warn_on_deprecated` — when `true`, emit one `tracing::warn!` per selected
///   deprecated algorithm (naming the algorithm, the active preset and a safer
///   replacement). Independent of `allow_deprecated`.
///
/// Errors with [`Error::InvalidConfig`] for an unknown preset name, or for a
/// deprecated algorithm selected while `allow_deprecated == false`.
pub fn resolve_crypto_policy(
    preset: Option<&str>,
    explicit: &CryptoPolicy,
    allow_deprecated: bool,
    warn_on_deprecated: bool,
) -> Result<CryptoPolicy> {
    let preset_name = preset.unwrap_or("modern");
    let set = CryptoPreset::by_name(preset_name).ok_or_else(|| {
        Error::InvalidConfig(format!(
            "unknown crypto.policy preset `{preset_name}`; valid presets are \
             `modern`, `interop`, `legacy`"
        ))
    })?;

    let fill = |explicit: &[String], preset: &[&'static str]| -> Vec<String> {
        if explicit.is_empty() {
            preset.iter().map(|s| (*s).to_owned()).collect()
        } else {
            explicit.to_vec()
        }
    };

    let policy = CryptoPolicy {
        ciphers: fill(&explicit.ciphers, set.ciphers),
        kex: fill(&explicit.kex, set.kex),
        macs: fill(&explicit.macs, set.macs),
        host_keys: fill(&explicit.host_keys, set.host_keys),
        compression: fill(&explicit.compression, set.compression),
    };

    // Scan the *resolved* selection for deprecated algorithms.
    for (category, algos) in [
        ("cipher", &policy.ciphers),
        ("kex", &policy.kex),
        ("mac", &policy.macs),
        ("hostkey", &policy.host_keys),
    ] {
        for algo in algos {
            if !is_deprecated(algo) {
                continue;
            }
            if !allow_deprecated {
                return Err(Error::InvalidConfig(format!(
                    "deprecated {category} algorithm `{algo}` selected (preset `{preset_name}`) \
                     but `crypto.allow_deprecated` is false; set `allow_deprecated = true` to \
                     permit it, or switch to a safer algorithm such as `{}` (spec §9.13.1)",
                    safer_replacement(algo)
                )));
            }
            if warn_on_deprecated {
                tracing::warn!(
                    target: "spt_ssh2::crypto",
                    algorithm = %algo,
                    category = category,
                    preset = preset_name,
                    safer_replacement = safer_replacement(algo),
                    "crypto policy allows a deprecated {category} algorithm `{algo}` \
                     (preset `{preset_name}`); consider `{}` instead (spec §9.13.1)",
                    safer_replacement(algo),
                );
            }
        }
    }

    Ok(policy)
}

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

    // ──────── crypto.policy presets + deprecation (spec §9.13.1) ───────────

    #[test]
    fn preset_by_name_is_case_insensitive() {
        assert!(CryptoPreset::by_name("modern").is_some());
        assert!(CryptoPreset::by_name("INTEROP").is_some());
        assert!(CryptoPreset::by_name("Legacy").is_some());
        assert!(CryptoPreset::by_name("nonsense").is_none());
    }

    #[test]
    fn modern_preset_is_deprecation_free() {
        // The MODERN preset must contain zero DEPRECATED algorithms in any
        // category — that is its defining property.
        for set in [MODERN.ciphers, MODERN.kex, MODERN.macs, MODERN.host_keys] {
            for algo in set {
                assert!(!is_deprecated(algo), "MODERN leaked deprecated `{algo}`");
            }
        }
    }

    #[test]
    fn empty_explicit_lists_fall_back_to_preset() {
        // Every category empty ⇒ the resolved policy equals the preset.
        let resolved =
            resolve_crypto_policy(Some("modern"), &CryptoPolicy::default(), false, false).unwrap();
        let expect = |s: &[&str]| s.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(resolved.ciphers, expect(MODERN.ciphers));
        assert_eq!(resolved.kex, expect(MODERN.kex));
        assert_eq!(resolved.macs, expect(MODERN.macs));
        assert_eq!(resolved.host_keys, expect(MODERN.host_keys));
        assert_eq!(resolved.compression, expect(MODERN.compression));
    }

    #[test]
    fn explicit_category_overrides_preset_for_that_category_only() {
        let explicit = CryptoPolicy {
            ciphers: vec!["aes256-gcm@openssh.com".into()],
            ..Default::default()
        };
        let resolved = resolve_crypto_policy(Some("modern"), &explicit, false, false).unwrap();
        // ciphers overridden…
        assert_eq!(resolved.ciphers, vec!["aes256-gcm@openssh.com".to_owned()]);
        // …but kex still filled from the preset.
        assert_eq!(
            resolved.kex,
            MODERN
                .kex
                .iter()
                .map(|x| (*x).to_owned())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn none_preset_defaults_to_modern() {
        let resolved = resolve_crypto_policy(None, &CryptoPolicy::default(), false, false).unwrap();
        assert_eq!(
            resolved.kex,
            MODERN
                .kex
                .iter()
                .map(|x| (*x).to_owned())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn unknown_preset_is_invalid_config() {
        let err = resolve_crypto_policy(Some("ultra"), &CryptoPolicy::default(), false, false)
            .expect_err("unknown preset must error");
        assert!(matches!(err, Error::InvalidConfig(_)), "{err:?}");
        assert!(format!("{err}").contains("ultra"));
    }

    #[test]
    fn explicit_deprecated_algo_rejected_when_not_allowed() {
        let explicit = CryptoPolicy {
            ciphers: vec!["aes256-cbc".into()],
            ..Default::default()
        };
        let err = resolve_crypto_policy(Some("modern"), &explicit, false, false)
            .expect_err("deprecated algo must be rejected when !allow_deprecated");
        assert!(matches!(err, Error::InvalidConfig(_)), "{err:?}");
        let s = format!("{err}");
        assert!(s.contains("aes256-cbc"), "{s}");
        assert!(s.contains("allow_deprecated"), "{s}");
    }

    #[test]
    fn legacy_preset_requires_allow_deprecated() {
        // LEGACY carries deprecated algorithms (e.g. hmac-sha1, ssh-rsa) so it
        // must be rejected unless allow_deprecated is set.
        let err = resolve_crypto_policy(Some("legacy"), &CryptoPolicy::default(), false, false)
            .expect_err("legacy preset must require allow_deprecated");
        assert!(matches!(err, Error::InvalidConfig(_)), "{err:?}");
    }

    #[test]
    fn legacy_preset_resolves_when_deprecated_allowed() {
        let resolved =
            resolve_crypto_policy(Some("legacy"), &CryptoPolicy::default(), true, false).unwrap();
        // The deprecated entries survive into the resolved policy.
        assert!(resolved.macs.iter().any(|m| m == "hmac-sha1"));
        assert!(resolved.host_keys.iter().any(|h| h == "ssh-rsa"));
    }

    #[test]
    fn warn_on_deprecated_does_not_block_resolution() {
        // allow_deprecated=true + warn_on_deprecated=true ⇒ resolves OK and the
        // warning is emitted (tracing is a no-op without a subscriber; we only
        // assert resolution succeeds and the algo survives).
        let explicit = CryptoPolicy {
            macs: vec!["hmac-sha1".into()],
            ..Default::default()
        };
        let resolved = resolve_crypto_policy(Some("modern"), &explicit, true, true).unwrap();
        assert_eq!(resolved.macs, vec!["hmac-sha1".to_owned()]);
    }
}
