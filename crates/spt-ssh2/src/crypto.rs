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
/// The SSH2 transport rides upstream `russh 0.61.2` (crates.io), which
/// implements the hybrid PQ KEX `mlkem768x25519-sha256` end-to-end (see
/// `russh::kex::MLKEM768X25519_SHA256`). That is the ONE post-quantum KEX
/// spt offers by default and the only entry in this list russh can actually
/// negotiate — see [`SUPPORTED_PQ_KEX`]. spt prepends it to every preset's
/// `kex` list so a profile offers `mlkem768x25519-sha256` FIRST with a
/// classical fallback (mirroring russh's own `SAFE_KEX_ORDER`); the hybrid
/// construction keeps X25519 security regardless, and servers without
/// ML-KEM negotiate curve25519.
///
/// The remaining entries below (the `@openssh.com` aliases, the NIST-P
/// ML-KEM variants, and the `sntrup761x25519-sha512` names) are
/// config-recognized so validation/diagnostics can reason about them, but
/// russh 0.61.2 does NOT register them: selecting one either fails the
/// `build_preferred` name-parse (unknown to russh) or — for the sntrup
/// names — is rejected up front by [`resolve_crypto_policy`] via
/// [`UNSUPPORTED_HANDSHAKE_KEX`].
pub const POST_QUANTUM_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "mlkem768x25519-sha256@openssh.com",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
];

/// Post-quantum KEX names that are config-recognized but that russh 0.61.2
/// cannot complete: `sntrup761x25519-sha512` and its legacy `@openssh.com`
/// alias name a KEM primitive russh does not implement. [`resolve_crypto_policy`]
/// rejects them at config-resolution time with a clear message so the failure
/// surfaces at config load rather than cryptically at handshake.
pub const UNSUPPORTED_HANDSHAKE_KEX: &[&str] = &[
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
];

/// The one post-quantum KEX russh 0.61.2 implements end-to-end
/// (`mlkem768x25519-sha256`). This is the algorithm spt offers by default and
/// the one [`apply_post_quantum_capability_policy`] keeps under a PQ-only
/// (`require_post_quantum_kex`) policy.
pub const SUPPORTED_PQ_KEX: &str = "mlkem768x25519-sha256";

/// ML-KEM hybrid SSH KEX method names recognized by config validation and
/// diagnostics. Only `mlkem768x25519-sha256` is negotiable by russh 0.61.2
/// (see [`SUPPORTED_PQ_KEX`]); the other names are recognized for diagnostics.
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
//
// Every preset's `kex` list leads with the hybrid post-quantum KEX
// [`SUPPORTED_PQ_KEX`] (`mlkem768x25519-sha256`), followed by the classical
// fallback — mirroring russh's own `SAFE_KEX_ORDER`. This makes spt offer PQ
// key exchange BY DEFAULT: a peer that speaks ML-KEM negotiates it, and a peer
// that does not falls back to curve25519 with no loss of security (the hybrid
// construction retains X25519's guarantees). The capability knobs in
// `[capabilities]` (`allow_post_quantum_kex` / `allow_ml_kem` /
// `require_post_quantum_kex`) refine this at the factory layer via
// [`apply_post_quantum_capability_policy`].

/// Modern, deprecation-free preset. No algorithm here appears in
/// [`DEPRECATED`]. Leads with the hybrid PQ KEX [`SUPPORTED_PQ_KEX`].
pub const MODERN: CryptoPreset = CryptoPreset {
    ciphers: &[
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
    ],
    kex: &[
        "mlkem768x25519-sha256",
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
        "mlkem768x25519-sha256",
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
        "mlkem768x25519-sha256",
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

    // Reject KEX names that the russh fork registers but cannot complete
    // (finding 8): they validate and connect, then fail cryptically at the key
    // exchange. Surface an honest config-time error naming the only supported
    // post-quantum KEX instead.
    for algo in &policy.kex {
        if UNSUPPORTED_HANDSHAKE_KEX
            .iter()
            .any(|u| u.eq_ignore_ascii_case(algo))
        {
            return Err(Error::InvalidConfig(format!(
                "kex algorithm `{algo}` is recognized but not implemented by the russh SSH2 \
                 backend: its KEM primitive is unwired, so the handshake would fail at key \
                 exchange (not at config load). The only supported post-quantum KEX is \
                 `{SUPPORTED_PQ_KEX}`. Remove `{algo}` from `crypto.kex_algorithms`, or \
                 replace it with `{SUPPORTED_PQ_KEX}`."
            )));
        }
    }

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

/// True when `algo` is a recognized post-quantum (or hybrid-PQ) KEX name
/// (any entry in [`POST_QUANTUM_KEX`]).
#[must_use]
pub fn is_post_quantum_kex(algo: &str) -> bool {
    contains_ignore_ascii_case(POST_QUANTUM_KEX, algo)
}

/// True when `algo` is the one post-quantum KEX russh 0.61.2 negotiates
/// end-to-end ([`SUPPORTED_PQ_KEX`], `mlkem768x25519-sha256`).
#[must_use]
pub fn is_supported_post_quantum_kex(algo: &str) -> bool {
    algo.eq_ignore_ascii_case(SUPPORTED_PQ_KEX)
}

/// Apply the `[capabilities]` post-quantum policy to an already-resolved
/// [`CryptoPolicy`]'s `kex` list, in place.
///
/// spt offers `mlkem768x25519-sha256` by default (it leads every preset's
/// `kex` list). This helper lets an operator override that default:
///
/// * `require_post_quantum_kex == Some(true)` — **PQ-only**. Restrict `kex` to
///   the supported post-quantum KEX (drop every classical algorithm) so the
///   handshake fails closed rather than silently negotiating classical crypto.
///   If no supported PQ KEX remains (e.g. the operator pinned only an
///   unsupported PQ name), returns [`Error::InvalidConfig`]. Takes precedence
///   over the `allow_*` knobs.
/// * else if `allow_post_quantum_kex == Some(false)` **or**
///   `allow_ml_kem == Some(false)` — **strip PQ**. Remove every recognized
///   post-quantum KEX from `kex`, leaving the classical fallback. If that would
///   empty the list (the operator pinned a PQ-only `kex` and then disallowed
///   PQ — a contradiction validation also flags), returns
///   [`Error::InvalidConfig`] rather than leaving an empty list (an empty list
///   would let russh fall back to its own PQ-by-default `Preferred`).
/// * otherwise the resolved `kex` is left untouched (PQ-by-default stands).
///
/// The list is never left empty on success.
pub fn apply_post_quantum_capability_policy(
    crypto: &mut CryptoPolicy,
    allow_post_quantum_kex: Option<bool>,
    allow_ml_kem: Option<bool>,
    require_post_quantum_kex: Option<bool>,
) -> Result<()> {
    if require_post_quantum_kex == Some(true) {
        crypto
            .kex
            .retain(|algo| is_supported_post_quantum_kex(algo));
        if crypto.kex.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "capabilities.require_post_quantum_kex = true, but the resolved key-exchange \
                 list contains no supported post-quantum KEX. The only supported post-quantum \
                 KEX is `{SUPPORTED_PQ_KEX}`; remove any pinned unsupported PQ algorithm from \
                 `crypto.kex_algorithms`, or clear it to use the default (which offers \
                 `{SUPPORTED_PQ_KEX}`)."
            )));
        }
        return Ok(());
    }

    if allow_post_quantum_kex == Some(false) || allow_ml_kem == Some(false) {
        crypto.kex.retain(|algo| !is_post_quantum_kex(algo));
        if crypto.kex.is_empty() {
            return Err(Error::InvalidConfig(
                "post-quantum KEX is disabled (capabilities.allow_post_quantum_kex = false or \
                 allow_ml_kem = false), but that leaves no key-exchange algorithm in \
                 `crypto.kex_algorithms`. Add a classical KEX such as `curve25519-sha256`, or \
                 clear the explicit list to use the preset default."
                    .to_owned(),
            ));
        }
    }

    Ok(())
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
    fn sntrup761_kex_rejected_at_config_resolution() {
        // finding 8: sntrup761x25519 names validate then fail at KEX time under
        // the current russh fork (KEM unwired). resolve_crypto_policy must reject
        // them at config-resolution time with a clear message that names the
        // supported PQ KEX. Fails against pre-fix (which returned Ok, deferring
        // the failure to the handshake).
        for name in [
            "sntrup761x25519-sha512",
            "sntrup761x25519-sha512@openssh.com",
        ] {
            let explicit = CryptoPolicy {
                kex: vec![name.into()],
                ..Default::default()
            };
            let err = resolve_crypto_policy(Some("modern"), &explicit, true, false)
                .expect_err("sntrup761 kex must be rejected at config time");
            assert!(matches!(err, Error::InvalidConfig(_)), "{err:?}");
            let s = format!("{err}");
            assert!(s.contains(name), "message must name the rejected algo: {s}");
            assert!(
                s.contains("mlkem768x25519-sha256"),
                "message must name the supported PQ KEX: {s}"
            );
        }
    }

    #[test]
    fn mlkem768_kex_still_resolves() {
        // The supported PQ KEX must NOT be swept up by the sntrup rejection.
        let explicit = CryptoPolicy {
            kex: vec!["mlkem768x25519-sha256".into()],
            ..Default::default()
        };
        let resolved = resolve_crypto_policy(Some("modern"), &explicit, false, false)
            .expect("mlkem768x25519-sha256 must resolve cleanly");
        assert_eq!(resolved.kex, vec!["mlkem768x25519-sha256".to_owned()]);
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

    // ──────── PQ-by-default preset ordering + capability policy ────────────

    #[test]
    fn presets_lead_with_supported_pq_kex() {
        // PQ-by-default: every preset's kex list must OFFER
        // `mlkem768x25519-sha256` FIRST, then a classical fallback.
        for set in [MODERN, INTEROP, LEGACY] {
            assert_eq!(
                set.kex.first().copied(),
                Some(SUPPORTED_PQ_KEX),
                "preset kex must lead with the supported PQ KEX"
            );
            // classical fallback still present right after the PQ entry.
            assert!(
                set.kex[1..].iter().any(|k| k.starts_with("curve25519")),
                "preset kex must retain a classical curve25519 fallback"
            );
        }
    }

    #[test]
    fn default_resolved_kex_is_pq_first_then_classical() {
        // A default ssh2 profile (no explicit kex, no caps) resolves to a kex
        // list beginning with mlkem768x25519-sha256 then classical.
        let resolved = resolve_crypto_policy(None, &CryptoPolicy::default(), false, false).unwrap();
        assert_eq!(
            resolved.kex.first().map(String::as_str),
            Some(SUPPORTED_PQ_KEX)
        );
        assert!(resolved.kex[1..].iter().any(|k| k == "curve25519-sha256"));
        assert!(resolved.has_post_quantum_kex());
    }

    #[test]
    fn allow_pq_false_strips_pq_leaving_classical() {
        let mut crypto =
            resolve_crypto_policy(None, &CryptoPolicy::default(), false, false).unwrap();
        apply_post_quantum_capability_policy(&mut crypto, Some(false), None, None).unwrap();
        assert!(
            !crypto.has_post_quantum_kex(),
            "allow_post_quantum_kex=false must strip every PQ KEX"
        );
        assert!(!crypto.kex.is_empty(), "classical fallback must remain");
        assert_eq!(
            crypto.kex.first().map(String::as_str),
            Some("curve25519-sha256")
        );
    }

    #[test]
    fn allow_ml_kem_false_strips_pq_leaving_classical() {
        let mut crypto =
            resolve_crypto_policy(None, &CryptoPolicy::default(), false, false).unwrap();
        apply_post_quantum_capability_policy(&mut crypto, None, Some(false), None).unwrap();
        assert!(!crypto.has_post_quantum_kex());
        assert!(!crypto.kex.is_empty());
    }

    #[test]
    fn require_pq_yields_pq_only_and_succeeds() {
        let mut crypto =
            resolve_crypto_policy(None, &CryptoPolicy::default(), false, false).unwrap();
        apply_post_quantum_capability_policy(&mut crypto, Some(true), Some(true), Some(true))
            .expect("require PQ must succeed now that mlkem768x25519-sha256 is supported");
        assert_eq!(crypto.kex, vec![SUPPORTED_PQ_KEX.to_owned()]);
    }

    #[test]
    fn require_pq_takes_precedence_over_allow_false() {
        // Contradictory config (require=true, allow=false): require wins,
        // yielding PQ-only rather than an empty list.
        let mut crypto =
            resolve_crypto_policy(None, &CryptoPolicy::default(), false, false).unwrap();
        apply_post_quantum_capability_policy(&mut crypto, Some(false), None, Some(true)).unwrap();
        assert_eq!(crypto.kex, vec![SUPPORTED_PQ_KEX.to_owned()]);
    }

    #[test]
    fn require_pq_with_no_supported_pq_errors() {
        // Operator pinned a classical-only kex but required PQ: restriction
        // empties the list ⇒ InvalidConfig.
        let mut crypto = CryptoPolicy {
            kex: vec!["curve25519-sha256".into()],
            ..Default::default()
        };
        let err = apply_post_quantum_capability_policy(&mut crypto, Some(true), None, Some(true))
            .expect_err("require PQ with no supported PQ kex must error");
        assert!(matches!(err, Error::InvalidConfig(_)), "{err:?}");
        assert!(format!("{err}").contains(SUPPORTED_PQ_KEX));
    }

    #[test]
    fn allow_pq_false_with_pq_only_kex_errors_not_empties() {
        // Contradiction: PQ-only explicit kex + allow=false. Rather than leave
        // an empty list (which would let russh fall back to PQ-by-default), we
        // error out.
        let mut crypto = CryptoPolicy {
            kex: vec![SUPPORTED_PQ_KEX.into()],
            ..Default::default()
        };
        let err = apply_post_quantum_capability_policy(&mut crypto, Some(false), None, None)
            .expect_err("stripping PQ from a PQ-only list must error, not empty the list");
        assert!(matches!(err, Error::InvalidConfig(_)), "{err:?}");
    }

    #[test]
    fn no_capability_flags_leave_pq_default_intact() {
        let mut crypto =
            resolve_crypto_policy(None, &CryptoPolicy::default(), false, false).unwrap();
        let before = crypto.kex.clone();
        apply_post_quantum_capability_policy(&mut crypto, None, None, None).unwrap();
        assert_eq!(crypto.kex, before, "no caps ⇒ PQ-by-default is untouched");
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
