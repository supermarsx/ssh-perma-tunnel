//! SHA-256 fingerprint of a canonical-rendered config.
//!
//! Status snapshots include the fingerprint so observers can verify the
//! running config matches the on-disk config without reading the file. The
//! fingerprint is computed over the *rendered* canonical form so insignificant
//! differences (whitespace, key ordering produced by the user) do not cause
//! spurious mismatches.
//!
//! The canonical render uses [`RedactionMode::None`] so that *every*
//! security-sensitive field participates in the hash — including `secret://`
//! references, inline secret material, and pins like `fingerprint_sha256`.
//!
//! E5-F12: a redacted render collapses every `secret://ns/name` to
//! `secret://[REDACTED]` and every `passphrase|password|token|auth|…` value to
//! `[REDACTED]`, so re-pointing `auth.passphrase` from `secret://a/x` to
//! `secret://b/y`, or changing `runtime.remote_config.fingerprint_sha256`,
//! would leave the fingerprint unchanged — defeating the "running config ==
//! on-disk config" check exactly on the fields that matter most. The
//! fingerprint is a one-way SHA-256 digest that never re-exposes the rendered
//! bytes, so hashing the verbatim render is safe and stays inside the process.

use sha2::{Digest, Sha256};
use spt_core::RedactionMode;

use crate::render::render;
use crate::schema::Config;

/// Fingerprint a [`Config`] by SHA-256 over its canonical rendered form.
///
/// The render is verbatim ([`RedactionMode::None`]) so secret-reference and
/// pin changes are reflected in the digest (E5-F12). The resulting 32-byte
/// hash is one-way; it does not leak the rendered secrets.
#[must_use]
pub fn fingerprint(c: &Config) -> [u8; 32] {
    let canonical = render(c, RedactionMode::None);
    fingerprint_str(&canonical)
}

/// Fingerprint a raw rendered TOML string.
#[must_use]
pub fn fingerprint_str(s: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher.finalize().into()
}

/// Render the SHA-256 as a lowercase hex string.
#[must_use]
pub fn fingerprint_hex(c: &Config) -> String {
    let bytes = fingerprint(c);
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::{fingerprint, fingerprint_hex, fingerprint_str};
    use crate::load::load_str;

    const RAW: &str = r#"
        version = 1
        [[profiles]]
        name = "p"
        protocol = "ssh2"
    "#;

    #[test]
    fn fingerprint_is_stable() {
        let (c1, _) = load_str(RAW, false).unwrap();
        let (c2, _) = load_str(RAW, false).unwrap();
        assert_eq!(fingerprint(&c1), fingerprint(&c2));
    }

    #[test]
    fn fingerprint_differs_when_changed() {
        let (mut c, _) = load_str(RAW, false).unwrap();
        let h1 = fingerprint(&c);
        c.profiles[0].name = "other".into();
        let h2 = fingerprint(&c);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hex_is_64_chars() {
        let (c, _) = load_str(RAW, false).unwrap();
        let hex = fingerprint_hex(&c);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_str_basic() {
        assert_ne!(fingerprint_str("a"), fingerprint_str("b"));
    }

    /// E5-F12: re-pointing a `secret://` reference must change the
    /// fingerprint. Under the old `RedactionMode::Standard` render both refs
    /// collapsed to `secret://[REDACTED]` and the digests matched.
    #[test]
    fn fingerprint_tracks_secret_ref_changes() {
        let with_ref = |r: &str| {
            format!(
                r#"
                version = 1
                [[profiles]]
                name = "p"
                protocol = "ssh2"
                host = "h"
                [profiles.auth]
                method = "password"
                password = "{r}"
                "#
            )
        };
        let (a, _) = load_str(&with_ref("secret://a/x"), false).unwrap();
        let (b, _) = load_str(&with_ref("secret://b/y"), false).unwrap();
        assert_ne!(
            fingerprint(&a),
            fingerprint(&b),
            "changing a secret:// reference must change the config fingerprint"
        );
    }
}
