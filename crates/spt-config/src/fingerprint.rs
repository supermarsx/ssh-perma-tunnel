//! SHA-256 fingerprint of a canonical-rendered config.
//!
//! Status snapshots include the fingerprint so observers can verify the
//! running config matches the on-disk config without reading the file. The
//! fingerprint is computed over the *rendered* canonical form so insignificant
//! differences (whitespace, key ordering produced by the user) do not cause
//! spurious mismatches.
//!
//! The canonical render uses [`RedactionMode::Standard`] so secrets are not
//! mixed into the fingerprint, then computes SHA-256 over the resulting bytes.

use sha2::{Digest, Sha256};
use spt_core::RedactionMode;

use crate::render::render;
use crate::schema::Config;

/// Fingerprint a [`Config`] by SHA-256 over its canonical rendered form.
#[must_use]
pub fn fingerprint(c: &Config) -> [u8; 32] {
    let canonical = render(c, RedactionMode::Standard);
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
}
