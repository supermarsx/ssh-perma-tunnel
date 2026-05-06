//! Remote-config descriptor types.
//!
//! Actual HTTPS fetching, fingerprint verification, `ETag` caching, and atomic
//! cache writes live in `spt-remote-config`. This module only declares the
//! shapes those components need.

use serde::{Deserialize, Serialize};

/// Description of a remote-config endpoint.
///
/// Mirrors `[runtime.remote_config]` from the schema (spec §9.1, §14.3) but
/// promoted to its own type so non-spt-config consumers can take it without
/// pulling in the full [`crate::Config`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteConfigSpec {
    /// HTTPS-only URL of the remote config document.
    pub url: String,
    /// SHA-256 fingerprint of the *body* (not TLS pin). 64-char lowercase hex.
    pub fingerprint_sha256: String,
    /// If `true`, allow falling back to the on-disk cache when fetch fails.
    #[serde(default)]
    pub allow_cached_on_failure: bool,
    /// Maximum allowed body size in bytes (defends against runaway responses).
    #[serde(default)]
    pub max_size_bytes: Option<u64>,
    /// Optional path to the `ETag` cache.
    #[serde(default)]
    pub etag_cache: Option<String>,
}

/// Outcome of validating a [`RemoteConfigSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecCheck {
    /// All required fields look correct.
    Ok,
    /// `url` is empty.
    UrlMissing,
    /// `url` is not HTTPS.
    UrlNotHttps,
    /// `fingerprint_sha256` is not 64 hex chars.
    FingerprintMalformed,
}

impl RemoteConfigSpec {
    /// Cheap shape check. Spec §14.3 requires HTTPS and a fingerprint pin.
    #[must_use]
    pub fn check(&self) -> SpecCheck {
        if self.url.is_empty() {
            return SpecCheck::UrlMissing;
        }
        if !self.url.starts_with("https://") {
            return SpecCheck::UrlNotHttps;
        }
        if self.fingerprint_sha256.len() != 64
            || !self
                .fingerprint_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return SpecCheck::FingerprintMalformed;
        }
        SpecCheck::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::{RemoteConfigSpec, SpecCheck};

    fn good() -> RemoteConfigSpec {
        RemoteConfigSpec {
            url: "https://x.example.com/c.toml".into(),
            fingerprint_sha256: "a".repeat(64),
            allow_cached_on_failure: true,
            max_size_bytes: Some(1_000_000),
            etag_cache: None,
        }
    }

    #[test]
    fn ok_spec() {
        assert_eq!(good().check(), SpecCheck::Ok);
    }

    #[test]
    fn rejects_http() {
        let mut s = good();
        s.url = "http://x".into();
        assert_eq!(s.check(), SpecCheck::UrlNotHttps);
    }

    #[test]
    fn rejects_short_fp() {
        let mut s = good();
        s.fingerprint_sha256 = "abc".into();
        assert_eq!(s.check(), SpecCheck::FingerprintMalformed);
    }

    #[test]
    fn rejects_empty_url() {
        let mut s = good();
        s.url = String::new();
        assert_eq!(s.check(), SpecCheck::UrlMissing);
    }
}
