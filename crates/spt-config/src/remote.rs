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

/// A fully-resolved remote-config retrieval plan built from
/// `[runtime.remote_config]` (E5-F5 pin plumbing).
///
/// `RemoteConfigSpec` only carries the *body*-integrity surface (URL,
/// fingerprint, cache-fallback flag, size cap). The TLS **pin** surface
/// (`pin_spki_sha256`, `allow_self_signed`, `max_cert_chain_depth`) is what the
/// HTTPS fetcher needs to construct a `PinnedTlsConnector`. This struct bundles
/// the two together so a call site (e.g. `config pull`, wired in Phase 4) can
/// build a correctly-pinned fetcher *and* a spec from a single config table,
/// instead of `ReqwestFetcher::new()` with no pins.
///
/// The actual fetcher construction lives in `spt-remote-config` (this crate has
/// no TLS dependency); see `spt_remote_config::fetch::fetcher_for_plan`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteConfigPlan {
    /// Body-integrity spec passed to `spt_remote_config::fetch`.
    pub spec: RemoteConfigSpec,
    /// SPKI SHA-256 pin set for the HTTPS endpoint (TLS pinning).
    pub pin_spki_sha256: Vec<String>,
    /// Allow self-signed certs (requires a non-empty pin set downstream).
    pub allow_self_signed: bool,
    /// Maximum certificate-chain depth; `None` maps to the connector default.
    pub max_cert_chain_depth: Option<u32>,
}

/// Why building a [`RemoteConfigPlan`] from `[runtime.remote_config]` failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// `url` is absent.
    UrlMissing,
    /// `fingerprint_sha256` is absent (the pull is pin-only per spec §14.3).
    FingerprintMissing,
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UrlMissing => f.write_str("[runtime.remote_config].url is required"),
            Self::FingerprintMissing => {
                f.write_str("[runtime.remote_config].fingerprint_sha256 is required")
            }
        }
    }
}

impl std::error::Error for PlanError {}

impl RemoteConfigSpec {
    /// Build a [`RemoteConfigPlan`] from a `[runtime.remote_config]` table.
    ///
    /// Carries the configured SPKI pins, `allow_cached_on_failure`, the body
    /// fingerprint, and an optional `max_size_bytes` cap into a single plan so
    /// the fetch call site honors configured pinning. `url` and
    /// `fingerprint_sha256` are required; everything else is optional and
    /// defaulted. Optional CLI overrides (e.g. `--url`/`--fingerprint`) can be
    /// passed to take precedence over the table values.
    ///
    /// `max_size_bytes` is taken from the explicit argument since the
    /// `[runtime.remote_config]` table has no such field; pass `None` to use the
    /// fetcher's built-in default cap.
    pub fn plan_from_runtime(
        rc: &crate::RuntimeRemoteConfig,
        url_override: Option<&str>,
        fingerprint_override: Option<&str>,
        max_size_bytes: Option<u64>,
    ) -> Result<RemoteConfigPlan, PlanError> {
        let url = url_override
            .map(str::to_owned)
            .or_else(|| rc.url.clone())
            .filter(|u| !u.is_empty())
            .ok_or(PlanError::UrlMissing)?;
        let fingerprint_sha256 = fingerprint_override
            .map(str::to_owned)
            .or_else(|| rc.fingerprint_sha256.clone())
            .filter(|f| !f.is_empty())
            .ok_or(PlanError::FingerprintMissing)?;
        Ok(RemoteConfigPlan {
            spec: RemoteConfigSpec {
                url,
                fingerprint_sha256,
                allow_cached_on_failure: rc.allow_cached_on_failure.unwrap_or(false),
                max_size_bytes,
                etag_cache: rc.cache_file.clone(),
            },
            pin_spki_sha256: rc.pin_spki_sha256.clone(),
            allow_self_signed: rc.allow_self_signed.unwrap_or(false),
            max_cert_chain_depth: rc.max_cert_chain_depth,
        })
    }
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

    #[test]
    fn plan_carries_configured_pin_and_flags() {
        use super::RemoteConfigSpec;
        let rc = crate::RuntimeRemoteConfig {
            enabled: Some(true),
            url: Some("https://cfg.example.com/c.toml".into()),
            fingerprint_sha256: Some("a".repeat(64)),
            cache_file: Some("/var/cache/spt/remote.toml".into()),
            allow_cached_on_failure: Some(true),
            poll_interval: Some("5m".into()),
            pin_spki_sha256: vec!["SHA256:AAAA".into(), "SHA256:BBBB".into()],
            allow_self_signed: Some(true),
            max_cert_chain_depth: Some(3),
            encryption_key_from: None,
            require_encrypted: None,
        };
        let plan = RemoteConfigSpec::plan_from_runtime(&rc, None, None, Some(2_000_000)).unwrap();
        // The configured fingerprint flows into the spec.
        assert_eq!(plan.spec.fingerprint_sha256, "a".repeat(64));
        assert_eq!(plan.spec.url, "https://cfg.example.com/c.toml");
        assert!(plan.spec.allow_cached_on_failure);
        assert_eq!(plan.spec.max_size_bytes, Some(2_000_000));
        assert_eq!(
            plan.spec.etag_cache.as_deref(),
            Some("/var/cache/spt/remote.toml")
        );
        // The configured TLS pins flow into the plan's pin surface.
        assert_eq!(plan.pin_spki_sha256, vec!["SHA256:AAAA", "SHA256:BBBB"]);
        assert!(plan.allow_self_signed);
        assert_eq!(plan.max_cert_chain_depth, Some(3));
    }

    #[test]
    fn plan_overrides_take_precedence() {
        use super::RemoteConfigSpec;
        let rc = crate::RuntimeRemoteConfig {
            url: Some("https://table.example/c.toml".into()),
            fingerprint_sha256: Some("a".repeat(64)),
            ..Default::default()
        };
        let plan = RemoteConfigSpec::plan_from_runtime(
            &rc,
            Some("https://cli.example/o.toml"),
            Some(&"b".repeat(64)),
            None,
        )
        .unwrap();
        assert_eq!(plan.spec.url, "https://cli.example/o.toml");
        assert_eq!(plan.spec.fingerprint_sha256, "b".repeat(64));
        assert!(!plan.spec.allow_cached_on_failure);
    }

    #[test]
    fn plan_requires_url_and_fingerprint() {
        use super::{PlanError, RemoteConfigSpec};
        let empty = crate::RuntimeRemoteConfig::default();
        assert_eq!(
            RemoteConfigSpec::plan_from_runtime(&empty, None, None, None),
            Err(PlanError::UrlMissing)
        );
        let url_only = crate::RuntimeRemoteConfig {
            url: Some("https://x/c.toml".into()),
            ..Default::default()
        };
        assert_eq!(
            RemoteConfigSpec::plan_from_runtime(&url_only, None, None, None),
            Err(PlanError::FingerprintMissing)
        );
    }
}
