//! `[status_api]` configuration table — read-only HTTP/JSON status API.
//!
//! This is the configuration surface for the optional, read-only HTTP/JSON
//! status server hosted by the supervisor when `enabled = true`. The actual
//! server implementation lives in the `spt-status-api` crate; this module
//! exists in `spt-config` so the schema (and `Config` struct, owned by the
//! Phase-B integrator) stays decoupled from the server crate's transitive
//! dependency graph.
//!
//! ## Security defaults (spec §14, plan §t4-e5)
//!
//! * **Disabled by default.** [`StatusApiConfig::enabled`] is `false` unless
//!   the operator explicitly sets it.
//! * **Loopback bind by default.** [`default_bind`] returns `127.0.0.1:9617`;
//!   the operator must opt in to a non-loopback bind.
//! * **Read-only by contract.** [`StatusApiConfig::read_only`] defaults to
//!   `true` and is reserved — no write paths are wired in this release.
//! * **Auth required when enabled.** [`StatusApiAuthConfig`] defaults to
//!   [`StatusApiAuthMode::None`] *only* as the explicit configuration choice;
//!   the spt-status-api server crate rejects `auth.mode = "none"` unless the
//!   bind address is on loopback. Operators wanting anonymous off-loopback
//!   access must override this in the server crate's runtime checks.
//! * **Rate limit on by default.** Defaults to ~1 request/second via the
//!   [`default_rate_limit`] helper.
//! * **TLS opt-in.** [`StatusApiTlsConfig::enabled`] defaults to `false`; the
//!   loopback default is plain HTTP. Non-loopback binds should set TLS.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use spt_secrets::SecretRef;

/// `[status_api]` — read-only HTTP/JSON status API configuration.
///
/// Spec: plan §t4-e5 (mini status JSON API). See module-level documentation
/// for security defaults.
///
/// Note: this type implements [`PartialEq`] but not [`Eq`] because
/// [`rate_limit_rps`](Self::rate_limit_rps) is an `f32` (`f32: !Eq`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct StatusApiConfig {
    /// Master kill-switch. Defaults to `false` — when the operator does not
    /// configure `[status_api]`, the server is never started.
    pub enabled: bool,

    /// TCP bind address. Defaults to `127.0.0.1:9617` (IANA-unassigned private
    /// port). Loopback is intentional: the server is intended for local
    /// scrape-target use; off-loopback binds require [`StatusApiTlsConfig`]
    /// and an authenticated [`StatusApiAuthConfig`].
    pub bind: SocketAddr,

    /// Reserved for future use. Always `true` in this release — no write
    /// endpoints are wired. Setting `false` is currently a no-op; the server
    /// crate enforces read-only behavior regardless.
    pub read_only: bool,

    /// Whether `/v1/metrics` (Prometheus text format) is exposed. Defaults to
    /// `true`. Operators can disable to avoid double-exposure when a separate
    /// metrics exporter is used.
    pub expose_metrics: bool,

    /// Per-client (per remote IP) rate limit in requests/second. Default ~1
    /// rps (60 req/min). The server crate's token bucket interprets fractional
    /// values as the refill rate.
    pub rate_limit_rps: f32,

    /// `[status_api.tls]` — optional rustls server configuration.
    pub tls: StatusApiTlsConfig,

    /// `[status_api.auth]` — authentication mode.
    pub auth: StatusApiAuthConfig,
}

impl Default for StatusApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_bind(),
            read_only: true,
            expose_metrics: true,
            rate_limit_rps: default_rate_limit(),
            tls: StatusApiTlsConfig::default(),
            auth: StatusApiAuthConfig::default(),
        }
    }
}

/// `[status_api.tls]` — server-side TLS configuration. Optional; when
/// `enabled` is `false`, the server runs over plain HTTP (which is only
/// acceptable on loopback).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct StatusApiTlsConfig {
    /// Whether TLS is active. Defaults to `false`.
    pub enabled: bool,
    /// PEM-encoded certificate chain. Path is canonical (no globs).
    pub cert_file: PathBuf,
    /// PEM-encoded private key. The server crate refuses to start if the file
    /// is world-readable on Unix.
    pub key_file: PathBuf,
}

impl Default for StatusApiTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_file: PathBuf::new(),
            key_file: PathBuf::new(),
        }
    }
}

/// `[status_api.auth]` — authentication mode + per-mode parameters.
///
/// The wire representation tags by the `mode` field (`"none" | "bearer" |
/// "basic" | "mtls"`). Bearer/basic credentials are resolved via the
/// `spt-secrets` [`Resolver`](spt_secrets::Resolver) at server start time —
/// never stored inline in the config.
///
/// ## Unknown-key detection limitation (E5-F13)
///
/// The [`mode`](Self::mode) field is `#[serde(flatten)]`ed onto an
/// internally-tagged enum ([`StatusApiAuthMode`]). `serde_ignored` — the
/// machinery that powers the unknown-key warning path and `--strict` mode —
/// **cannot see keys consumed inside a flattened/buffered value**, because
/// flattening routes deserialization through serde's internal `Content`
/// buffer rather than the tracking deserializer. As a consequence a typo'd
/// key inside `[status_api.auth]` (for example `allowed_subject = [...]`
/// instead of `allowed_subjects`, while `mode = "mtls"` defaults apply) is
/// silently dropped instead of being reported.
///
/// This is a structural hole in the safety net that replaced
/// `deny_unknown_fields`. It is documented rather than fixed here to avoid
/// reshaping the (shared) schema; the semantic checks added by
/// `validate::check_status_api` recover *value*-level coverage (TLS/cert/mtls
/// cross-field validation), but cannot recover unknown-*key* coverage for
/// keys swallowed by the flatten. Operators relying on strict-mode typo
/// detection for this table should treat that as a known gap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusApiAuthConfig {
    /// Active authentication mode.
    ///
    /// Note: because this is `#[serde(flatten)]`ed, unknown keys nested in
    /// the same `[status_api.auth]` table escape `serde_ignored` detection —
    /// see the type-level docs (E5-F13).
    #[serde(flatten)]
    pub mode: StatusApiAuthMode,
}

impl Default for StatusApiAuthConfig {
    fn default() -> Self {
        Self {
            mode: StatusApiAuthMode::None,
        }
    }
}

/// Variants for `[status_api.auth].mode`.
///
/// Tagged on the wire by the `mode` field; the per-mode parameters are
/// flattened alongside `mode` in the same table so the operator-facing TOML
/// stays flat (see plan §t4-e5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum StatusApiAuthMode {
    /// No authentication. The server crate refuses non-loopback binds in this
    /// mode unless explicitly overridden.
    None,

    /// `Authorization: Bearer <token>`. The token is resolved at server start
    /// via [`spt_secrets::Resolver`] from the [`SecretRef`].
    Bearer {
        /// `secret://ns/name` reference for the bearer token.
        token_from: SecretRef,
    },

    /// HTTP basic auth (`Authorization: Basic base64(user:password)`).
    /// Password resolved from secrets at server start.
    Basic {
        /// Username (sent in cleartext in the `Authorization` header; treat
        /// as a public identifier, not a secret).
        user: String,
        /// `secret://ns/name` reference for the basic-auth password.
        password_from: SecretRef,
    },

    /// Mutual TLS. The server crate verifies the client certificate against
    /// `ca_bundle` and matches the verified subject against
    /// `allowed_subjects` (RFC 4514 distinguished-name strings, e.g.
    /// `"CN=prom.internal"`). Requires `[status_api.tls].enabled = true`.
    #[serde(rename = "mtls")]
    MutualTls {
        /// PEM-encoded bundle of trusted client-CA certificates.
        ca_bundle: PathBuf,
        /// Whitelist of accepted subject DNs. Empty list rejects all clients.
        allowed_subjects: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// serde defaults
// ---------------------------------------------------------------------------

/// Default bind for [`StatusApiConfig::bind`] (`127.0.0.1:9617`).
#[must_use]
pub fn default_bind() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9617)
}

/// Default rate limit for [`StatusApiConfig::rate_limit_rps`] (~1 rps).
#[must_use]
pub fn default_rate_limit() -> f32 {
    1.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_secure() {
        let cfg = StatusApiConfig::default();
        assert!(!cfg.enabled, "must be disabled by default");
        assert_eq!(cfg.bind, default_bind());
        assert_eq!(cfg.bind.ip().to_string(), "127.0.0.1");
        assert!(cfg.read_only);
        assert!(cfg.expose_metrics);
        assert!((cfg.rate_limit_rps - 1.0).abs() < f32::EPSILON);
        assert!(!cfg.tls.enabled);
        assert!(matches!(cfg.auth.mode, StatusApiAuthMode::None));
    }

    #[test]
    fn roundtrips_none_auth() {
        let cfg = StatusApiConfig::default();
        let toml = toml::to_string(&cfg).unwrap();
        let back: StatusApiConfig = toml::from_str(&toml).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn parses_bearer_mode() {
        let s = r#"
enabled = true
bind = "127.0.0.1:9617"
read_only = true
expose_metrics = true
rate_limit_rps = 1.0

[tls]
enabled = false
cert_file = ""
key_file = ""

[auth]
mode = "bearer"
token_from = "secret://status/api-token"
"#;
        let cfg: StatusApiConfig = toml::from_str(s).unwrap();
        assert!(cfg.enabled);
        match cfg.auth.mode {
            StatusApiAuthMode::Bearer { token_from } => {
                assert_eq!(token_from.ns(), "status");
                assert_eq!(token_from.name(), "api-token");
            }
            other => panic!("expected Bearer, got {other:?}"),
        }
    }

    // Helper struct for the per-section parse tests below — kept at module
    // scope so clippy::items_after_statements stays happy.
    #[derive(Deserialize)]
    struct AuthOnly {
        auth: StatusApiAuthConfig,
    }

    #[test]
    fn parses_basic_mode() {
        let s = r#"
[auth]
mode = "basic"
user = "monitoring"
password_from = "secret://status/basic"
"#;
        let outer: AuthOnly = toml::from_str(s).unwrap();
        match outer.auth.mode {
            StatusApiAuthMode::Basic {
                user,
                password_from,
            } => {
                assert_eq!(user, "monitoring");
                assert_eq!(password_from.to_string(), "secret://status/basic");
            }
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    #[test]
    fn parses_mtls_mode() {
        let s = r#"
[auth]
mode = "mtls"
ca_bundle = "/etc/spt/clients-ca.pem"
allowed_subjects = ["CN=prom.internal", "CN=grafana.internal"]
"#;
        let outer: AuthOnly = toml::from_str(s).unwrap();
        match outer.auth.mode {
            StatusApiAuthMode::MutualTls {
                ca_bundle,
                allowed_subjects,
            } => {
                assert_eq!(ca_bundle, PathBuf::from("/etc/spt/clients-ca.pem"));
                assert_eq!(allowed_subjects.len(), 2);
            }
            other => panic!("expected MutualTls, got {other:?}"),
        }
    }
}
