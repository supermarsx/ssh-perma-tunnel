//! Configuration types for the SSH3 backend.
//!
//! These mirror the `[profiles.ssh3]` and `[profiles.tls]` sub-tables of the
//! TOML schema (spec §9.10 / §9.13). They are the surface a profile validator
//! constructs and hands to [`crate::Ssh3Protocol::connect`]. The types are
//! deliberately serde-friendly so `spt-config` can deserialize them directly.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use spt_auth::SecretRef;
use spt_core::{Error, Result};
use spt_trust::TlsPin;
use url::Url;

/// SSH3 backend configuration for one profile.
///
/// Supplied alongside an [`Endpoint`](spt_protocol::Endpoint) and an
/// [`AuthConfig`](spt_auth::AuthConfig) when constructing a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ssh3Config {
    /// Path component of the Extended-CONNECT request (e.g. `/ssh3`).
    ///
    /// The francoismichel/ssh3 reference exposes its endpoint at a configurable
    /// HTTP path; this is sent as the `:path` pseudo-header.
    #[serde(default = "default_url_path")]
    pub url_path: String,

    /// SNI / `:authority` to present to the server. When `None`, defaults to
    /// the endpoint host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,

    /// TLS configuration sub-table.
    #[serde(default)]
    pub tls: Ssh3TlsConfig,

    /// Auth extras specific to SSH3 transports.
    #[serde(default)]
    pub auth: Ssh3AuthExtras,

    /// **Operator must set this to `true` to silence the spec-mandated
    /// experimental warning** on each `connect()`. Default: `false`.
    ///
    /// Spec §4.2 requires that startup, `validate`, `doctor`, and
    /// `tunnel run` all emit a clearly-experimental notice for SSH3 unless
    /// the operator has explicitly acknowledged the status.
    #[serde(default)]
    pub acknowledge_experimental: bool,

    /// Optional QUIC keepalive interval in seconds (PING frames).
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u32,
}

fn default_url_path() -> String {
    "/ssh3".to_string()
}

const fn default_keepalive_secs() -> u32 {
    25
}

impl Default for Ssh3Config {
    fn default() -> Self {
        Self {
            url_path: default_url_path(),
            sni: None,
            tls: Ssh3TlsConfig::default(),
            auth: Ssh3AuthExtras::default(),
            acknowledge_experimental: false,
            keepalive_secs: default_keepalive_secs(),
        }
    }
}

/// TLS configuration applied to the QUIC handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ssh3TlsConfig {
    /// Optional explicit CA bundle (PEM). When present, replaces system roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,

    /// SHA-256 SPKI pin set. Empty means "no pinning" (system-roots only).
    #[serde(default, skip_serializing_if = "TlsPin_is_empty")]
    pub pin: TlsPin,

    /// Allow self-signed certificates. Spec §9.13: this is ALSO gated by
    /// `acknowledge_experimental` — both must be `true` for `connect()` to
    /// proceed in non-stub mode (when self-signed roots are encountered).
    #[serde(default)]
    pub allow_self_signed: bool,

    /// Optional ALPN values to advertise. SSH3 reference uses `h3` plus a
    /// custom string; default `["h3"]`.
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
}

#[allow(non_snake_case)]
fn TlsPin_is_empty(pin: &TlsPin) -> bool {
    pin.spki_sha256.is_empty()
}

fn default_alpn() -> Vec<String> {
    vec!["h3".to_string()]
}

impl Default for Ssh3TlsConfig {
    fn default() -> Self {
        Self {
            ca_file: None,
            pin: TlsPin::default(),
            allow_self_signed: false,
            alpn: default_alpn(),
        }
    }
}

/// Auth extras specific to SSH3 transports.
///
/// The base [`AuthConfig`](spt_auth::AuthConfig) carries the user-facing method
/// (bearer/basic/oidc); this struct carries any SSH3-specific knobs that don't
/// fit there cleanly.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Ssh3AuthExtras {
    /// Optional override for the OIDC discovery URL. When `None`, the
    /// [`AuthMethod::OidcDeviceFlow`](spt_auth::AuthMethod) issuer is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_discovery_url: Option<Url>,

    /// Optional secret reference for a cached OIDC refresh token. The OIDC
    /// device-flow handler stores and reads from this slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_refresh_token: Option<SecretRef>,
}

impl Ssh3Config {
    /// Validate the configuration shape.
    ///
    /// Currently this checks:
    ///
    /// * `url_path` starts with `/`.
    /// * If `tls.allow_self_signed` is `true`, `acknowledge_experimental` MUST
    ///   also be `true` (spec §9.13 — explicit dual-acknowledgment).
    /// * `keepalive_secs > 0`.
    pub fn validate(&self) -> Result<()> {
        if !self.url_path.starts_with('/') {
            return Err(Error::InvalidConfig(format!(
                "ssh3.url_path must start with '/' (got `{}`)",
                self.url_path
            )));
        }
        if self.tls.allow_self_signed && !self.acknowledge_experimental {
            return Err(Error::InvalidConfig(
                "ssh3.tls.allow_self_signed=true requires \
                 ssh3.acknowledge_experimental=true"
                    .to_string(),
            ));
        }
        if self.keepalive_secs == 0 {
            return Err(Error::InvalidConfig(
                "ssh3.keepalive_secs must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        Ssh3Config::default().validate().unwrap();
    }

    #[test]
    fn url_path_must_start_with_slash() {
        let c = Ssh3Config {
            url_path: "ssh3".into(),
            ..Ssh3Config::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn allow_self_signed_requires_ack() {
        let mut c = Ssh3Config {
            tls: Ssh3TlsConfig {
                allow_self_signed: true,
                ..Ssh3TlsConfig::default()
            },
            ..Ssh3Config::default()
        };
        let err = c.validate().unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
        c.acknowledge_experimental = true;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn keepalive_zero_rejected() {
        let c = Ssh3Config {
            keepalive_secs: 0,
            ..Ssh3Config::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn round_trip_json() {
        let c = Ssh3Config::default();
        let s = serde_json::to_string(&c).unwrap();
        let de: Ssh3Config = serde_json::from_str(&s).unwrap();
        assert_eq!(de.url_path, c.url_path);
        assert_eq!(de.acknowledge_experimental, c.acknowledge_experimental);
    }
}
