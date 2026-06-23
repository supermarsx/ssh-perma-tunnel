//! Configuration types for the SSH3 backend.
//!
//! These mirror the `[profiles.ssh3]` and `[profiles.tls]` sub-tables of the
//! TOML schema (spec §9.10 / §9.13). They are the surface a profile validator
//! constructs and hands to [`spt_protocol::TunnelProtocol::connect`]. The types are
//! deliberately serde-friendly so `spt-config` can deserialize them directly.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use spt_auth::SecretRef;
use spt_core::{Error, Result};
use spt_trust::{ChainDepthCap, TlsPin};
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

    /// Optional QUIC max-idle-timeout in seconds. `None` leaves the implicit
    /// quinn default in place (behaviour-preserving). When set, maps to
    /// [`quinn::TransportConfig::max_idle_timeout`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u32>,

    /// Optional cap on concurrent bidirectional QUIC streams the peer may open.
    /// `None` leaves the implicit quinn default in place
    /// (behaviour-preserving). When set, maps to
    /// [`quinn::TransportConfig::max_concurrent_bidi_streams`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<u32>,

    /// Whether QUIC datagrams (the substrate for UDP forwards) are enabled.
    ///
    /// Default `true` — this matches today's implicit behaviour where
    /// datagrams rely on quinn's defaults. Setting `false` explicitly disables
    /// the datagram receive buffer so the peer cannot send datagrams, and UDP
    /// forwards surface [`Error::UnsupportedPlatform`].
    #[serde(default = "default_enable_datagrams")]
    pub enable_datagrams: bool,

    /// The `:protocol` pseudo-header value sent on the Extended-CONNECT
    /// request. `None` ⇒ `"ssh3"` (the francoismichel/ssh3 reference value and
    /// today's hard-coded behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_token: Option<String>,
}

fn default_url_path() -> String {
    "/ssh3".to_string()
}

const fn default_keepalive_secs() -> u32 {
    25
}

const fn default_enable_datagrams() -> bool {
    true
}

/// Default `:protocol` token used when [`Ssh3Config::protocol_token`] is
/// `None`. Matches the francoismichel/ssh3 reference.
pub const DEFAULT_PROTOCOL_TOKEN: &str = "ssh3";

impl Default for Ssh3Config {
    fn default() -> Self {
        Self {
            url_path: default_url_path(),
            sni: None,
            tls: Ssh3TlsConfig::default(),
            auth: Ssh3AuthExtras::default(),
            acknowledge_experimental: false,
            keepalive_secs: default_keepalive_secs(),
            idle_timeout_secs: None,
            max_streams: None,
            enable_datagrams: default_enable_datagrams(),
            protocol_token: None,
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
    /// proceed when self-signed roots are encountered.
    #[serde(default)]
    pub allow_self_signed: bool,

    /// Optional ALPN values to advertise. SSH3 reference uses `h3` plus a
    /// custom string; default `["h3"]`.
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,

    /// Maximum permitted certificate-chain depth (intermediates count).
    ///
    /// Default `Some(5)`. `None` disables the structural depth check.
    /// Mirrors `[profiles.tls].max_cert_chain_depth` in the TOML schema.
    /// See [`spt_trust::ChainDepthCap`].
    #[serde(default)]
    pub max_cert_chain_depth: ChainDepthCap,
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
            max_cert_chain_depth: ChainDepthCap::default(),
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
    /// The effective `:protocol` token: [`Ssh3Config::protocol_token`] when set
    /// (and non-empty), otherwise [`DEFAULT_PROTOCOL_TOKEN`].
    #[must_use]
    pub fn protocol_token_value(&self) -> &str {
        match self.protocol_token.as_deref() {
            Some(t) if !t.is_empty() => t,
            _ => DEFAULT_PROTOCOL_TOKEN,
        }
    }

    /// Validate the configuration shape.
    ///
    /// Currently this checks:
    ///
    /// * `url_path` starts with `/`.
    /// * If `tls.allow_self_signed` is `true`, `acknowledge_experimental` MUST
    ///   also be `true` (spec §9.13 — explicit dual-acknowledgment).
    /// * `keepalive_secs > 0`.
    /// * `idle_timeout_secs`, when set, is `> 0`.
    /// * `max_streams`, when set, is `> 0`.
    /// * `protocol_token`, when set, is non-empty and contains only printable
    ///   ASCII (it is sent verbatim as an HTTP/3 pseudo-header value).
    pub fn validate(&self) -> Result<()> {
        if !self.url_path.starts_with('/') {
            return Err(Error::InvalidConfig(format!(
                "ssh3.url_path must start with '/' (got `{}`)",
                self.url_path
            )));
        }
        if self.tls.allow_self_signed {
            // `acknowledge_experimental` keeps the "I know what I'm doing"
            // gate, but on its own it does NOT make `allow_self_signed`
            // safe: WebPKI is skipped, so without either an explicit pin
            // set or a `ca_file` the only trust check is "the server
            // presented *some* certificate." That collapses TLS to a
            // hostname-confirmation no-op. Require at least one of:
            //   - `tls.pin.spki_sha256` is non-empty (pinned), or
            //   - `tls.ca_file` is set (private CA bundle).
            if !self.acknowledge_experimental {
                return Err(Error::InvalidConfig(
                    "ssh3.tls.allow_self_signed=true requires \
                     ssh3.acknowledge_experimental=true"
                        .to_string(),
                ));
            }
            if self.tls.pin.spki_sha256.is_empty() && self.tls.ca_file.is_none() {
                return Err(Error::InvalidConfig(
                    "ssh3.tls.allow_self_signed=true requires either a non-empty \
                     `tls.pin.spki_sha256` pin set or a `tls.ca_file` private CA \
                     bundle — otherwise no trust anchor is enforced"
                        .to_string(),
                ));
            }
        }
        if self.keepalive_secs == 0 {
            return Err(Error::InvalidConfig(
                "ssh3.keepalive_secs must be > 0".to_string(),
            ));
        }
        if self.idle_timeout_secs == Some(0) {
            return Err(Error::InvalidConfig(
                "ssh3.idle_timeout_secs must be > 0 when set (omit it to use the \
                 transport default)"
                    .to_string(),
            ));
        }
        if self.max_streams == Some(0) {
            return Err(Error::InvalidConfig(
                "ssh3.max_streams must be > 0 when set (omit it to use the \
                 transport default)"
                    .to_string(),
            ));
        }
        if let Some(token) = self.protocol_token.as_deref() {
            if token.is_empty() {
                return Err(Error::InvalidConfig(
                    "ssh3.protocol_token must be non-empty when set (omit it to \
                     use the default `ssh3`)"
                        .to_string(),
                ));
            }
            // The token is emitted verbatim as the `:protocol` pseudo-header
            // value; reject anything that is not printable ASCII (no controls,
            // no whitespace, no high bytes) so it can never inject framing.
            if !token.bytes().all(|b| b.is_ascii_graphic() && b != b' ') {
                return Err(Error::InvalidConfig(format!(
                    "ssh3.protocol_token must be printable non-space ASCII (got `{token}`)"
                )));
            }
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
        // Without `acknowledge_experimental` → fail.
        let err = c.validate().unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
        // With `acknowledge_experimental` but no pin/ca_file → still fail.
        c.acknowledge_experimental = true;
        let err = c.validate().unwrap_err();
        match err {
            Error::InvalidConfig(m) => {
                assert!(
                    m.contains("`tls.pin.spki_sha256`") || m.contains("`tls.ca_file`"),
                    "got: {m}"
                );
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn allow_self_signed_with_pin_validates() {
        let c = Ssh3Config {
            tls: Ssh3TlsConfig {
                allow_self_signed: true,
                pin: TlsPin {
                    spki_sha256: vec![[0xABu8; 32]],
                },
                ..Ssh3TlsConfig::default()
            },
            acknowledge_experimental: true,
            ..Ssh3Config::default()
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn allow_self_signed_with_ca_file_validates() {
        let c = Ssh3Config {
            tls: Ssh3TlsConfig {
                allow_self_signed: true,
                ca_file: Some(std::path::PathBuf::from("/etc/spt/private-ca.pem")),
                ..Ssh3TlsConfig::default()
            },
            acknowledge_experimental: true,
            ..Ssh3Config::default()
        };
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

    #[test]
    fn new_knob_defaults_are_behaviour_preserving() {
        let c = Ssh3Config::default();
        assert_eq!(c.idle_timeout_secs, None);
        assert_eq!(c.max_streams, None);
        assert!(c.enable_datagrams);
        assert_eq!(c.protocol_token, None);
        assert_eq!(c.protocol_token_value(), "ssh3");
        c.validate().unwrap();
    }

    #[test]
    fn protocol_token_value_falls_back_on_empty() {
        let c = Ssh3Config {
            protocol_token: Some(String::new()),
            ..Ssh3Config::default()
        };
        // Accessor falls back; validate rejects the empty literal.
        assert_eq!(c.protocol_token_value(), "ssh3");
        assert!(c.validate().is_err());
    }

    #[test]
    fn protocol_token_custom_value_kept() {
        let c = Ssh3Config {
            protocol_token: Some("ssh3-next".into()),
            ..Ssh3Config::default()
        };
        assert_eq!(c.protocol_token_value(), "ssh3-next");
        c.validate().unwrap();
    }

    #[test]
    fn protocol_token_rejects_non_ascii_or_space() {
        for bad in ["ssh 3", "ssh3\n", "ssh3\u{00e9}"] {
            let c = Ssh3Config {
                protocol_token: Some(bad.into()),
                ..Ssh3Config::default()
            };
            assert!(c.validate().is_err(), "should reject `{bad}`");
        }
    }

    #[test]
    fn idle_timeout_and_max_streams_zero_rejected() {
        let c = Ssh3Config {
            idle_timeout_secs: Some(0),
            ..Ssh3Config::default()
        };
        assert!(c.validate().is_err());
        let c = Ssh3Config {
            max_streams: Some(0),
            ..Ssh3Config::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn positive_knobs_validate() {
        let c = Ssh3Config {
            idle_timeout_secs: Some(30),
            max_streams: Some(64),
            enable_datagrams: false,
            protocol_token: Some("ssh3".into()),
            ..Ssh3Config::default()
        };
        c.validate().unwrap();
    }

    #[test]
    fn round_trip_json_preserves_new_knobs() {
        let c = Ssh3Config {
            idle_timeout_secs: Some(45),
            max_streams: Some(128),
            enable_datagrams: false,
            protocol_token: Some("ssh3-x".into()),
            ..Ssh3Config::default()
        };
        let s = serde_json::to_string(&c).unwrap();
        let de: Ssh3Config = serde_json::from_str(&s).unwrap();
        assert_eq!(de.idle_timeout_secs, Some(45));
        assert_eq!(de.max_streams, Some(128));
        assert!(!de.enable_datagrams);
        assert_eq!(de.protocol_token.as_deref(), Some("ssh3-x"));
    }

    #[test]
    fn omitted_new_knobs_deserialize_to_defaults() {
        // A config TOML/JSON that predates the new fields must still parse,
        // with the new fields taking behaviour-preserving defaults.
        let de: Ssh3Config = serde_json::from_str(r#"{"url_path":"/ssh3"}"#).unwrap();
        assert_eq!(de.idle_timeout_secs, None);
        assert_eq!(de.max_streams, None);
        assert!(de.enable_datagrams);
        assert_eq!(de.protocol_token, None);
    }
}
