//! Configuration types for the SSH3 backend.
//!
//! These mirror the `[profiles.ssh3]` and `[profiles.tls]` sub-tables of the
//! TOML schema (spec §9.10 / §9.13). They are the surface a profile validator
//! constructs and hands to [`spt_protocol::TunnelProtocol::connect`]. The types are
//! deliberately serde-friendly so `spt-config` can deserialize them directly.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use spt_auth::SecretRef;
use spt_core::{DnsResolution, Error, Result};
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

    /// Client-side DNS resolution policy (`[profiles.connection].dns_resolution`).
    ///
    /// [`DnsResolution::PerAttempt`] (default) re-resolves the endpoint host on
    /// every bootstrap — byte-for-byte the prior behaviour.
    /// [`DnsResolution::Once`] resolves once per `(host, port)` and pins the
    /// result across reconnects via the shared [`spt_core::dns`] cache.
    #[serde(default)]
    pub dns: DnsResolution,
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
            dns: DnsResolution::PerAttempt,
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

    /// Whether to load the OS trust store (system roots) as trust anchors.
    ///
    /// Default `true`. When `false`, the OS trust store is NOT loaded, and the
    /// only trust anchors are `ca_file` (when set) and/or the SPKI `pin` set —
    /// [`crate::tls`] never silently falls back to system roots. Honored
    /// INDEPENDENTLY of `ca_file`: `system_roots = false` disables the OS store
    /// even when no `ca_file` is present. `false` with neither a `ca_file` nor a
    /// pin (and without `allow_self_signed`) is a configuration error — nothing
    /// would be trusted — and [`Ssh3Config::validate`] rejects it.
    #[serde(default = "default_system_roots")]
    pub system_roots: bool,

    /// Offer the hybrid post-quantum TLS-1.3 key-exchange group
    /// `X25519MLKEM768` on the ssh3 QUIC handshake.
    ///
    /// Default `true` (PQ-by-default for spt↔spt ssh3, mirroring the ssh2
    /// `mlkem768x25519-sha256` default). When `true`, [`crate::tls`] builds the
    /// QUIC `rustls::ClientConfig` with a *per-config* aws-lc-rs provider whose
    /// `kx_groups` lead with `X25519MLKEM768` and fall back to classical
    /// X25519 / P-256 / P-384 — the negotiation is *hybrid*, so it is never
    /// weaker than classical X25519 and a non-PQ peer still connects.
    ///
    /// When `false`, the classical `ring` provider is used (no PQ group), giving
    /// an operator a force-off switch that reproduces the pre-PQ behaviour
    /// byte-for-byte. This never swaps the process-global rustls provider; only
    /// the ssh3 QUIC config is affected.
    #[serde(default = "default_post_quantum")]
    pub post_quantum: bool,
}

const fn default_system_roots() -> bool {
    true
}

const fn default_post_quantum() -> bool {
    true
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
            system_roots: true,
            post_quantum: default_post_quantum(),
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
    ///   also be `true` (spec §9.13 — explicit dual-acknowledgment). The
    ///   blind-accept combo (`allow_self_signed` with neither a pin nor a
    ///   `ca_file`) is permitted but emits a loud `tracing::warn!` that
    ///   certificate verification is DISABLED.
    /// * `tls.system_roots = false` with no `ca_file` and no pin (and no
    ///   `allow_self_signed`) is rejected — nothing would be trusted.
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
        // SECURITY (O3): `url_path` is emitted verbatim as the `:path`
        // pseudo-header value; apply the same control-char strictness as
        // `protocol_token` (below) so a path like "/x\r\nevil: 1" or one with
        // a NUL can never inject a second header / control sequence against a
        // lenient intermediary. (`extended_connect_raw` re-validates on the
        // wire path as defense-in-depth, but reject early with a clear error.)
        if let Some(b) = self.url_path.bytes().find(|&b| b < 0x20 || b == 0x7f) {
            return Err(Error::InvalidConfig(format!(
                "ssh3.url_path must not contain control bytes (found 0x{b:02x})"
            )));
        }
        if self.tls.allow_self_signed {
            // `acknowledge_experimental` keeps the "I know what I'm doing"
            // gate. It stays a HARD requirement.
            if !self.acknowledge_experimental {
                return Err(Error::InvalidConfig(
                    "ssh3.tls.allow_self_signed=true requires \
                     ssh3.acknowledge_experimental=true"
                        .to_string(),
                ));
            }
            // When a `ca_file` OR a pin is set, that anchor is now genuinely
            // enforced at connect time (see `crate::tls`): a `ca_file` forces
            // the server chain to validate against it (even with
            // `allow_self_signed`), and the pin path is fail-closed. Only the
            // combo with NEITHER a pin NOR a `ca_file` is true blind-accept:
            // WebPKI is skipped and any certificate is accepted. That is a
            // permitted dev-only mode (gated by `acknowledge_experimental`
            // above), but it is INSECURE — warn loudly rather than silently
            // accepting, and never confuse it with an enforced trust anchor.
            if self.tls.pin.spki_sha256.is_empty() && self.tls.ca_file.is_none() {
                tracing::warn!(
                    "ssh3.tls.allow_self_signed=true with no `tls.pin.spki_sha256` \
                     and no `tls.ca_file`: TLS certificate verification is DISABLED \
                     (INSECURE, dev-only)"
                );
            }
        }
        // `system_roots=false` removes the OS trust store as an anchor, HONORED
        // independently of `ca_file`. If that leaves nothing to trust (no
        // `ca_file`, no pin) and we are not in the blind-accept mode handled
        // above, the config can never succeed — the runtime fails closed (an
        // empty root store rejects every chain and never falls back to system
        // roots) — so reject it up front rather than failing opaquely at connect.
        if !self.tls.system_roots
            && self.tls.ca_file.is_none()
            && self.tls.pin.spki_sha256.is_empty()
            && !self.tls.allow_self_signed
        {
            return Err(Error::InvalidConfig(
                "ssh3.tls.system_roots=false requires a trust anchor — set \
                 `tls.ca_file` or a non-empty `tls.pin.spki_sha256` (nothing \
                 would be trusted otherwise)"
                    .to_string(),
            ));
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
    fn url_path_rejects_control_bytes() {
        // SECURITY (O3): a path that smuggles CR/LF (or NUL) must be rejected,
        // matching the strictness already applied to `protocol_token`.
        for bad in ["/x\r\nevil: 1", "/a\nb", "/a\rb", "/a\0b", "/a\x7fb"] {
            let c = Ssh3Config {
                url_path: bad.into(),
                ..Ssh3Config::default()
            };
            let err = c.validate().unwrap_err();
            assert!(matches!(err, Error::InvalidConfig(_)), "{bad:?} -> {err:?}");
        }
    }

    #[test]
    fn url_path_accepts_clean_path() {
        let c = Ssh3Config {
            url_path: "/ssh3".into(),
            ..Ssh3Config::default()
        };
        assert!(c.validate().is_ok());
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
        // Without `acknowledge_experimental` → hard error (unchanged).
        let err = c.validate().unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
        // With `acknowledge_experimental` but no pin/ca_file → now PERMITTED
        // (blind-accept dev mode) with a loud warning, no longer an error.
        c.acknowledge_experimental = true;
        c.validate()
            .expect("blind-accept is permitted once experimental is acknowledged");
    }

    #[tracing_test::traced_test]
    #[test]
    fn blind_accept_validate_warns() {
        // allow_self_signed + ack + NO pin + NO ca_file → validate must WARN
        // that verification is disabled (and still succeed).
        let c = Ssh3Config {
            tls: Ssh3TlsConfig {
                allow_self_signed: true,
                ..Ssh3TlsConfig::default()
            },
            acknowledge_experimental: true,
            ..Ssh3Config::default()
        };
        c.validate().unwrap();
        assert!(
            logs_contain("verification is DISABLED"),
            "blind-accept must log the insecure warning"
        );
    }

    #[test]
    fn system_roots_false_without_anchor_errors() {
        // system_roots=false with no ca_file, no pin, no allow_self_signed →
        // nothing to trust → ERROR (never a silent fall-back to system roots).
        let c = Ssh3Config {
            tls: Ssh3TlsConfig {
                system_roots: false,
                ..Ssh3TlsConfig::default()
            },
            ..Ssh3Config::default()
        };
        let err = c.validate().unwrap_err();
        assert!(
            matches!(err, Error::InvalidConfig(ref m) if m.contains("system_roots")),
            "got: {err:?}"
        );
    }

    #[test]
    fn system_roots_false_with_pin_ok() {
        let c = Ssh3Config {
            tls: Ssh3TlsConfig {
                system_roots: false,
                pin: TlsPin {
                    spki_sha256: vec![[9u8; 32]],
                },
                ..Ssh3TlsConfig::default()
            },
            ..Ssh3Config::default()
        };
        c.validate().unwrap();
    }

    #[test]
    fn system_roots_false_with_ca_ok() {
        let c = Ssh3Config {
            tls: Ssh3TlsConfig {
                system_roots: false,
                ca_file: Some(std::path::PathBuf::from("/etc/spt/private-ca.pem")),
                ..Ssh3TlsConfig::default()
            },
            ..Ssh3Config::default()
        };
        c.validate().unwrap();
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
        // PQ hybrid KEX is on by default (mirrors ssh2 policy).
        assert!(de.tls.post_quantum);
    }

    #[test]
    fn post_quantum_defaults_on_and_round_trips() {
        // Default is ON (PQ-by-default for spt↔spt ssh3).
        assert!(Ssh3TlsConfig::default().post_quantum);
        assert!(Ssh3Config::default().tls.post_quantum);

        // A profile can force it OFF and that survives a serde round-trip.
        let c = Ssh3Config {
            tls: Ssh3TlsConfig {
                post_quantum: false,
                ..Ssh3TlsConfig::default()
            },
            ..Ssh3Config::default()
        };
        let s = serde_json::to_string(&c).unwrap();
        let de: Ssh3Config = serde_json::from_str(&s).unwrap();
        assert!(!de.tls.post_quantum);
        // Absent key in a legacy `[profiles.tls]` sub-table → defaults ON.
        let legacy: Ssh3TlsConfig = serde_json::from_str("{}").unwrap();
        assert!(legacy.post_quantum);
    }
}
