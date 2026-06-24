//! `ObfsConfig` — on-disk representation of every obfuscation transport.
//!
//! The enum mirrors the `[profiles.transport.obfuscation]` table on the
//! `Profile::transport` schema added by t6-e13. The `kind` discriminator is
//! serde-tagged so unknown variants are flagged at parse time rather than
//! silently demoted to an "obfs4 default" — important because operators must
//! see misconfigured obfuscation at config-load time, not at first connect.

use serde::{Deserialize, Serialize};

use spt_secrets::SecretRef;

use crate::error::ObfsError;

/// Symmetric cipher selector for the Shadowsocks transport.
///
/// AEAD-2022 modes are the recommended floor; legacy AEAD modes remain for
/// interoperability with older servers but log a deprecation warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SsMethod {
    /// AES-128-GCM, legacy AEAD profile.
    Aes128Gcm,
    /// AES-256-GCM, legacy AEAD profile.
    Aes256Gcm,
    /// ChaCha20-Poly1305, legacy AEAD profile.
    ChaCha20Poly1305,
    /// AEAD-2022 with AES-128-GCM keying.
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aead2022Blake3Aes128Gcm,
    /// AEAD-2022 with AES-256-GCM keying.
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aead2022Blake3Aes256Gcm,
    /// AEAD-2022 with ChaCha20-Poly1305 keying.
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Aead2022Blake3ChaCha20Poly1305,
}

impl SsMethod {
    /// Stable identifier used in audit logs / config-error messages.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SsMethod::Aes128Gcm => "aes-128-gcm",
            SsMethod::Aes256Gcm => "aes-256-gcm",
            SsMethod::ChaCha20Poly1305 => "chacha20-poly1305",
            SsMethod::Aead2022Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
            SsMethod::Aead2022Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
            SsMethod::Aead2022Blake3ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    /// Key length in bytes for the chosen cipher.
    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            SsMethod::Aes128Gcm | SsMethod::Aead2022Blake3Aes128Gcm => 16,
            SsMethod::Aes256Gcm
            | SsMethod::ChaCha20Poly1305
            | SsMethod::Aead2022Blake3Aes256Gcm
            | SsMethod::Aead2022Blake3ChaCha20Poly1305 => 32,
        }
    }

    /// Returns true for AEAD-2022 variants (BLAKE3-keyed subkey derivation).
    #[must_use]
    pub fn is_aead_2022(self) -> bool {
        matches!(
            self,
            SsMethod::Aead2022Blake3Aes128Gcm
                | SsMethod::Aead2022Blake3Aes256Gcm
                | SsMethod::Aead2022Blake3ChaCha20Poly1305
        )
    }
}

/// Obfuscation transport configuration.
///
/// `#[serde(tag = "kind")]` so the discriminator is explicit on the wire:
///
/// ```toml
/// [profiles.transport.obfuscation]
/// kind = "websocket"
/// url = "wss://front.example/ssh"
/// headers = []
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ObfsConfig {
    /// Tor PT obfs4 bridge — NTOR-style handshake + ChaCha20-Poly1305 framing.
    Obfs4 {
        /// 20-byte server node id (hex-decoded by the loader).
        node_id: [u8; 20],
        /// 32-byte server identity public key.
        public_key: [u8; 32],
        /// Inter-arrival timing obfuscation mode (0 / 1 / 2 per Tor PT spec).
        iat_mode: u8,
    },
    /// meek-style HTTPS-CONNECT fronting.
    MeekHttp {
        /// Fronting URL (the TLS SNI target).
        url: String,
        /// Optional Host: header override — when set, this is sent in the
        /// HTTP request while `sni` (or the URL's host) drives TLS SNI.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        front_host: Option<String>,
        /// Optional explicit SNI override (when the URL's host is unsuitable).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
    },
    /// Tunnel SSH wire bytes inside a WebSocket upgrade.
    Websocket {
        /// WebSocket endpoint (`ws://` or `wss://`).
        url: String,
        /// Extra HTTP headers added to the WS upgrade request.
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
    /// Tunnel SSH wire bytes inside Shadowsocks AEAD framing.
    Shadowsocks {
        /// Cipher selector.
        method: SsMethod,
        /// Pre-shared password reference (resolved via `spt-secrets`).
        password: SecretRef,
    },
}

impl ObfsConfig {
    /// Validate the parsed config without touching the network.
    ///
    /// Run at construction time. Returns [`ObfsError::InvalidConfig`] with a
    /// human-readable message on shape-level errors.
    pub fn validate(&self) -> Result<(), ObfsError> {
        match self {
            ObfsConfig::Obfs4 { iat_mode, .. } => {
                if *iat_mode > 2 {
                    return Err(ObfsError::InvalidConfig(format!(
                        "obfs4 iat_mode must be 0, 1, or 2 (got {iat_mode})"
                    )));
                }
                Ok(())
            }
            ObfsConfig::MeekHttp { url, .. } => {
                if url.is_empty() {
                    return Err(ObfsError::InvalidConfig(
                        "meek-http url must not be empty".into(),
                    ));
                }
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    return Err(ObfsError::InvalidConfig(format!(
                        "meek-http url must start with http:// or https:// (got {url})"
                    )));
                }
                Ok(())
            }
            ObfsConfig::Websocket { url, .. } => {
                if url.is_empty() {
                    return Err(ObfsError::InvalidConfig(
                        "websocket url must not be empty".into(),
                    ));
                }
                if !url.starts_with("ws://") && !url.starts_with("wss://") {
                    return Err(ObfsError::InvalidConfig(format!(
                        "websocket url must start with ws:// or wss:// (got {url})"
                    )));
                }
                Ok(())
            }
            ObfsConfig::Shadowsocks { .. } => Ok(()),
        }
    }

    /// Static transport name used for audit log lines.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            ObfsConfig::Obfs4 { .. } => "obfs4",
            ObfsConfig::MeekHttp { .. } => "meek-http",
            ObfsConfig::Websocket { .. } => "ssh-over-websocket",
            ObfsConfig::Shadowsocks { .. } => "ssh-over-shadowsocks",
        }
    }

    /// The secret reference this transport needs resolved before it can dial,
    /// if any.
    ///
    /// Only the Shadowsocks transport carries a pre-shared `password`
    /// reference; every other transport returns `None`. Callers (the SSH dial
    /// path) resolve the returned reference through the secrets backend chain
    /// and hand the bytes to [`crate::transport_for_with_secret`].
    #[must_use]
    pub fn password_ref(&self) -> Option<&SecretRef> {
        match self {
            ObfsConfig::Shadowsocks { password, .. } => Some(password),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfs4_round_trip_serde() {
        let cfg = ObfsConfig::Obfs4 {
            node_id: [7u8; 20],
            public_key: [3u8; 32],
            iat_mode: 1,
        };
        let s = serde_json::to_string(&cfg).unwrap();
        let back: ObfsConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn meek_round_trip_serde() {
        let cfg = ObfsConfig::MeekHttp {
            url: "https://front.cdn/path".into(),
            front_host: Some("hidden.example".into()),
            sni: None,
        };
        let s = serde_json::to_string(&cfg).unwrap();
        let back: ObfsConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn websocket_round_trip_serde() {
        let cfg = ObfsConfig::Websocket {
            url: "wss://example.test/ssh".into(),
            headers: vec![("X-Auth".into(), "tok".into())],
        };
        let s = serde_json::to_string(&cfg).unwrap();
        let back: ObfsConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn shadowsocks_round_trip_serde() {
        let cfg = ObfsConfig::Shadowsocks {
            method: SsMethod::Aead2022Blake3Aes256Gcm,
            password: SecretRef::new("ns", "ss_pw").unwrap(),
        };
        let s = serde_json::to_string(&cfg).unwrap();
        let back: ObfsConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn validate_rejects_bad_iat() {
        let cfg = ObfsConfig::Obfs4 {
            node_id: [0; 20],
            public_key: [0; 32],
            iat_mode: 9,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn ssmethod_key_len_matches_spec() {
        assert_eq!(SsMethod::Aes128Gcm.key_len(), 16);
        assert_eq!(SsMethod::Aes256Gcm.key_len(), 32);
        assert_eq!(SsMethod::ChaCha20Poly1305.key_len(), 32);
        assert_eq!(SsMethod::Aead2022Blake3Aes128Gcm.key_len(), 16);
        assert!(SsMethod::Aead2022Blake3Aes256Gcm.is_aead_2022());
    }
}
