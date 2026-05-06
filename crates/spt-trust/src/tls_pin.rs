//! TLS Subject Public Key Info (SPKI) pinning for the SSH3 backend.
//!
//! Spec §9.13: `[profiles.tls].pin_sha256 = []`. Each pin is the SHA-256 of
//! the certificate's DER-encoded `SubjectPublicKeyInfo`, matching the format
//! that `openssl x509 -pubkey -noout | openssl rsa -pubin -outform DER |
//! openssl dgst -sha256` produces.

use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x509_parser::prelude::*;

use spt_core::{Error, Result};

/// One or more accepted SPKI SHA-256 hashes (raw 32-byte digests).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TlsPin {
    /// Accepted SPKI SHA-256 digests (32 bytes each).
    pub spki_sha256: Vec<[u8; 32]>,
}

impl TlsPin {
    /// Build a pin set from `SHA256:<base64>` or hex strings.
    pub fn from_strings(strings: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Self> {
        let mut out = Vec::new();
        for s in strings {
            out.push(parse_pin_string(s.as_ref())?);
        }
        Ok(Self { spki_sha256: out })
    }

    /// Verify `cert` (DER) against the configured pin set.
    ///
    /// Returns `Ok(())` on first match. Returns `TrustFailed` if the
    /// certificate's SPKI does not match any configured pin, or `InvalidConfig`
    /// if the certificate fails to parse.
    pub fn verify(&self, cert: &CertificateDer<'_>) -> Result<()> {
        if self.spki_sha256.is_empty() {
            return Err(Error::InvalidConfig(
                "TlsPin::verify called with empty pin set".into(),
            ));
        }
        let (_, parsed) = X509Certificate::from_der(cert.as_ref())
            .map_err(|e| Error::InvalidConfig(format!("x509 parse: {e}")))?;
        let spki_der = parsed.tbs_certificate.subject_pki.raw;
        let mut h = Sha256::new();
        h.update(spki_der);
        let got: [u8; 32] = h.finalize().into();
        for want in &self.spki_sha256 {
            if got.ct_eq(want).into() {
                return Ok(());
            }
        }
        Err(Error::TrustFailed(format!(
            "TLS SPKI pin mismatch: got SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(got)
        )))
    }
}

fn parse_pin_string(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    let body = s.strip_prefix("SHA256:").unwrap_or(s);
    let bytes = if body.len() == 64 && body.chars().all(|c| c.is_ascii_hexdigit()) {
        // hex form
        hex_decode_32(body)?
    } else {
        // base64 (with or without padding)
        let raw = base64_any(body)?;
        if raw.len() != 32 {
            return Err(Error::InvalidConfig(format!(
                "TLS pin must decode to 32 bytes; got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        out
    };
    Ok(bytes)
}

fn hex_decode_32(s: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| Error::InvalidConfig(format!("hex pin: {e}")))?;
        out[i] = byte;
    }
    Ok(out)
}

fn base64_any(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
    use base64::Engine;
    if s.contains('=') {
        STANDARD
            .decode(s)
            .map_err(|e| Error::InvalidConfig(format!("base64 pin: {e}")))
    } else {
        STANDARD_NO_PAD
            .decode(s)
            .map_err(|e| Error::InvalidConfig(format!("base64 pin: {e}")))
    }
}

// Pull `base64::Engine` into scope for the verify error path above.
use base64::Engine as _;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pin_string_forms() {
        // 32-byte zero digest in three forms.
        let zeros_hex = "0".repeat(64);
        let zeros_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let zeros_b64nopad = base64::engine::general_purpose::STANDARD_NO_PAD.encode([0u8; 32]);
        let prefixed = format!("SHA256:{zeros_b64nopad}");
        for s in [
            zeros_hex.as_str(),
            zeros_b64.as_str(),
            zeros_b64nopad.as_str(),
            prefixed.as_str(),
        ] {
            let p = parse_pin_string(s).unwrap();
            assert_eq!(p, [0u8; 32], "input was {s}");
        }
    }

    #[test]
    fn empty_pinset_rejected() {
        let pin = TlsPin::default();
        // Construct a bogus 1-byte cert just to drive the empty-set path.
        let cert = CertificateDer::from(vec![0u8]);
        let r = pin.verify(&cert);
        assert!(r.is_err());
    }

    #[test]
    fn malformed_cert_is_invalid_config() {
        let pin = TlsPin {
            spki_sha256: vec![[0u8; 32]],
        };
        let cert = CertificateDer::from(vec![0x30, 0x00]);
        let err = pin.verify(&cert).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}
