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

use crate::chain_depth::{check_chain_depth, ChainDepthCap};

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

    /// True iff no pins are configured.
    pub fn is_empty(&self) -> bool {
        self.spki_sha256.is_empty()
    }

    /// Number of configured pins.
    pub fn len(&self) -> usize {
        self.spki_sha256.len()
    }

    /// Compute SPKI SHA-256 of a DER-encoded certificate.
    ///
    /// Returns `InvalidConfig` if the certificate fails to parse.
    pub fn spki_sha256_of(cert: &CertificateDer<'_>) -> Result<[u8; 32]> {
        let (_, parsed) = X509Certificate::from_der(cert.as_ref())
            .map_err(|e| Error::InvalidConfig(format!("x509 parse: {e}")))?;
        let spki_der = parsed.tbs_certificate.subject_pki.raw;
        let mut h = Sha256::new();
        h.update(spki_der);
        Ok(h.finalize().into())
    }

    /// Constant-time check whether `digest` matches any configured pin.
    ///
    /// Returns `false` when the pin set is empty.
    pub fn matches_digest(&self, digest: &[u8; 32]) -> bool {
        let mut found = 0u8;
        for want in &self.spki_sha256 {
            // ct_eq returns a Choice; OR the byte-equivalent (0 or 1) into
            // `found`. We never short-circuit so the timing is independent
            // of which pin matched.
            found |= digest.ct_eq(want).unwrap_u8();
        }
        found != 0
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
        let got = Self::spki_sha256_of(cert)?;
        if self.matches_digest(&got) {
            return Ok(());
        }
        Err(Error::TrustFailed(format!(
            "TLS SPKI pin mismatch: got SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(got)
        )))
    }

    /// Verify a server-presented certificate chain against both the pin
    /// set and a [`ChainDepthCap`].
    ///
    /// `chain` is in TLS-wire order: index 0 is the end-entity (leaf),
    /// and the remaining entries are intermediates. The pin match is
    /// performed against the leaf (matching `verify`); the depth cap is
    /// enforced via [`check_chain_depth`].
    ///
    /// This is the entry point shared with t5-e1's `PinnedTlsConnector`
    /// `ServerCertVerifier`: it lets both the SSH3 verifier and the
    /// generic pinned-HTTPS connector apply identical policy.
    ///
    /// # Errors
    ///
    /// * [`Error::TrustFailed`] when the chain is empty, when the
    ///   intermediate count meets/exceeds the cap, or when the leaf's
    ///   SPKI does not match any configured pin.
    /// * [`Error::InvalidConfig`] when called with an empty pin set or
    ///   when the leaf fails to parse.
    #[allow(clippy::trivially_copy_pass_by_ref)] // signature matches `check_chain_depth`
    pub fn verify_chain(
        &self,
        chain: &[CertificateDer<'_>],
        depth_cap: &ChainDepthCap,
    ) -> Result<()> {
        check_chain_depth(chain, depth_cap)?;
        // `check_chain_depth` already rejected the empty-chain case, but
        // be defensive in case a future refactor relaxes that.
        let leaf = chain
            .first()
            .ok_or_else(|| Error::TrustFailed("empty TLS certificate chain".to_string()))?;
        self.verify(leaf)
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

    /// Build a self-signed cert and compute its SPKI SHA-256.
    fn gen_cert_and_pin() -> (Vec<u8>, [u8; 32]) {
        use x509_parser::prelude::*;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().to_vec();
        let (_, parsed) = X509Certificate::from_der(&der).unwrap();
        let mut h = Sha256::new();
        h.update(parsed.tbs_certificate.subject_pki.raw);
        let pin: [u8; 32] = h.finalize().into();
        (der, pin)
    }

    #[test]
    fn verify_accepts_matching_pin_real_cert() {
        let (der, pin) = gen_cert_and_pin();
        let pinset = TlsPin {
            spki_sha256: vec![pin],
        };
        let cert = CertificateDer::from(der);
        pinset.verify(&cert).unwrap();
    }

    #[test]
    fn verify_rejects_when_cert_does_not_match_any_pin() {
        let (der, _real_pin) = gen_cert_and_pin();
        let pinset = TlsPin {
            spki_sha256: vec![[0xAB; 32]],
        };
        let cert = CertificateDer::from(der);
        let err = pinset.verify(&cert).unwrap_err();
        match err {
            Error::TrustFailed(msg) => {
                assert!(msg.contains("TLS SPKI pin mismatch"));
                assert!(msg.contains("SHA256:"));
            }
            other => panic!("expected TrustFailed, got {other:?}"),
        }
    }

    #[test]
    fn verify_accepts_pin_in_a_set_of_many() {
        let (der, pin) = gen_cert_and_pin();
        let pinset = TlsPin {
            spki_sha256: vec![[0u8; 32], [0xFF; 32], pin, [0x55; 32]],
        };
        let cert = CertificateDer::from(der);
        pinset.verify(&cert).unwrap();
    }

    #[test]
    fn from_strings_parses_mixed_forms() {
        // Mix hex, base64 (padded), base64 (no pad), and SHA256: prefixed.
        use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
        use base64::Engine;
        let zeros_hex = "0".repeat(64);
        let zeros_b64 = STANDARD.encode([0u8; 32]);
        let zeros_b64nopad = STANDARD_NO_PAD.encode([0u8; 32]);
        let prefixed = format!("SHA256:{zeros_b64nopad}");
        let pin = TlsPin::from_strings([
            zeros_hex.as_str(),
            zeros_b64.as_str(),
            zeros_b64nopad.as_str(),
            prefixed.as_str(),
        ])
        .unwrap();
        assert_eq!(pin.spki_sha256.len(), 4);
        for p in &pin.spki_sha256 {
            assert_eq!(p, &[0u8; 32]);
        }
    }

    #[test]
    fn from_strings_rejects_wrong_length() {
        // 24 zero bytes → 32 base64 chars without padding → not 32-byte digest.
        let short = base64::engine::general_purpose::STANDARD_NO_PAD.encode([0u8; 24]);
        let err = TlsPin::from_strings([short.as_str()]).unwrap_err();
        match err {
            Error::InvalidConfig(msg) => assert!(msg.contains("32 bytes")),
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn parse_pin_string_rejects_bad_hex() {
        // Exactly 64 chars, but contains a non-hex character → falls through
        // to the base64 path and either decodes wrong-length or fails to decode.
        // We pick a 64-char string of `Z` which is valid base64 but not hex.
        let bad = "Z".repeat(64);
        let err = parse_pin_string(&bad).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn parse_pin_string_rejects_padded_base64_garbage() {
        // base64 with `=` padding so we hit the STANDARD path; garbage chars.
        let bad = "!!!!====";
        let err = parse_pin_string(bad).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn parse_pin_string_rejects_nopad_base64_garbage() {
        // No `=` → STANDARD_NO_PAD path; deliberately invalid chars.
        let bad = "%%%%";
        let err = parse_pin_string(bad).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn parse_pin_string_strips_sha256_prefix() {
        // SHA256: + hex shouldn't trip the parser even when the digest is hex.
        let p = parse_pin_string(&format!("SHA256:{}", "0".repeat(64))).unwrap();
        assert_eq!(p, [0u8; 32]);
    }

    #[test]
    fn hex_decode_32_rejects_nonhex_byte() {
        // 64 chars but a non-hex char in the middle.
        let mut buf = vec![b'0'; 64];
        buf[10] = b'Z';
        let s = String::from_utf8(buf).unwrap();
        let err = hex_decode_32(&s).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn from_strings_empty_iterator_yields_empty_pin() {
        let pin = TlsPin::from_strings(std::iter::empty::<&str>()).unwrap();
        assert!(pin.spki_sha256.is_empty());
        // ... and that empty pin set rejects on verify.
        let cert = CertificateDer::from(vec![0u8]);
        assert!(pin.verify(&cert).is_err());
    }
}
