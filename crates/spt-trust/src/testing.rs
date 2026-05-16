//! Test facilities for `known_hosts`, SHA-256 host pins, and TLS pins.
//!
//! Activated via `--features testing`.

use ssh_key::{HashAlg, PublicKey};

use crate::known_hosts::KnownHosts;
use crate::sha256_pin::Sha256HostPin;
use crate::tls_pin::TlsPin;

/// Fluent builder for [`KnownHosts`] used in tests.
///
/// ```
/// # #[cfg(feature = "testing")] fn _doc() -> spt_core::Result<()> {
/// use spt_trust::testing::KnownHostsBuilder;
/// use spt_key::testing::fixtures;
/// let kp = fixtures::ed25519_kp()?;
/// let kh = KnownHostsBuilder::new()
///     .add("h.example", 22, kp.public_ref().clone())
///     .build();
/// assert_eq!(kh.entries.len(), 1);
/// # Ok(()) }
/// ```
#[derive(Debug, Default)]
pub struct KnownHostsBuilder {
    inner: KnownHosts,
}

impl KnownHostsBuilder {
    /// Construct an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an unhashed entry for `(host, port)`.
    #[must_use]
    pub fn add(mut self, host: &str, port: u16, key: PublicKey) -> Self {
        self.inner.add(host, port, key, false);
        self
    }

    /// Add a hashed (`|1|salt|hash`) entry for `(host, port)`.
    #[must_use]
    pub fn add_hashed(mut self, host: &str, port: u16, key: PublicKey) -> Self {
        self.inner.add(host, port, key, true);
        self
    }

    /// Finalize the builder.
    #[must_use]
    pub fn build(self) -> KnownHosts {
        self.inner
    }
}

/// Pre-built fixture values for negative and positive tests.
pub mod fixtures {
    use super::{HashAlg, KnownHosts, KnownHostsBuilder, PublicKey, Sha256HostPin, TlsPin};

    /// A small `KnownHosts` with three entries (loopback, hostname, hashed).
    ///
    /// All three reference the same Ed25519 fixture key from
    /// [`spt_key::testing::fixtures::ed25519_kp`], so the same public key
    /// matches every entry.
    ///
    /// ```
    /// # #[cfg(feature = "testing")] fn _doc() -> spt_core::Result<()> {
    /// let kh = spt_trust::testing::fixtures::sample_known_hosts()?;
    /// assert_eq!(kh.entries.len(), 3);
    /// # Ok(()) }
    /// ```
    pub fn sample_known_hosts() -> spt_core::Result<KnownHosts> {
        let kp = spt_key::testing::fixtures::ed25519_kp()?;
        let pk = kp.public_ref().clone();
        Ok(KnownHostsBuilder::new()
            .add("127.0.0.1", 22, pk.clone())
            .add("ssh.example.com", 22, pk.clone())
            .add_hashed("hashed.example.com", 2222, pk)
            .build())
    }

    /// Build a [`Sha256HostPin`] containing one accepted SHA-256 fingerprint
    /// for `public_key`, scoped to `h.example:22`.
    ///
    /// ```
    /// # #[cfg(feature = "testing")] fn _doc() -> spt_core::Result<()> {
    /// use spt_trust::testing::fixtures::sha256_pin_for;
    /// let kp = spt_key::testing::fixtures::ed25519_kp()?;
    /// let pin = sha256_pin_for(kp.public_ref());
    /// assert_eq!(pin.pins.len(), 1);
    /// # Ok(()) }
    /// ```
    #[must_use]
    pub fn sha256_pin_for(public_key: &PublicKey) -> Sha256HostPin {
        let mut pin = Sha256HostPin::new();
        let fp = public_key.fingerprint(HashAlg::Sha256).to_string();
        pin.insert("h.example", 22, fp);
        pin
    }

    /// Build a [`TlsPin`] from a DER-encoded X.509 certificate by hashing its
    /// `SubjectPublicKeyInfo`.
    ///
    /// Returns an empty pin set if the certificate cannot be parsed — useful
    /// only for negative-path tests where a malformed cert is acceptable.
    ///
    /// ```no_run
    /// # #[cfg(feature = "testing")] fn _doc() {
    /// // Assumes you have a real DER cert; rcgen is a common source.
    /// let der: &[u8] = &[];
    /// let _pin = spt_trust::testing::fixtures::tls_pin_from_cert_der(der);
    /// # }
    /// ```
    #[must_use]
    pub fn tls_pin_from_cert_der(der: &[u8]) -> TlsPin {
        use sha2::{Digest, Sha256};
        use x509_parser::prelude::*;
        let Ok((_, parsed)) = X509Certificate::from_der(der) else {
            return TlsPin::default();
        };
        let mut h = Sha256::new();
        h.update(parsed.tbs_certificate.subject_pki.raw);
        let got: [u8; 32] = h.finalize().into();
        TlsPin {
            spki_sha256: vec![got],
        }
    }

    /// A [`Sha256HostPin`] populated with a fingerprint that no real key will
    /// produce — useful for verifying the negative path of pin verification.
    ///
    /// ```
    /// # #[cfg(feature = "testing")] fn _doc() {
    /// let mismatched = spt_trust::testing::fixtures::mismatched_pin();
    /// assert_eq!(mismatched.pins.len(), 1);
    /// # }
    /// ```
    #[must_use]
    pub fn mismatched_pin() -> Sha256HostPin {
        let mut pin = Sha256HostPin::new();
        pin.insert(
            "h.example",
            22,
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        pin
    }
}

/// Convenience re-export at the module root for the most common helper.
pub use fixtures::mismatched_pin;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::known_hosts::KnownHostsResult;

    #[test]
    fn builder_round_trip() {
        let kp = spt_key::testing::fixtures::ed25519_kp().unwrap();
        let kh = KnownHostsBuilder::new()
            .add("h.example", 22, kp.public_ref().clone())
            .build();
        let r = kh.verify("h.example", 22, kp.public_ref());
        assert_eq!(r, KnownHostsResult::Match);
    }

    #[test]
    fn hashed_entry_matches() {
        let kp = spt_key::testing::fixtures::ed25519_kp().unwrap();
        let kh = KnownHostsBuilder::new()
            .add_hashed("hashed.example.com", 2222, kp.public_ref().clone())
            .build();
        assert!(kh.entries[0].host_field.starts_with("|1|"));
        assert_eq!(
            kh.verify("hashed.example.com", 2222, kp.public_ref()),
            KnownHostsResult::Match
        );
    }

    #[test]
    fn sample_fixtures_smoke() {
        let kh = fixtures::sample_known_hosts().unwrap();
        assert_eq!(kh.entries.len(), 3);
    }

    #[test]
    fn mismatched_pin_does_not_match_real_key() {
        let kp = spt_key::testing::fixtures::ed25519_kp().unwrap();
        let pin = mismatched_pin();
        let r = pin.verify("h.example", 22, kp.public_ref());
        assert!(matches!(r, KnownHostsResult::Mismatch { .. }));
    }

    #[test]
    fn builder_new_equals_default() {
        let _a = KnownHostsBuilder::new();
        let _b = KnownHostsBuilder::default();
        // No assertion needed; types just need to construct.
    }

    #[test]
    fn sha256_pin_for_matches_same_key() {
        let kp = spt_key::testing::fixtures::ed25519_kp().unwrap();
        let pin = fixtures::sha256_pin_for(kp.public_ref());
        // Pin scoped to h.example:22 in the helper.
        let r = pin.verify("h.example", 22, kp.public_ref());
        assert_eq!(r, KnownHostsResult::Match);
        // Different host returns NotFound.
        let r2 = pin.verify("other.example", 22, kp.public_ref());
        assert_eq!(r2, KnownHostsResult::NotFound);
    }

    #[test]
    fn tls_pin_from_cert_der_with_real_cert_matches_verify() {
        use crate::tls_pin::TlsPin;
        use rustls_pki_types::CertificateDer;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().to_vec();
        let pin = fixtures::tls_pin_from_cert_der(&der);
        assert_eq!(pin.spki_sha256.len(), 1);
        // Round-trip: the produced pin verifies against the cert it came from.
        let cert_der = CertificateDer::from(der);
        assert!(<TlsPin as Clone>::clone(&pin).verify(&cert_der).is_ok());
    }

    #[test]
    fn tls_pin_from_cert_der_with_garbage_yields_empty() {
        let pin = fixtures::tls_pin_from_cert_der(&[0u8, 1, 2, 3]);
        assert!(pin.spki_sha256.is_empty());
    }

    #[test]
    fn sample_known_hosts_verifies_for_each_entry_form() {
        use crate::known_hosts::KnownHostsResult;
        let kh = fixtures::sample_known_hosts().unwrap();
        assert_eq!(kh.entries.len(), 3);
        let kp = spt_key::testing::fixtures::ed25519_kp().unwrap();
        // Loopback + named (port 22) + hashed (port 2222) all match.
        assert_eq!(
            kh.verify("127.0.0.1", 22, kp.public_ref()),
            KnownHostsResult::Match
        );
        assert_eq!(
            kh.verify("ssh.example.com", 22, kp.public_ref()),
            KnownHostsResult::Match
        );
        assert_eq!(
            kh.verify("hashed.example.com", 2222, kp.public_ref()),
            KnownHostsResult::Match
        );
        // Hashed entry is keyed on (host, 2222) — port 22 misses.
        assert_eq!(
            kh.verify("hashed.example.com", 22, kp.public_ref()),
            KnownHostsResult::NotFound
        );
    }

    #[test]
    fn mismatched_pin_helper_uses_h_example() {
        let pin = fixtures::mismatched_pin();
        assert_eq!(pin.pins.len(), 1);
        assert!(pin.pins.keys().any(|k| k.contains("h.example")));
    }

    #[test]
    fn module_root_mismatched_pin_re_export_matches_fixtures() {
        // Re-export at module root should yield equivalent shape.
        let a = mismatched_pin();
        let b = fixtures::mismatched_pin();
        assert_eq!(a.pins.len(), b.pins.len());
    }
}
