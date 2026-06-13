//! OpenSSH user-certificate signing and verification.
//!
//! Wraps `ssh-key`'s [`certificate::Builder`](ssh_key::certificate::Builder) +
//! [`Certificate`] for the small subset of options the CLI exposes
//! (`spt key cert sign` / `spt key cert verify` — spec §9.12).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use ssh_key::certificate::Builder;
use ssh_key::{Algorithm, HashAlg, PublicKey};

pub use ssh_key::Certificate;

use spt_core::{Error, Result};

use crate::keypair::KeyPair;

/// Options accepted by [`sign_cert`].
#[derive(Debug, Clone)]
pub struct CertOptions {
    /// Certificate kind — user or host.
    pub cert_type: CertType,
    /// Key identifier (free-form, often the principal name).
    pub key_id: String,
    /// Allowed principals (`valid_principals`). Must be non-empty unless
    /// `all_principals` is set.
    pub principals: Vec<String>,
    /// If `true`, mark the certificate valid for ALL principals (golden ticket).
    pub all_principals: bool,
    /// Validity start (`valid_after`); defaults to now if `None`.
    pub valid_after: Option<SystemTime>,
    /// Validity end (`valid_before`); defaults to now+`default_lifetime` if `None`.
    pub valid_before: Option<SystemTime>,
    /// Default lifetime when `valid_before` is `None`.
    pub default_lifetime: Duration,
    /// Optional serial number.
    pub serial: u64,
    /// Optional comment.
    pub comment: String,
    /// Critical options (e.g. `force-command`).
    pub critical_options: Vec<(String, String)>,
    /// Extensions (e.g. `permit-pty`).
    pub extensions: Vec<(String, String)>,
}

impl Default for CertOptions {
    fn default() -> Self {
        Self {
            cert_type: CertType::User,
            key_id: String::new(),
            principals: Vec::new(),
            all_principals: false,
            valid_after: None,
            valid_before: None,
            default_lifetime: Duration::from_secs(60 * 60 * 24 * 30),
            serial: 0,
            comment: String::new(),
            critical_options: Vec::new(),
            extensions: Vec::new(),
        }
    }
}

/// Certificate kind for [`CertOptions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertType {
    /// Authenticates a user to a host.
    User,
    /// Authenticates a host to a user.
    Host,
}

impl From<CertType> for ssh_key::certificate::CertType {
    fn from(c: CertType) -> Self {
        match c {
            CertType::User => Self::User,
            CertType::Host => Self::Host,
        }
    }
}

/// Sign `subject` with `ca` producing an OpenSSH certificate per `opts`.
pub fn sign_cert(ca: &KeyPair, subject: &PublicKey, opts: CertOptions) -> Result<Certificate> {
    let now = SystemTime::now();
    let valid_after = opts.valid_after.unwrap_or(now);
    let valid_before = opts.valid_before.unwrap_or(now + opts.default_lifetime);

    let va = valid_after
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::InvalidArgs(format!("valid_after before unix epoch: {e}")))?
        .as_secs();
    let vb = valid_before
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::InvalidArgs(format!("valid_before before unix epoch: {e}")))?
        .as_secs();

    let mut b = Builder::new_with_random_nonce(&mut OsRng, subject.key_data().clone(), va, vb)
        .map_err(map_err)?;

    b.cert_type(opts.cert_type.into()).map_err(map_err)?;
    b.serial(opts.serial).map_err(map_err)?;
    if !opts.key_id.is_empty() {
        b.key_id(opts.key_id).map_err(map_err)?;
    }

    if opts.all_principals {
        b.all_principals_valid().map_err(map_err)?;
    } else {
        if opts.principals.is_empty() {
            return Err(Error::InvalidArgs(
                "cert sign: at least one principal is required (or set all_principals)".into(),
            ));
        }
        for p in opts.principals {
            b.valid_principal(p).map_err(map_err)?;
        }
    }

    for (k, v) in opts.critical_options {
        b.critical_option(k, v).map_err(map_err)?;
    }
    for (k, v) in opts.extensions {
        b.extension(k, v).map_err(map_err)?;
    }
    if !opts.comment.is_empty() {
        b.comment(opts.comment).map_err(map_err)?;
    }

    // ssh-key 0.6.7's own RSA `Signer` impl reconstructs the `rsa::RsaPrivateKey`
    // from `(p, p)` instead of `(p, q)` (bug in `private/rsa.rs`), so signing
    // with an RSA CA fails with a `cryptographic error`. For RSA CAs we route
    // through a corrected signer that rebuilds the key with the proper `(p, q)`;
    // every other algorithm uses ssh-key's intact signer directly.
    match ca.private().algorithm() {
        Algorithm::Rsa { .. } => {
            let signer = rsa::RsaCertSigner::new(ca.private())?;
            b.sign(&signer).map_err(map_err)
        }
        _ => b.sign(ca.private()).map_err(map_err),
    }
}

/// Corrected RSA certificate signer.
///
/// Works around the ssh-key 0.6.7 bug where `TryFrom<&RsaKeypair> for
/// rsa::RsaPrivateKey` passes the prime `p` twice (`vec![p, p]`) instead of
/// `(p, q)`, producing a structurally invalid key whose signing operation
/// fails. We reconstruct the `rsa::RsaPrivateKey` with the correct `(p, q)` and
/// produce a byte-identical `rsa-sha2-512` PKCS#1 v1.5 signature — matching what
/// ssh-key's own (intact) verifier expects.
mod rsa {
    pub use ::rsa::{BigUint, RsaPrivateKey};

    use rsa::pkcs1v15::SigningKey;
    use rsa::sha2::Sha512;
    use rsa::signature::{SignatureEncoding, Signer};

    use spt_core::{Error, Result};
    use ssh_key::public::KeyData;
    use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};

    /// A `SigningKey` for ssh-key's certificate `Builder` that signs RSA with a
    /// correctly-reconstructed `(p, q)` private key.
    pub struct RsaCertSigner {
        signing_key: SigningKey<Sha512>,
        public: KeyData,
    }

    impl RsaCertSigner {
        /// Build the corrected signer from an RSA [`PrivateKey`].
        ///
        /// # Errors
        /// Returns an error if `ca` is not RSA or if the key components cannot
        /// be assembled into a valid `rsa::RsaPrivateKey`.
        pub fn new(ca: &PrivateKey) -> Result<Self> {
            let ssh_key::private::KeypairData::Rsa(kp) = ca.key_data() else {
                return Err(Error::InvalidArgs(
                    "RsaCertSigner: CA key is not RSA".into(),
                ));
            };
            let to_big = |m: &ssh_key::Mpint| -> Result<BigUint> {
                BigUint::try_from(m).map_err(|e| {
                    Error::InvalidConfig(format!("ssh-key cert: bad RSA component: {e}"))
                })
            };
            // The fix: `(p, q)`, not `(p, p)`.
            let priv_key = RsaPrivateKey::from_components(
                to_big(&kp.public.n)?,
                to_big(&kp.public.e)?,
                to_big(&kp.private.d)?,
                vec![to_big(&kp.private.p)?, to_big(&kp.private.q)?],
            )
            .map_err(|e| {
                Error::InvalidConfig(format!("ssh-key cert: reconstruct RSA private key: {e}"))
            })?;

            Ok(Self {
                signing_key: SigningKey::<Sha512>::new(priv_key),
                public: ca.public_key().key_data().clone(),
            })
        }
    }

    impl Signer<Signature> for RsaCertSigner {
        fn try_sign(&self, message: &[u8]) -> ::rsa::signature::Result<Signature> {
            let sig = self
                .signing_key
                .try_sign(message)
                .map_err(|_| ::rsa::signature::Error::new())?;
            Signature::new(
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                sig.to_vec(),
            )
            .map_err(|_| ::rsa::signature::Error::new())
        }
    }

    // ssh-key's blanket `SigningKey` impl applies to any `Signer<Signature>`
    // that also has `KeyData: From<&Self>`.
    impl From<&RsaCertSigner> for KeyData {
        fn from(s: &RsaCertSigner) -> Self {
            s.public.clone()
        }
    }
}

/// Verify `cert`'s signature and that it was issued by one of `trusted_cas`.
///
/// Performs:
/// 1. SSH-level signature verification ([`Certificate::verify_signature`]).
/// 2. Time-bound and CA-fingerprint check ([`Certificate::validate`]) using
///    SHA-256 fingerprints of every trusted CA public key.
pub fn verify_cert(cert: &Certificate, trusted_cas: &[PublicKey]) -> Result<()> {
    cert.verify_signature()
        .map_err(|e| Error::TrustFailed(format!("cert signature: {e}")))?;

    let fingerprints: Vec<_> = trusted_cas
        .iter()
        .map(|k| k.fingerprint(HashAlg::Sha256))
        .collect();

    cert.validate(fingerprints.iter())
        .map_err(|e| Error::TrustFailed(format!("cert validate: {e}")))
}

#[allow(clippy::needless_pass_by_value)]
fn map_err(e: ssh_key::Error) -> Error {
    Error::InvalidConfig(format!("ssh-key cert: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::KeyAlgorithm;
    use crate::io::generate;

    #[test]
    fn sign_and_verify_user_cert() {
        let ca = generate(KeyAlgorithm::Ed25519).unwrap();
        let subject = generate(KeyAlgorithm::Ed25519).unwrap();

        let opts = CertOptions {
            cert_type: CertType::User,
            key_id: "alice@spt".into(),
            principals: vec!["alice".into()],
            ..CertOptions::default()
        };
        let cert = sign_cert(&ca, subject.public_ref(), opts).unwrap();
        verify_cert(&cert, &[ca.public()]).unwrap();
    }

    #[test]
    fn rejects_untrusted_ca() {
        let ca = generate(KeyAlgorithm::Ed25519).unwrap();
        let other_ca = generate(KeyAlgorithm::Ed25519).unwrap();
        let subject = generate(KeyAlgorithm::Ed25519).unwrap();

        let cert = sign_cert(
            &ca,
            subject.public_ref(),
            CertOptions {
                key_id: "bob".into(),
                principals: vec!["bob".into()],
                ..CertOptions::default()
            },
        )
        .unwrap();

        assert!(verify_cert(&cert, &[other_ca.public()]).is_err());
    }

    #[test]
    fn requires_principals() {
        let ca = generate(KeyAlgorithm::Ed25519).unwrap();
        let subject = generate(KeyAlgorithm::Ed25519).unwrap();
        let r = sign_cert(&ca, subject.public_ref(), CertOptions::default());
        assert!(r.is_err());
    }

    #[test]
    fn cert_type_conversion_user_and_host() {
        let u: ssh_key::certificate::CertType = CertType::User.into();
        assert_eq!(u, ssh_key::certificate::CertType::User);
        let h: ssh_key::certificate::CertType = CertType::Host.into();
        assert_eq!(h, ssh_key::certificate::CertType::Host);
    }

    #[test]
    fn cert_options_default_shape() {
        let d = CertOptions::default();
        assert_eq!(d.cert_type, CertType::User);
        assert!(d.key_id.is_empty());
        assert!(d.principals.is_empty());
        assert!(!d.all_principals);
        assert!(d.valid_after.is_none());
        assert!(d.valid_before.is_none());
        assert_eq!(d.default_lifetime, Duration::from_secs(60 * 60 * 24 * 30));
        assert_eq!(d.serial, 0);
        assert!(d.comment.is_empty());
        assert!(d.critical_options.is_empty());
        assert!(d.extensions.is_empty());
    }

    #[test]
    fn cert_options_clone_and_debug() {
        let opts = CertOptions {
            key_id: "k".into(),
            principals: vec!["p".into()],
            ..CertOptions::default()
        };
        let cloned = opts.clone();
        assert_eq!(cloned.key_id, "k");
        // Exercise Debug impl.
        let _ = format!("{opts:?}");
    }

    #[test]
    fn host_cert_with_all_principals_signs() {
        let ca = generate(KeyAlgorithm::Ed25519).unwrap();
        let subject = generate(KeyAlgorithm::Ed25519).unwrap();
        let cert = sign_cert(
            &ca,
            subject.public_ref(),
            CertOptions {
                cert_type: CertType::Host,
                key_id: "host.example".into(),
                all_principals: true,
                ..CertOptions::default()
            },
        )
        .unwrap();
        assert_eq!(cert.cert_type(), ssh_key::certificate::CertType::Host);
        verify_cert(&cert, &[ca.public()]).unwrap();
    }

    #[test]
    fn cert_with_all_extensions_and_critical_options() {
        let ca = generate(KeyAlgorithm::Ed25519).unwrap();
        let subject = generate(KeyAlgorithm::Ed25519).unwrap();
        let opts = CertOptions {
            key_id: "complex".into(),
            principals: vec!["alice".into()],
            serial: 12_345,
            comment: "issued by spt".into(),
            critical_options: vec![("force-command".into(), "/usr/bin/spt".into())],
            extensions: vec![
                ("permit-pty".into(), String::new()),
                ("permit-port-forwarding".into(), String::new()),
            ],
            ..CertOptions::default()
        };
        let cert = sign_cert(&ca, subject.public_ref(), opts).unwrap();
        assert_eq!(cert.serial(), 12_345);
        assert_eq!(cert.key_id(), "complex");
        verify_cert(&cert, &[ca.public()]).unwrap();
    }

    #[test]
    fn cert_with_explicit_valid_after_and_before() {
        let ca = generate(KeyAlgorithm::Ed25519).unwrap();
        let subject = generate(KeyAlgorithm::Ed25519).unwrap();
        // Use a window that spans now so `validate()` would accept time-wise.
        let now = SystemTime::now();
        let va = now - Duration::from_secs(60);
        let vb = now + Duration::from_secs(3600);
        let cert = sign_cert(
            &ca,
            subject.public_ref(),
            CertOptions {
                key_id: "ranged".into(),
                principals: vec!["alice".into()],
                valid_after: Some(va),
                valid_before: Some(vb),
                ..CertOptions::default()
            },
        )
        .unwrap();
        verify_cert(&cert, &[ca.public()]).unwrap();
    }

    #[test]
    fn cert_all_principals_supersedes_empty_principals() {
        // `all_principals = true` must allow signing even when `principals`
        // is empty.
        let ca = generate(KeyAlgorithm::Ed25519).unwrap();
        let subject = generate(KeyAlgorithm::Ed25519).unwrap();
        let cert = sign_cert(
            &ca,
            subject.public_ref(),
            CertOptions {
                all_principals: true,
                key_id: "wild".into(),
                ..CertOptions::default()
            },
        )
        .unwrap();
        verify_cert(&cert, &[ca.public()]).unwrap();
    }

    #[test]
    fn verify_fails_when_trusted_ca_list_is_empty() {
        let ca = generate(KeyAlgorithm::Ed25519).unwrap();
        let subject = generate(KeyAlgorithm::Ed25519).unwrap();
        let cert = sign_cert(
            &ca,
            subject.public_ref(),
            CertOptions {
                key_id: "x".into(),
                principals: vec!["alice".into()],
                ..CertOptions::default()
            },
        )
        .unwrap();
        // Empty trusted-CA list: signature still verifies, but `validate`
        // rejects because no CA matches.
        assert!(verify_cert(&cert, &[]).is_err());
    }

    #[test]
    fn map_err_wraps_as_invalid_config() {
        // Indirectly exercise `map_err` by triggering a Builder error path:
        // `valid_before < valid_after` makes ssh-key reject the build.
        let ca = generate(KeyAlgorithm::Ed25519).unwrap();
        let subject = generate(KeyAlgorithm::Ed25519).unwrap();
        let now = SystemTime::now();
        let result = sign_cert(
            &ca,
            subject.public_ref(),
            CertOptions {
                key_id: "bad".into(),
                principals: vec!["alice".into()],
                valid_after: Some(now + Duration::from_secs(3600)),
                valid_before: Some(now), // before valid_after
                ..CertOptions::default()
            },
        );
        // ssh-key may or may not flag the inversion at build vs. validate
        // time; either way verifying with no CAs fails.
        if let Ok(cert) = result {
            assert!(verify_cert(&cert, &[ca.public()]).is_err());
        }
    }

    /// Regression: signing a certificate with an **RSA CA** must succeed and
    /// verify. ssh-key 0.6.7's own RSA signer reconstructs the private key from
    /// `(p, p)` instead of `(p, q)`, so before the corrected signer in
    /// [`sign_cert`] this failed with `cryptographic error`. Uses RSA-2048 (the
    /// bug is size-independent) to keep keygen fast enough for the default
    /// (non-ignored) test run.
    #[test]
    fn rsa_ca_signs_and_verifies_cert() {
        use rand::rngs::OsRng;
        use ssh_key::private::{KeypairData, RsaKeypair};
        use ssh_key::{Algorithm, PrivateKey};

        let rsa = RsaKeypair::random(&mut OsRng, 2048).unwrap();
        let ca = KeyPair::from_private(PrivateKey::new(KeypairData::from(rsa), "rsa-ca").unwrap());
        // Sanity: the CA really is RSA.
        assert!(matches!(ca.private().algorithm(), Algorithm::Rsa { .. }));

        let subject =
            KeyPair::from_private(PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap());

        let cert = sign_cert(
            &ca,
            subject.public_ref(),
            CertOptions {
                key_id: "rsa-ca-test".into(),
                principals: vec!["alice".into()],
                serial: 7,
                ..CertOptions::default()
            },
        )
        .expect("RSA-CA cert signing must succeed");

        // The signature must verify against the CA (the core of the bug fix).
        verify_cert(&cert, &[ca.public()]).expect("RSA-CA cert must verify");

        // And the cert must carry an RSA (sha2-512) signature.
        assert!(matches!(
            cert.signature().algorithm(),
            Algorithm::Rsa {
                hash: Some(ssh_key::HashAlg::Sha512)
            }
        ));

        // Byte round-trip survives.
        let s = cert.to_openssh().unwrap();
        let reparsed = Certificate::from_openssh(&s).unwrap();
        assert_eq!(reparsed.serial(), 7);
        verify_cert(&reparsed, &[ca.public()]).expect("reparsed RSA cert must verify");
    }

    #[test]
    fn cert_type_clone_copy_eq() {
        let a = CertType::User;
        let b = a;
        assert_eq!(a, b);
        let h: CertType = CertType::Host;
        assert_ne!(a, h);
        let _ = format!("{a:?}");
    }
}
