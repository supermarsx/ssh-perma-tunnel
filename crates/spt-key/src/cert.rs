//! OpenSSH user-certificate signing and verification.
//!
//! Wraps `ssh-key`'s [`certificate::Builder`](ssh_key::certificate::Builder) +
//! [`Certificate`] for the small subset of options the CLI exposes
//! (`spt key cert sign` / `spt key cert verify` — spec §9.12).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use ssh_key::certificate::Builder;
use ssh_key::{HashAlg, PublicKey};

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

    b.sign(ca.private()).map_err(map_err)
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
}
