//! [`KeyPair`] — owned private+public key material.
//!
//! The struct intentionally keeps the underlying `ssh_key::PrivateKey`
//! accessible (rather than fully sealing it) because callers in `spt-ssh2`
//! must hand the raw key to libssh2. Treat instances as secret material —
//! never log them, never serialize them, and prefer dropping early.

use ssh_key::{PrivateKey, PublicKey};

use crate::algorithm::KeyAlgorithm;

/// A parsed SSH key pair (private + derived public).
#[derive(Debug, Clone)]
pub struct KeyPair {
    private: PrivateKey,
}

impl KeyPair {
    /// Wrap an existing `ssh_key::PrivateKey`.
    #[must_use]
    pub fn from_private(private: PrivateKey) -> Self {
        Self { private }
    }

    /// Borrow the underlying private key.
    #[must_use]
    pub fn private(&self) -> &PrivateKey {
        &self.private
    }

    /// Mutable access to the underlying private key (used by passphrase ops).
    pub fn private_mut(&mut self) -> &mut PrivateKey {
        &mut self.private
    }

    /// Cloned public-key half.
    #[must_use]
    pub fn public(&self) -> PublicKey {
        self.private.public_key().clone()
    }

    /// Borrow public key by reference.
    #[must_use]
    pub fn public_ref(&self) -> &PublicKey {
        self.private.public_key()
    }

    /// Best-effort algorithm classification — note that `Rsa{3072,4096}` map
    /// to a single `Rsa` `ssh_key::Algorithm`, so RSA bit width must be
    /// derived from the key data itself if needed.
    #[must_use]
    pub fn algorithm(&self) -> Option<KeyAlgorithm> {
        match self.private.algorithm() {
            ssh_key::Algorithm::Ed25519 => Some(KeyAlgorithm::Ed25519),
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            } => Some(KeyAlgorithm::EcdsaP256),
            ssh_key::Algorithm::Rsa { .. } => match self.private.key_data() {
                ssh_key::private::KeypairData::Rsa(rsa) => {
                    let bits = rsa.public.n.as_bytes().len() * 8;
                    if bits >= 4090 {
                        Some(KeyAlgorithm::Rsa4096)
                    } else if bits >= 3060 {
                        Some(KeyAlgorithm::Rsa3072)
                    } else {
                        None
                    }
                }
                _ => None,
            },
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::KeyAlgorithm;
    use crate::io::generate;
    use rand::rngs::OsRng;
    use ssh_key::Algorithm;

    fn ed25519_pk() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn from_private_and_borrows() {
        let pk = ed25519_pk();
        let public_fp = pk.public_key().fingerprint(ssh_key::HashAlg::Sha256);
        let kp = KeyPair::from_private(pk);

        // Immutable borrow returns the same key.
        assert_eq!(
            kp.private().public_key().fingerprint(ssh_key::HashAlg::Sha256),
            public_fp
        );

        // public_ref() returns the same key data as public() (clone).
        let p_ref = kp.public_ref();
        let p_clone = kp.public();
        assert_eq!(
            p_ref.fingerprint(ssh_key::HashAlg::Sha256),
            p_clone.fingerprint(ssh_key::HashAlg::Sha256)
        );
    }

    #[test]
    fn private_mut_allows_in_place_mutation() {
        let pk = ed25519_pk();
        let mut kp = KeyPair::from_private(pk);
        // Set a comment via private_mut() — proves we got &mut and that the
        // mutation sticks.
        kp.private_mut().set_comment("changed");
        assert_eq!(kp.private().comment(), "changed");
    }

    #[test]
    fn algorithm_classifies_ed25519() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        assert_eq!(kp.algorithm(), Some(KeyAlgorithm::Ed25519));
    }

    #[test]
    fn algorithm_classifies_ecdsa_p256() {
        let kp = generate(KeyAlgorithm::EcdsaP256).unwrap();
        assert_eq!(kp.algorithm(), Some(KeyAlgorithm::EcdsaP256));
    }

    /// Hand-build an RSA-2048 key — `generate()` rejects sub-3072 sizes, so we
    /// poke `ssh_key` directly to exercise the "RSA but bits below 3060" arm
    /// of [`KeyPair::algorithm`] (the `None` branch under `Rsa { .. }`).
    #[test]
    fn algorithm_rsa_below_3060_is_none() {
        let rsa = ssh_key::private::RsaKeypair::random(&mut OsRng, 2048).unwrap();
        let kd = ssh_key::private::KeypairData::from(rsa);
        let priv_key = PrivateKey::new(kd, "rsa-2048-test").unwrap();
        let kp = KeyPair::from_private(priv_key);
        assert_eq!(kp.algorithm(), None);
    }

    /// Construct an RSA-3072 key and confirm the 3060+ bit-width branch
    /// returns `Rsa3072`. Marked `#[ignore]` because keygen is slow.
    #[test]
    #[ignore = "RSA-3072 keygen is slow (~5s+)"]
    fn algorithm_rsa_3072_branch() {
        let kp = generate(KeyAlgorithm::Rsa3072).unwrap();
        assert_eq!(kp.algorithm(), Some(KeyAlgorithm::Rsa3072));
    }

    /// 4096-bit RSA must report `Rsa4096`. `#[ignore]` for the same reason.
    #[test]
    #[ignore = "RSA-4096 keygen is very slow"]
    fn algorithm_rsa_4096_branch() {
        let kp = generate(KeyAlgorithm::Rsa4096).unwrap();
        assert_eq!(kp.algorithm(), Some(KeyAlgorithm::Rsa4096));
    }

    #[test]
    fn debug_does_not_panic() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        // Just exercise the derived `Debug` impl — output content isn't
        // asserted because ssh-key's Debug for PrivateKey is opaque.
        let s = format!("{kp:?}");
        assert!(!s.is_empty());
    }

    #[test]
    fn clone_preserves_fingerprint() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let cloned = kp.clone();
        assert_eq!(
            kp.public_ref().fingerprint(ssh_key::HashAlg::Sha256),
            cloned.public_ref().fingerprint(ssh_key::HashAlg::Sha256)
        );
    }
}
