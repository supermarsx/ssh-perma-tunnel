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
