//! Supported key algorithms for `spt key generate`.

use serde::{Deserialize, Serialize};
use spt_core::{Error, Result};

/// Key algorithm choices exposed to the CLI / config.
///
/// RSA modulus sizes are constrained to 3072 and 4096 bits — the spec rejects
/// shorter RSA moduli for new keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAlgorithm {
    /// Ed25519 — the recommended default.
    Ed25519,
    /// ECDSA over NIST P-256.
    EcdsaP256,
    /// RSA, 3072-bit modulus.
    Rsa3072,
    /// RSA, 4096-bit modulus.
    Rsa4096,
}

impl KeyAlgorithm {
    /// Translate to ssh-key's [`Algorithm`](ssh_key::Algorithm).
    pub fn to_ssh_key(self) -> ssh_key::Algorithm {
        match self {
            Self::Ed25519 => ssh_key::Algorithm::Ed25519,
            Self::EcdsaP256 => ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
            Self::Rsa3072 | Self::Rsa4096 => ssh_key::Algorithm::Rsa {
                hash: Some(ssh_key::HashAlg::Sha256),
            },
        }
    }

    /// Modulus size in bits when relevant; `None` for non-RSA algorithms.
    #[must_use]
    pub const fn rsa_bits(self) -> Option<usize> {
        match self {
            Self::Rsa3072 => Some(3072),
            Self::Rsa4096 => Some(4096),
            _ => None,
        }
    }

    /// Parse from CLI string form.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "ed25519" => Ok(Self::Ed25519),
            "ecdsa-p256" | "ecdsa" => Ok(Self::EcdsaP256),
            "rsa-3072" | "rsa3072" => Ok(Self::Rsa3072),
            "rsa-4096" | "rsa4096" | "rsa" => Ok(Self::Rsa4096),
            _ => Err(Error::InvalidArgs(format!(
                "unknown key algorithm `{s}`; want one of: ed25519, ecdsa-p256, rsa-3072, rsa-4096"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(
            KeyAlgorithm::parse("ed25519").unwrap(),
            KeyAlgorithm::Ed25519
        );
        assert_eq!(
            KeyAlgorithm::parse("rsa-4096").unwrap(),
            KeyAlgorithm::Rsa4096
        );
        assert!(KeyAlgorithm::parse("dsa").is_err());
    }

    #[test]
    fn rsa_bits() {
        assert_eq!(KeyAlgorithm::Rsa3072.rsa_bits(), Some(3072));
        assert_eq!(KeyAlgorithm::Ed25519.rsa_bits(), None);
    }
}
