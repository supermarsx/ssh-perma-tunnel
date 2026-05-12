//! Test facilities for crates that consume [`KeyPair`].
//!
//! Activated via `--features testing`. Helpers here are deterministic by
//! default — every call with the same `(seed, algorithm)` returns a key with
//! an identical SHA-256 fingerprint, so downstream tests do not flake.

use std::path::PathBuf;

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use ssh_key::PrivateKey;
use tempfile::TempDir;

use spt_core::{Error, Result};

use crate::algorithm::KeyAlgorithm;
use crate::io::save_encrypted;
use crate::keypair::KeyPair;

/// Generate a fully deterministic [`KeyPair`] from `(seed, alg)`.
///
/// Backed by `ChaCha20Rng::seed_from_u64`. `ssh-key 0.6` consumes any
/// `CryptoRng + RngCore` (`rand_core` 0.6), which `ChaCha20Rng` satisfies — no
/// OS-RNG fallback is required for any of [`KeyAlgorithm`]'s variants.
///
/// ```
/// # #[cfg(feature = "testing")] fn _doc() -> spt_core::Result<()> {
/// use spt_key::testing::deterministic_keypair;
/// use spt_key::{KeyAlgorithm, fingerprint_sha256};
/// let a = deterministic_keypair(7, KeyAlgorithm::Ed25519)?;
/// let b = deterministic_keypair(7, KeyAlgorithm::Ed25519)?;
/// assert_eq!(fingerprint_sha256(a.public_ref()), fingerprint_sha256(b.public_ref()));
/// # Ok(()) }
/// ```
pub fn deterministic_keypair(seed: u64, alg: KeyAlgorithm) -> Result<KeyPair> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let private = match alg {
        KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
            let bits = alg.rsa_bits().unwrap_or(3072);
            let rsa = ssh_key::private::RsaKeypair::random(&mut rng, bits).map_err(map_err)?;
            let kd = ssh_key::private::KeypairData::from(rsa);
            PrivateKey::new(kd, "spt-test").map_err(map_err)?
        }
        _ => PrivateKey::random(&mut rng, alg.to_ssh_key()).map_err(map_err)?,
    };
    Ok(KeyPair::from_private(private))
}

#[allow(clippy::needless_pass_by_value)]
fn map_err(e: ssh_key::Error) -> Error {
    Error::InvalidConfig(format!("ssh-key (testing): {e}"))
}

/// Pre-built key fixtures with stable fingerprints across test runs.
///
/// All helpers delegate to [`deterministic_keypair`] with seed `42` and the
/// named algorithm. Prefer [`fixtures::ed25519_kp`] for the default — RSA
/// generation (even at 3072 bits) is slow and best avoided unless the test
/// specifically exercises RSA behaviour.
pub mod fixtures {
    use super::{deterministic_keypair, KeyAlgorithm, KeyPair, Result};

    /// Deterministic Ed25519 key pair (seed 42).
    ///
    /// ```
    /// # #[cfg(feature = "testing")] fn _doc() -> spt_core::Result<()> {
    /// let kp = spt_key::testing::fixtures::ed25519_kp()?;
    /// assert_eq!(kp.algorithm(), Some(spt_key::KeyAlgorithm::Ed25519));
    /// # Ok(()) }
    /// ```
    pub fn ed25519_kp() -> Result<KeyPair> {
        deterministic_keypair(42, KeyAlgorithm::Ed25519)
    }

    /// Deterministic ECDSA-P256 key pair (seed 42).
    ///
    /// ```
    /// # #[cfg(feature = "testing")] fn _doc() -> spt_core::Result<()> {
    /// let kp = spt_key::testing::fixtures::p256_kp()?;
    /// assert_eq!(kp.algorithm(), Some(spt_key::KeyAlgorithm::EcdsaP256));
    /// # Ok(()) }
    /// ```
    pub fn p256_kp() -> Result<KeyPair> {
        deterministic_keypair(42, KeyAlgorithm::EcdsaP256)
    }

    /// Deterministic RSA-3072 key pair (seed 42).
    ///
    /// **Slow** — RSA-3072 generation can take multiple seconds even with a
    /// seeded RNG. Tests that don't specifically need RSA should use
    /// [`ed25519_kp`].
    ///
    /// ```no_run
    /// # #[cfg(feature = "testing")] fn _doc() -> spt_core::Result<()> {
    /// let _kp = spt_key::testing::fixtures::rsa3072_kp()?;
    /// # Ok(()) }
    /// ```
    pub fn rsa3072_kp() -> Result<KeyPair> {
        deterministic_keypair(42, KeyAlgorithm::Rsa3072)
    }
}

/// Save `kp` (optionally encrypted) into a fresh [`TempDir`] and return both
/// the directory handle (drop = cleanup) and the path of the written key.
///
/// ```
/// # #[cfg(feature = "testing")] fn _doc() -> spt_core::Result<()> {
/// use spt_key::testing::{fixtures, temp_key_file};
/// let kp = fixtures::ed25519_kp()?;
/// let (_dir, path) = temp_key_file(&kp, Some("hunter2"))?;
/// assert!(path.exists());
/// # Ok(()) }
/// ```
pub fn temp_key_file(kp: &KeyPair, passphrase: Option<&str>) -> Result<(TempDir, PathBuf)> {
    let dir =
        tempfile::tempdir().map_err(|e| Error::RuntimeFailure(format!("create tempdir: {e}")))?;
    let path = dir.path().join("id_test");
    save_encrypted(kp, &path, passphrase)?;
    Ok((dir, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::fingerprint_sha256;

    #[test]
    fn ed25519_seed_42_is_stable() {
        let a = deterministic_keypair(42, KeyAlgorithm::Ed25519).unwrap();
        let b = deterministic_keypair(42, KeyAlgorithm::Ed25519).unwrap();
        assert_eq!(
            fingerprint_sha256(a.public_ref()),
            fingerprint_sha256(b.public_ref())
        );
    }

    #[test]
    fn different_seeds_differ() {
        let a = deterministic_keypair(1, KeyAlgorithm::Ed25519).unwrap();
        let b = deterministic_keypair(2, KeyAlgorithm::Ed25519).unwrap();
        assert_ne!(
            fingerprint_sha256(a.public_ref()),
            fingerprint_sha256(b.public_ref())
        );
    }

    #[test]
    fn p256_deterministic() {
        let a = fixtures::p256_kp().unwrap();
        let b = fixtures::p256_kp().unwrap();
        assert_eq!(
            fingerprint_sha256(a.public_ref()),
            fingerprint_sha256(b.public_ref())
        );
    }

    #[test]
    fn temp_key_file_round_trip() {
        let kp = fixtures::ed25519_kp().unwrap();
        let (dir, path) = temp_key_file(&kp, None).unwrap();
        assert!(path.starts_with(dir.path()));
        let loaded = crate::io::load(&path, None).unwrap();
        assert_eq!(
            fingerprint_sha256(loaded.public_ref()),
            fingerprint_sha256(kp.public_ref())
        );
    }
}
