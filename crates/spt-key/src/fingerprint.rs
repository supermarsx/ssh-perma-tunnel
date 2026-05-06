//! SHA-256 fingerprint computation matching OpenSSH's display format.

use ssh_key::{HashAlg, PublicKey};

/// Return the OpenSSH-style SHA-256 fingerprint string for `key`.
///
/// The format is `SHA256:<base64-no-padding>` exactly as printed by
/// `ssh-keygen -lf` and the IETF SSH fingerprint convention.
///
/// Internally delegates to [`ssh_key::PublicKey::fingerprint`].
#[must_use]
pub fn fingerprint_sha256(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use ssh_key::{Algorithm, PrivateKey};

    use super::*;

    #[test]
    fn format_is_sha256_colon_b64nopad() {
        let pk = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let fp = fingerprint_sha256(pk.public_key());
        assert!(fp.starts_with("SHA256:"));
        // Base64 NoPad — no '=' tail.
        assert!(!fp.ends_with('='));
        // Stable across calls.
        assert_eq!(fp, fingerprint_sha256(pk.public_key()));
    }

    #[test]
    fn different_keys_have_different_fingerprints() {
        let a = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let b = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        assert_ne!(
            fingerprint_sha256(a.public_key()),
            fingerprint_sha256(b.public_key())
        );
    }
}
