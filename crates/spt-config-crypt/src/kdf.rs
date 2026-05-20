//! Key-derivation primitives.
//!
//! Three KDFs are supported:
//!
//! 1. [`derive_argon2id`] — passphrase → 32-byte body key via Argon2id with
//!    the parameters carried in [`crate::envelope::Argon2idParams`].
//! 2. [`hkdf_sha256`] — vault-master + salt → 32-byte body key
//!    (HKDF-SHA-256 extract+expand fused via [`sha2::Sha256`]/[`hmac::Hmac`]
//!    — we implement extract+expand inline to avoid pulling another crate).
//! 3. [`x25519_wrap_unwrap`] — X25519 ECDH + HKDF-SHA-256 → per-recipient
//!    32-byte AES-GCM key used to wrap/unwrap the body key.

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use spt_core::Error;
use zeroize::Zeroizing;

use crate::envelope::Argon2idParams;

/// Derive a 32-byte key from a passphrase via Argon2id.
pub(crate) fn derive_argon2id(
    passphrase: &[u8],
    params: &Argon2idParams,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| Error::SecretCryptoFailed(format!("argon2id params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let salt = params.salt()?;
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, &salt, out.as_mut())
        .map_err(|e| Error::SecretCryptoFailed(format!("argon2id derive: {e}")))?;
    Ok(out)
}

/// HKDF-SHA-256 extract+expand producing exactly 32 bytes.
///
/// Implemented inline to avoid a separate `hkdf` crate. SHA-256 block size
/// is 64; output length 32 (one HMAC block); info is appended verbatim.
pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    // HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
    let prk = hmac_sha256(salt, ikm);
    // HKDF-Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
    let mut input = Vec::with_capacity(info.len() + 1);
    input.extend_from_slice(info);
    input.push(0x01);
    let t1 = hmac_sha256(&prk, &input);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&t1);
    out
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    // Normalize key to BLOCK bytes (hashed or zero-padded).
    let mut k_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        let d = h.finalize();
        k_block[..32].copy_from_slice(&d);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_d = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_d);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    #[test]
    fn argon2id_deterministic_for_fixed_salt() {
        let params = Argon2idParams {
            memory_kib: 8 * 1024, // keep tests fast — 8 MiB
            iterations: 1,
            parallelism: 1,
            salt_b64: B64.encode([7u8; 16]),
        };
        let a = derive_argon2id(b"hunter2", &params).unwrap();
        let b = derive_argon2id(b"hunter2", &params).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
        let c = derive_argon2id(b"hunter3", &params).unwrap();
        assert_ne!(a.as_ref(), c.as_ref());
    }

    #[test]
    fn hkdf_is_deterministic_and_keyed() {
        let a = hkdf_sha256(b"ikm", b"salt", b"info");
        let b = hkdf_sha256(b"ikm", b"salt", b"info");
        assert_eq!(a.as_ref(), b.as_ref());
        let c = hkdf_sha256(b"ikm", b"salt", b"info2");
        assert_ne!(a.as_ref(), c.as_ref());
        let d = hkdf_sha256(b"ikm2", b"salt", b"info");
        assert_ne!(a.as_ref(), d.as_ref());
    }
}
