//! Key generation helpers for the `SPTENC1` envelope.
//!
//! These mint the key material the two asymmetric/symmetric modes consume:
//!
//! * [`generate_x25519`] — a fresh X25519 keypair (raw private scalar +
//!   derived public key), for the `kdf = "x25519"` sealed-recipient mode.
//! * [`generate_psk`] — 32 random bytes for the `kdf = "psk"` raw-symmetric
//!   mode (used directly as the AES-256-GCM body key).
//! * [`psk_id`] — a deterministic non-secret key label (first 8 hex of
//!   `SHA-256(psk)`) so operators can identify which PSK sealed a blob.
//!
//! All randomness comes from the OS CSPRNG via `rand::thread_rng`.

use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

/// Re-export the X25519 public-key newtype for callers minting keypairs.
pub use x25519_dalek::PublicKey as X25519PublicKey;

/// Generate a fresh X25519 keypair from the OS CSPRNG.
///
/// Returns `(private_scalar_bytes, public_key)` where the public key always
/// equals `X25519PublicKey::from(&StaticSecret::from(private_scalar_bytes))`.
/// The raw private scalar feeds [`crate::KeySource::X25519Secrets`] (unseal)
/// and the public key feeds [`crate::KeySource::X25519Recipients`] (seal).
#[must_use]
pub fn generate_x25519() -> ([u8; 32], X25519PublicKey) {
    let mut rng = rand::thread_rng();
    let mut scalar = [0u8; 32];
    rng.fill_bytes(&mut scalar);
    // StaticSecret::from clamps the scalar internally; the derived public
    // key is computed from the clamped form. We return the *raw* (unclamped)
    // bytes — re-deriving via StaticSecret::from reproduces the same public
    // key, so the round-trip is stable.
    let secret = StaticSecret::from(scalar);
    let public = X25519PublicKey::from(&secret);
    (scalar, public)
}

/// Generate a fresh 32-byte pre-shared key from the OS CSPRNG.
///
/// The bytes are used directly as the AES-256-GCM body key for the
/// `kdf = "psk"` mode — there is no KDF.
#[must_use]
pub fn generate_psk() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut psk = [0u8; 32];
    rng.fill_bytes(&mut psk);
    psk
}

/// Compute the non-secret PSK label: the first 8 hex characters of
/// `SHA-256(psk)`.
///
/// Deterministic for a given PSK; different PSKs almost always differ.
/// Carries no usable secret (a 4-byte truncated hash of a 32-byte key).
#[must_use]
pub fn psk_id(psk: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(psk);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(8);
    for byte in digest.iter().take(4) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
