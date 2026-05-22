//! Sealed-config envelope for `spt`.
//!
//! This crate implements the `SPTENC1` on-disk format used to ship
//! encrypted (and optionally signed) configuration files. The envelope is
//! AEAD-protected with AES-256-GCM and supports three key sources:
//!
//! * **Passphrase** — Argon2id (m=64 MiB, t=3, p=4) derives a 32-byte key.
//! * **Vault master** — a 32-byte key resolved out-of-band (typically from
//!   the OS keychain via [`spt_secrets::VaultBackend`]).
//! * **X25519 recipients** — one or more X25519 public keys; the body key
//!   is randomly generated and sealed per recipient via X25519 ECDH +
//!   HKDF-SHA-256 (KEM-style). Any recipient holding a matching private
//!   key can unseal.
//!
//! An optional Ed25519 [`signature`](sign) covers the magic + meta + body
//! bytes — allowing publishers to prove provenance independently of the
//! sealing key.
//!
//! Public surface mirrors the t5-e5 contract:
//!
//! * [`seal`] — encrypt + frame.
//! * [`unseal`] — decrypt + return a zeroizing secret buffer.
//! * [`sign`] / [`verify`] — Ed25519 detached signature.
//! * [`peek_meta`] — read `[meta]` without unsealing.
//! * [`is_sealed`] — fast magic-check.
//!
//! # File layout
//!
//! ```text
//! offset  bytes        contents
//! ------  -----------  -----------------------------------------------
//! 0       8            magic = b"SPTENC1\n"
//! 8       4            meta_len  (big-endian u32)
//! 12      meta_len     meta-toml (UTF-8 TOML with single `[meta]` table)
//! ..      4            body_len  (big-endian u32)
//! ..      body_len     body-toml (UTF-8 TOML with single `[body]` table)
//! ..      4            sig_len   (big-endian u32, optional — absent if EOF)
//! ..      sig_len      sig-toml  (UTF-8 TOML with single `[signature]`)
//! ```
//!
//! **AAD** for the body AEAD = `magic || meta_toml_bytes` (the exact bytes
//! as on disk, so canonicalization issues never bite the verifier).
//!
//! **Signature input** = `magic || meta_toml_bytes || body_toml_bytes`.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

mod envelope;
mod kdf;
mod sealing;
mod signing;

pub use envelope::{Meta, MAGIC};
pub use sealing::{
    is_sealed, peek_meta, seal, unseal, KeySource, Passphrase, SecretSlice, X25519PublicKey,
};
pub use signing::{sign, verify, SigningKey, VerifyingKey};

#[cfg(test)]
mod tests;
