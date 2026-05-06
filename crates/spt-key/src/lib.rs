//! SSH key generation, fingerprinting, and OpenSSH user-certificate handling.
//!
//! This crate is the single place in the workspace that manipulates SSH key
//! material directly. Every other crate that needs to consume a key (notably
//! `spt-ssh2` for transport and `spt-cli` for `key generate` / `key inspect`)
//! depends on the types here.
//!
//! Backed by [`ssh-key`](https://docs.rs/ssh-key) — we use ssh-key directly
//! (rather than `russh-keys`) because it exposes the OpenSSH PEM encoder we
//! need for `save_encrypted` (spec §9.12: encrypted-at-rest output).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod algorithm;
pub mod cert;
pub mod fingerprint;
pub mod io;
pub mod keypair;

pub use algorithm::KeyAlgorithm;
pub use cert::{sign_cert, verify_cert, CertOptions, Certificate};
pub use fingerprint::fingerprint_sha256;
pub use io::{change_passphrase, generate, load, save_encrypted};
pub use keypair::KeyPair;

// Re-exports of underlying types for downstream crates.
pub use ssh_key::{PrivateKey, PublicKey};
