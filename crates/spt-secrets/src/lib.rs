//! Secret resolver, vault, and OS keychain integration for `spt`.
//!
//! This crate provides the secret-management subsystem mandated by spec
//! §14.6:
//!
//! * [`SecretRef`] — typed `secret://ns/name` reference with strict
//!   validation. Reject any reference containing characters outside the
//!   alphanumeric / `_-.` set in either the namespace or the name.
//! * [`SecretBackend`] — pluggable backend trait. Implementations:
//!   [`KeychainBackend`] (OS keychain via the `keyring` crate),
//!   [`VaultBackend`] (file-backed AES-256-GCM + Argon2id vault),
//!   [`EnvBackend`] (process environment), and [`FileBackend`]
//!   (mode-checked file paths).
//! * [`Resolver`] — composes backends in priority order and returns the
//!   first hit; missing references map to
//!   [`spt_core::Error::SecretUnavailable`].
//! * [`mlock`] — best-effort memory locking helpers.
//! * [`doctor`] — per-backend health reports aggregated into
//!   [`SecretsDoctor`].
//!
//! Returned secret bytes are wrapped in [`SecretBytes`], a
//! `secrecy::SecretBox` over a `zeroize::Zeroizing<Vec<u8>>`, ensuring the
//! buffer is zeroed on drop and not exposed by `Debug`.

// `unsafe` is permitted only in `mlock` for OS-level memory locking
// syscalls. Everywhere else, deny unsafe via the module-level attribute.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod backend;
pub mod doctor;
pub mod env;
pub mod file;
pub mod keychain;
pub mod mlock;
pub mod reference;
pub mod resolver;
pub mod vault;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use backend::{BackendDoctor, BackendKind, BackendStatus, SecretBackend, SecretBytes};
pub use doctor::SecretsDoctor;
pub use env::EnvBackend;
pub use file::FileBackend;
pub use keychain::KeychainBackend;
pub use reference::{ReferenceError, SecretRef};
pub use resolver::Resolver;
pub use vault::{VaultBackend, VaultMeta};
