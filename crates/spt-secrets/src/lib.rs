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
//! * [`secret_alloc`] — non-swappable, zero-on-drop allocations
//!   ([`SecretAlloc`], [`SecretSlice`], typed [`MemfdSecretBox<T>`]). Backed
//!   by `memfd_secret(2)` on Linux ≥5.14 with `CONFIG_SECRETMEM=y`,
//!   otherwise by `mlock`/`VirtualLock`-ed heap.
//! * [`doctor`] — per-backend health reports aggregated into
//!   [`SecretsDoctor`].
//!
//! Returned secret bytes are wrapped in [`SecretBytes`], a
//! `secrecy::SecretBox` over a `zeroize::Zeroizing<Vec<u8>>`, ensuring the
//! buffer is zeroed on drop and not exposed by `Debug`.

// `unsafe` is permitted in `mlock` and `secret_alloc` for OS-level memory
// locking and `memfd_secret`/`mmap` FFI. Every `unsafe` block carries a
// `// SAFETY:` comment.
#![warn(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod backend;
pub mod doctor;
pub mod env;
pub mod file;
pub mod keychain;
pub mod mem_protection;
pub mod mlock;
pub mod passphrase;
pub mod portable;
pub mod reference;
pub mod resolver;
pub mod secret_alloc;
pub mod vault;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use backend::{BackendDoctor, BackendKind, BackendStatus, SecretBackend, SecretBytes};
pub use doctor::SecretsDoctor;
pub use env::EnvBackend;
pub use file::FileBackend;
pub use keychain::KeychainBackend;
pub use mem_protection::{
    apply as apply_memory_protection, apply_once as apply_memory_protection_once, MemoryProtection,
    ProtectionOutcome,
};
pub use passphrase::read_passphrase;
pub use portable::{
    keychain_allowed, set_portable_mode, vault_passphrase_from_file, PortableVaultLayout,
};
pub use reference::{ReferenceError, SecretRef};
pub use resolver::Resolver;
pub use secret_alloc::{MemfdSecretBox, SecretAlloc, SecretSlice};
pub use vault::{VaultBackend, VaultMeta};
