//! Host trust primitives: OpenSSH `known_hosts`, SHA-256 host pinning, and
//! TLS public-key (SPKI) pinning.
//!
//! Spec references: §9.13 (trust), §11 (per-attempt verification), §10.5
//! (split-horizon DNS does not bypass trust). All verification routines are
//! pure functions — no I/O beyond reading/writing the configured files —
//! and constant-time where they compare secret-equivalent material.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod known_hosts;
pub mod sha256_pin;
pub mod tls_pin;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use known_hosts::{KnownHosts, KnownHostsResult};
pub use sha256_pin::Sha256HostPin;
pub use tls_pin::TlsPin;
