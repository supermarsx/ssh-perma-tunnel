//! Authentication method types and validation for spt — protocol-agnostic.
//!
//! This crate defines the [`AuthMethod`] enum covering every method modeled by
//! spec §9.12 (SSH2 public key / agent / password / keyboard-interactive /
//! certificate; SSH3 bearer / basic / OIDC). It is **transport-free**: no
//! socket I/O, no SSH handshake — just type-level modelling and per-method
//! validation suitable for `spt config validate` and the CLI preflight checks.
//!
//! Secret material is referenced through [`SecretRef`], a thin newtype around
//! the spec's `secret://ns/name`, `env:NAME`, and `file:///path` reference
//! grammar. Resolution lives in `spt-secrets`; this crate only checks shape.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod kbi;
pub mod method;
pub mod secret_ref;
pub mod validate;

pub use kbi::KbiAnswer;
pub use method::{AuthConfig, AuthMethod};
pub use secret_ref::{SecretRef, SecretRefError};
pub use validate::validate;
