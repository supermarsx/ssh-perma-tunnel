//! Shared helpers for the `stress` crate's integration tests.
//!
//! Three concerns live here:
//!
//! 1. [`probe`] — process-level resource snapshots (RSS in bytes, open
//!    handle/fd count). Implemented per-platform with no extra crates beyond
//!    what the workspace already carries.
//! 2. [`echo`] — a tiny in-process TCP echo server. Used by the burst test as
//!    a deterministic target for the libssh2 client loop, since the
//!    `RusshTestServer` shipped from `spt-ssh2/testing` only supports
//!    session-channel echo (not `direct-tcpip`).
//! 3. [`seed`] — deterministic seeding helpers (fixed const + `SPT_STRESS_SEED`
//!    env override → `ChaCha20Rng`).
//!
//! Nothing here is `#[cfg(test)]`-gated — these helpers must be visible to the
//! integration test binaries which compile as separate crates.

#![allow(clippy::missing_errors_doc)]

pub mod echo;
pub mod probe;
pub mod seed;
