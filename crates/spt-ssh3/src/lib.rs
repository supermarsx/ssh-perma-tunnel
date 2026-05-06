//! SSH3 backend for spt built on QUIC, rustls, and HTTP/3.
//!
//! # Status: experimental stub
//!
//! This crate ships in **stub mode** for the v1 milestone. It provides:
//!
//! * The full public type surface — [`Ssh3Protocol`], [`Ssh3Config`],
//!   [`Ssh3Frame`], [`Ssh3Settings`], [`Ssh3StreamKind`] — so downstream code
//!   (`spt-supervisor`, `spt-bin`) can compile and reason about SSH3 today.
//! * A working [`TunnelProtocol`] implementation whose [`Ssh3Protocol::connect`]
//!   always returns [`spt_core::Error::UnsupportedPlatform`] with the reason
//!   `"SSH3 backend disabled at build: …"`.
//! * **The mandatory `tracing::warn!` experimental notice** on every
//!   `connect()` call (and on every settings emit), unless the operator sets
//!   `acknowledge_experimental = true` on the [`Ssh3Config`]. This satisfies
//!   the spec §4.2 requirement that SSH3 startup/`validate`/`doctor`/`tunnel
//!   run` surface experimental status.
//!
//! See [`crates/spt-ssh3/README.md`](https://github.com/Mariana/ssh-perma-tunnel/blob/main/crates/spt-ssh3/README.md)
//! for the full rationale and the path to a non-stub implementation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod frame;
pub mod protocol;

pub use config::{Ssh3AuthExtras, Ssh3Config, Ssh3TlsConfig};
pub use frame::{Ssh3Frame, Ssh3FrameKind, Ssh3Settings, Ssh3StreamKind};
pub use protocol::{Ssh3Protocol, EXPERIMENTAL_WARNING, STUB_BLOCKER_REASON};
