//! Pluggable obfuscation transports for SSH backends.
//!
//! This crate ships the public [`ObfsTransport`] trait, the on-wire [`ObfsConfig`]
//! enum (`obfs4`, `meek-http`, `ssh-over-websocket`, `ssh-over-shadowsocks`),
//! the [`transport_for`] dispatcher, and an [`AuditHook`] sink that the parent
//! binary attaches at construction so audit / metrics layers observe every
//! obfuscated connect attempt.
//!
//! ## Stub-where-needed precedent
//!
//! Several transports require crates that are not currently present in
//! `Cargo.lock`. Per the workspace policy that forbids `cargo update`, this
//! crate ships **contract-enforcing stubs** today (matching the t6-e7 / t6-e9
//! precedent) that:
//!
//! * accept the same parsed config the real implementation will,
//! * advance through the documented state machine far enough to surface
//!   shape-level errors (`Error::InvalidConfig` for bad arguments,
//!   `Error::UnsupportedPlatform` for unimplemented network paths),
//! * fire the [`AuditHook`] with the transport name,
//! * release every owned resource on drop.
//!
//! Bwire activates the real implementations once the upstream crates land in
//! `Cargo.lock`; the public surface is intended to be byte-stable across that
//! flip.
//!
//! ## Error-variant mapping
//!
//! The t6-e13 plan names `Error::ConfigInvalid` and `Error::UnsupportedFeature`.
//! Those variants do not exist in `spt-core::Error`; following the t6-e9
//! precedent for `UnsupportedBackend`, this crate maps them to the existing
//! `Error::InvalidConfig` and `Error::UnsupportedPlatform`. See the
//! `.orchestration/logs/t6-e13.md` log for the rationale.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod audit;
pub mod config;
pub mod error;
pub mod transport;

pub mod obfs4;
pub mod meek;
pub mod websocket;
pub mod shadowsocks;

pub use audit::{AuditHook, NoopAuditHook};
pub use config::{ObfsConfig, SsMethod};
pub use error::ObfsError;
pub use transport::{AsyncReadWrite, ObfsTransport};

use std::sync::Arc;

use spt_core::{Error, Result};

/// Construct a boxed [`ObfsTransport`] for the given configuration.
///
/// Returns `Error::InvalidConfig` (the variant the plan refers to as
/// `ConfigInvalid`) when the supplied config is rejected at construction time.
/// Returns `Error::UnsupportedPlatform` (`UnsupportedFeature`) when the
/// corresponding upstream crate is not present in the lockfile and the stub
/// transport refuses to surface an unfaithful wire path.
///
/// The constructed transport carries a [`NoopAuditHook`]; call
/// [`transport_for_with_audit`] to plug a real audit sink in.
pub fn transport_for(cfg: &ObfsConfig) -> Result<Box<dyn ObfsTransport>> {
    transport_for_with_audit(cfg, Arc::new(NoopAuditHook))
}

/// Like [`transport_for`] but accepts a caller-supplied audit hook.
///
/// The hook fires from inside [`ObfsTransport::connect`] with the transport
/// name verbatim so that downstream subscribers (Bwire's audit layer; the
/// metrics pipeline) can record per-transport selection counts and per-attempt
/// telemetry.
pub fn transport_for_with_audit(
    cfg: &ObfsConfig,
    audit: Arc<dyn AuditHook>,
) -> Result<Box<dyn ObfsTransport>> {
    cfg.validate().map_err(|e| Error::InvalidConfig(e.to_string()))?;
    match cfg {
        ObfsConfig::Obfs4 { .. } => Ok(Box::new(obfs4::Obfs4Transport::new(cfg.clone(), audit)?)),
        ObfsConfig::MeekHttp { .. } => Ok(Box::new(meek::MeekHttpTransport::new(cfg.clone(), audit)?)),
        ObfsConfig::Websocket { .. } => Ok(Box::new(websocket::WebsocketTransport::new(cfg.clone(), audit)?)),
        ObfsConfig::Shadowsocks { .. } => Ok(Box::new(shadowsocks::ShadowsocksTransport::new(cfg.clone(), audit)?)),
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod testing {
    //! Test fixtures exposed when the `testing` feature is enabled.
    pub use crate::audit::MockAuditHook;
}
