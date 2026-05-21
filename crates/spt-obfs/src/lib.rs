//! Pluggable obfuscation transports for SSH backends.
//!
//! This crate ships the public [`ObfsTransport`] trait, the on-wire
//! [`ObfsConfig`] enum (`obfs4`, `meek-http`, `ssh-over-websocket`,
//! `ssh-over-shadowsocks`), the [`transport_for`] dispatcher, and an
//! [`AuditHook`] sink that the parent binary attaches at construction so
//! audit / metrics layers observe every obfuscated connect attempt.
//!
//! ## Implementations
//!
//! Each transport ships a real wire path as of t7-A4:
//!
//! * `obfs4` — hand-rolled NTOR-style handshake (X25519 + HMAC-SHA256
//!   KDF) and ChaCha20-Poly1305 frame layer. Documented as the "obfs4
//!   client subset" — see [`obfs4`] and `docs/obfuscation.md` for the
//!   wire-incompatibility caveats vs. obfs4proxy.
//! * `meek-http` — HTTPS POST/POST chunked tunnel over `reqwest`, with
//!   the standard Host-vs-SNI domain-fronting split.
//! * `ssh-over-websocket` — RFC 6455 upgrade via `tokio-tungstenite
//!   0.24`, advertising the `ssh` subprotocol.
//! * `ssh-over-shadowsocks` — AEAD-2022 framing with the BLAKE3
//!   `derive_key` KDF (`"shadowsocks 2022 session subkey"` context),
//!   AES-128/256-GCM and ChaCha20-Poly1305 ciphers, sliding-window
//!   replay protection.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod audit;
pub mod config;
pub mod error;
pub mod transport;

pub mod meek;
pub mod obfs4;
pub mod shadowsocks;
pub mod websocket;

pub use audit::{AuditHook, NoopAuditHook};
pub use config::{ObfsConfig, SsMethod};
pub use error::ObfsError;
pub use transport::{AsyncReadWrite, ObfsTransport};

use std::sync::Arc;

use spt_core::{Error, Result};

/// Construct a boxed [`ObfsTransport`] for the given configuration.
///
/// Returns [`Error::InvalidConfig`] when the supplied config is rejected
/// at construction time.
///
/// The constructed transport carries a [`NoopAuditHook`]; call
/// [`transport_for_with_audit`] to plug a real audit sink in.
pub fn transport_for(cfg: &ObfsConfig) -> Result<Box<dyn ObfsTransport>> {
    transport_for_with_audit(cfg, Arc::new(NoopAuditHook))
}

/// Like [`transport_for`] but accepts a caller-supplied audit hook.
///
/// The hook fires from inside [`ObfsTransport::connect`] with the
/// transport name verbatim so that downstream subscribers (the audit
/// layer; the metrics pipeline) can record per-transport selection
/// counts and per-attempt telemetry.
pub fn transport_for_with_audit(
    cfg: &ObfsConfig,
    audit: Arc<dyn AuditHook>,
) -> Result<Box<dyn ObfsTransport>> {
    cfg.validate().map_err(|e| Error::InvalidConfig(e.to_string()))?;
    match cfg {
        ObfsConfig::Obfs4 { .. } => Ok(Box::new(obfs4::Obfs4Transport::new(cfg.clone(), audit)?)),
        ObfsConfig::MeekHttp { .. } => Ok(Box::new(meek::MeekHttpTransport::new(cfg.clone(), audit)?)),
        ObfsConfig::Websocket { .. } => Ok(Box::new(websocket::WebsocketTransport::new(cfg.clone(), audit)?)),
        ObfsConfig::Shadowsocks { .. } => {
            Ok(Box::new(shadowsocks::ShadowsocksTransport::new(cfg.clone(), audit)?))
        }
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod testing {
    //! Test fixtures exposed when the `testing` feature is enabled.
    pub use crate::audit::MockAuditHook;
}
