//! Crate-local error type.
//!
//! Maps cleanly into `spt_core::Error` at the public surface; only used
//! internally by validators / handshake state machines to keep the
//! shape-discrimination explicit.

use thiserror::Error;

use spt_core::Error as CoreError;

/// Errors surfaced by obfuscated-transport construction and operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ObfsError {
    /// A required configuration field was malformed.
    #[error("invalid obfuscation config: {0}")]
    InvalidConfig(String),

    /// The transport requires an upstream crate (`obfs4`, `tokio-tungstenite`,
    /// `blake3`) that is not present in the workspace lockfile. The stub path
    /// refuses to forge a partial implementation.
    #[error("transport `{transport}` requires `{crate_name}` in Cargo.lock: {detail}")]
    Unsupported {
        /// Transport identifier (`obfs4` / `meek-http` / `ssh-over-websocket`
        /// / `ssh-over-shadowsocks`).
        transport: &'static str,
        /// Upstream crate that must land in `Cargo.lock` to activate the real
        /// path.
        crate_name: &'static str,
        /// Free-form human-readable detail.
        detail: String,
    },

    /// Wire-level handshake failure.
    #[error("obfuscation handshake failed: {0}")]
    Handshake(String),

    /// I/O error wrapping `std::io::Error`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ObfsError> for CoreError {
    fn from(e: ObfsError) -> Self {
        match e {
            ObfsError::InvalidConfig(s) => CoreError::InvalidConfig(s),
            ObfsError::Unsupported { transport, crate_name, detail } => {
                CoreError::UnsupportedPlatform(format!(
                    "{transport}: missing `{crate_name}` in Cargo.lock ({detail})"
                ))
            }
            ObfsError::Handshake(s) => CoreError::RuntimeFailure(format!("obfs handshake: {s}")),
            ObfsError::Io(e) => CoreError::RuntimeFailure(format!("obfs io: {e}")),
        }
    }
}
