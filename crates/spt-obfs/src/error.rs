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

    /// Reserved error class for transports that explicitly refuse to
    /// run on a given build (no-op on the live wire paths shipped today
    /// but kept on the public surface for back-compat with t6-era
    /// callers that match on it).
    #[error("transport `{transport}` requires `{crate_name}`: {detail}")]
    Unsupported {
        /// Transport identifier.
        transport: &'static str,
        /// Name of the upstream dep / feature.
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
