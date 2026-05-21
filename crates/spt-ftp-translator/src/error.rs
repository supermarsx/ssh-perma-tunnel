//! Translator error type.
//!
//! Every variant maps cleanly to a `spt_core::Error` so the CLI surface
//! exits with the right code from [`spt_core::ExitCode`]. Wire-level
//! protocol violations (out-of-order USER/PASS, refused verbs) are
//! reported back to the client as `5xx` FTP replies via [`crate::Reply`];
//! they do NOT escape as [`TranslatorError`] because they're recoverable
//! per the FTP state machine.

use thiserror::Error;

/// Translator-level error.
#[derive(Debug, Error)]
pub enum TranslatorError {
    /// I/O failure on the control channel.
    #[error("ftp control I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Listener bind failure.
    #[error("ftp bind {addr}: {source}")]
    Bind {
        /// Address we tried to bind.
        addr: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// Could not allocate a passive port from the configured range.
    #[error("no free passive port in range {low}-{high}")]
    NoPassivePort {
        /// Inclusive lower bound.
        low: u16,
        /// Inclusive upper bound.
        high: u16,
    },

    /// Server is at its `max_clients` limit.
    #[error("ftp translator at capacity ({max} clients)")]
    AtCapacity {
        /// Configured cap.
        max: usize,
    },

    /// SFTP backend call failed.
    #[error("sftp backend: {0}")]
    Sftp(String),

    /// TLS configuration error.
    #[error("tls config: {0}")]
    Tls(String),

    /// Idle timeout struck the control channel.
    #[error("ftp control channel idle timeout")]
    IdleTimeout,

    /// Generic configuration error (e.g. malformed `passive_port_range`).
    #[error("ftp translator config: {0}")]
    InvalidConfig(String),
}

impl From<TranslatorError> for spt_core::Error {
    fn from(e: TranslatorError) -> Self {
        match e {
            TranslatorError::InvalidConfig(s) | TranslatorError::Tls(s) => {
                Self::InvalidConfig(format!("ftp translator: {s}"))
            }
            other => Self::RuntimeFailure(format!("ftp translator: {other}")),
        }
    }
}
