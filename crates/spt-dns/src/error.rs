//! Error type for `spt-dns`.

use std::io;

use thiserror::Error;

/// Errors produced by `spt-dns`.
#[derive(Debug, Error)]
pub enum DnsError {
    /// Underlying I/O failure (socket bind, hosts-file read/write, etc.).
    #[error("dns i/o error: {0}")]
    Io(#[from] io::Error),

    /// Invalid hostname in a [`Record`](crate::zone::Record) or in a request.
    #[error("invalid dns name: {0}")]
    InvalidName(String),

    /// Invalid [`Record`](crate::zone::Record) value (e.g. malformed IP).
    #[error("invalid record value for {kind:?} record `{value}`: {reason}")]
    InvalidValue {
        /// Record kind that failed.
        kind: crate::zone::RecordKind,
        /// The offending value.
        value: String,
        /// Human-readable reason.
        reason: String,
    },

    /// Hickory-server failure during run.
    #[error("dns server failure: {0}")]
    Server(String),

    /// Hickory-resolver failure on an upstream forward.
    #[error("upstream resolver failure: {0}")]
    Upstream(String),

    /// Hosts-file backup is missing on restore.
    #[error("hosts-file backup not found: {0}")]
    BackupMissing(String),

    /// Configuration error (invalid bind, mutually exclusive options).
    #[error("dns configuration error: {0}")]
    Config(String),
}

/// Convenience `Result` alias.
pub type Result<T> = std::result::Result<T, DnsError>;
