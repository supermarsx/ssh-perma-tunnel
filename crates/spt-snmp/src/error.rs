//! Error types used across `spt-snmp`.

use thiserror::Error;

/// Top-level result alias.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Errors raised by the codec, USM, and agent.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// BER/DER decoding failure (truncated, malformed length, unexpected tag).
    #[error("ber decode: {0}")]
    Ber(String),

    /// BER/DER encoding failure.
    #[error("ber encode: {0}")]
    BerEncode(String),

    /// SNMPv3 message-level decode failure.
    #[error("snmp message: {0}")]
    Message(String),

    /// USM authentication failure (wrong digest, unknown user, ...).
    #[error("usm: {0}")]
    Usm(UsmError),

    /// I/O error from the agent socket.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Agent or sender mis-configuration.
    #[error("config: {0}")]
    Config(String),

    /// Privacy (encryption/decryption) failure.
    #[error("privacy: {0}")]
    Privacy(String),

    /// Internal invariant violation. Should be unreachable in correct code.
    #[error("internal invariant: {0}")]
    Internal(&'static str),
}

/// USM-specific error variants. These map 1-1 to the RFC 3414 / 7860
/// `usmStats*` counters that the agent maintains.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum UsmError {
    /// `usmStatsUnsupportedSecLevels`
    #[error("unsupported security level")]
    UnsupportedSecLevel,
    /// `usmStatsNotInTimeWindows` — engine clock outside the 150 s window.
    #[error("message not in time window")]
    NotInTimeWindow,
    /// `usmStatsUnknownUserNames`
    #[error("unknown user name")]
    UnknownUserName,
    /// `usmStatsUnknownEngineIDs`
    #[error("unknown engine id")]
    UnknownEngineId,
    /// `usmStatsWrongDigests`
    #[error("wrong digest")]
    WrongDigest,
    /// `usmStatsDecryptionErrors`
    #[error("decryption error")]
    DecryptionError,
}
