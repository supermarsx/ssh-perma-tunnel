//! Cross-crate error type for `spt`.
//!
//! Every variant aligns with one of the 38 stable [`ExitCode`] values from
//! spec §7.4. Use [`Error::exit_code`] to translate an error to its process
//! exit code at the binary boundary.

use std::path::PathBuf;

use thiserror::Error;

use crate::exit_code::ExitCode;

/// Convenience [`Result`] alias bound to [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error type for the spt workspace.
///
/// The variants intentionally mirror spec §7.4 one-to-one so that mapping to a
/// process exit code via [`Error::exit_code`] is unambiguous.
#[derive(Debug, Error)]
#[non_exhaustive]
#[allow(clippy::enum_variant_names)] // names mirror spec §7.4 verbatim
pub enum Error {
    /// 1 — Invalid command-line arguments.
    #[error("invalid command-line arguments: {0}")]
    InvalidArgs(String),

    /// 2 — Configuration file failed to parse or validate.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// 3 — Generic runtime failure.
    #[error("runtime failure: {0}")]
    RuntimeFailure(String),

    /// 4 — A required profile failed to start or remained down.
    #[error("required profile `{profile}` failed: {reason}")]
    RequiredProfileFailed {
        /// Profile id that failed.
        profile: String,
        /// Human-readable reason.
        reason: String,
    },

    /// 5 — Authentication failure to a remote endpoint.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// 6 — Host key, certificate, or TLS pin verification failed.
    #[error("trust verification failed: {0}")]
    TrustFailed(String),

    /// 7 — Local listener bind failed.
    #[error("local bind failed on `{address}`: {reason}")]
    LocalBindFailed {
        /// Address that could not be bound.
        address: String,
        /// Underlying reason.
        reason: String,
    },

    /// 8 — Remote/forwarded bind failed.
    #[error("remote bind failed on `{address}`: {reason}")]
    RemoteBindFailed {
        /// Address requested for the remote bind.
        address: String,
        /// Underlying reason.
        reason: String,
    },

    /// 9 — A service-manager (systemd, launchd, SCM, ...) operation failed.
    #[error("service manager operation failed: {0}")]
    ServiceManagerFailed(String),

    /// 10 — Platform or feature is not supported on this system.
    #[error("unsupported platform or feature: {0}")]
    UnsupportedPlatform(String),

    /// 11 — DNS resolution or internal DNS failure.
    #[error("DNS failure: {0}")]
    DnsFailed(String),

    /// 12 — Network unreachable, connection refused, or similar.
    #[error("network unreachable: {0}")]
    NetworkUnreachable(String),

    /// 13 — A keepalive probe timed out.
    #[error("keepalive timed out after {after_ms} ms")]
    KeepaliveTimeout {
        /// Timeout duration in milliseconds.
        after_ms: u64,
    },

    /// 14 — `config reload` failed.
    #[error("config reload failed: {0}")]
    ReloadFailed(String),

    /// 15 — A logging sink is unavailable.
    #[error("logging sink `{sink}` unavailable: {reason}")]
    LoggingSinkUnavailable {
        /// Sink identifier (e.g. `journald`, `https`, `file`).
        sink: String,
        /// Underlying reason.
        reason: String,
    },

    /// 16 — State lock or state directory failure.
    #[error("state lock failed at `{path}`: {reason}")]
    StateLockFailed {
        /// Path of the state file or directory.
        path: PathBuf,
        /// Underlying reason.
        reason: String,
    },

    /// 17 — Referenced secret is unavailable, locked, or denied by policy.
    #[error("secret `{reference}` unavailable: {reason}")]
    SecretUnavailable {
        /// `secret://ns/name` reference or similar opaque id.
        reference: String,
        /// Underlying reason.
        reason: String,
    },

    /// 18 — Secret encryption or decryption failed.
    #[error("secret crypto failure: {0}")]
    SecretCryptoFailed(String),

    /// 19 — Key generation, parsing, or file-permission check failed.
    #[error("key failure: {0}")]
    KeyFailure(String),

    /// 20 — Permission denied for an OS-level operation.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// 21 — Resource exhausted (file descriptors, memory, ...).
    #[error("resource exhausted: {0}")]
    ResourceExhausted(String),

    /// 22 — Operation rejected by a rate-limit or throttle policy.
    #[error("rate-limited: {0}")]
    RateLimited(String),

    /// 23 — All failover targets exhausted.
    #[error("failover exhausted for profile `{profile}`")]
    FailoverExhausted {
        /// Profile id whose targets are exhausted.
        profile: String,
    },

    /// 24 — SNMP agent or metrics exporter failure.
    #[error("snmp/metrics exporter failed: {0}")]
    SnmpOrMetricsFailed(String),

    /// 25 — A Windows Event Log operation failed.
    #[error("Windows Event Log operation failed: {0}")]
    WindowsEventLogFailed(String),

    /// 26 — MCP server or MCP policy failure.
    #[error("MCP failure: {0}")]
    McpFailed(String),

    /// 27 — A remote observability sink rejected delivered data.
    #[error("remote sink `{sink}` rejected data: {reason}")]
    RemoteSinkRejected {
        /// Sink identifier.
        sink: String,
        /// Underlying reason.
        reason: String,
    },

    /// 28 — Partial success: non-required profiles degraded.
    #[error("partial success; degraded profiles: {0:?}")]
    PartialDegraded(Vec<String>),

    /// 29 — A health check failed.
    #[error("health check `{check}` failed: {reason}")]
    HealthCheckFailed {
        /// Health-check identifier.
        check: String,
        /// Underlying reason.
        reason: String,
    },

    /// 30 — Schema version or migration failure.
    #[error("version/migration failed: {0}")]
    VersionOrMigrationFailed(String),

    /// 31 — Internal invariant violation. Always indicates a bug.
    #[error("internal error: {0}")]
    InternalError(String),

    /// 32 — A diagnostic check reported failure.
    #[error("diagnostic check `{check}` failed: {reason}")]
    DiagnosticFailed {
        /// Diagnostic check id.
        check: String,
        /// Underlying reason.
        reason: String,
    },

    /// 33 — Diagnostic bundle generation failed.
    #[error("diagnostic bundle generation failed: {0}")]
    DiagnosticBundleFailed(String),

    /// 34 — A benchmark run failed.
    #[error("benchmark failed: {0}")]
    BenchmarkFailed(String),

    /// 35 — Benchmark refused by safety policy.
    #[error("benchmark refused by safety policy: {0}")]
    BenchmarkRefused(String),

    /// 36 — Session not found.
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// 37 — Session close or drain failed.
    #[error("session close failed: {0}")]
    SessionCloseFailed(String),
}

impl Error {
    /// Map an error to the stable process exit code stipulated by spec §7.4.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::InvalidArgs(_) => ExitCode::InvalidArgs,
            Self::InvalidConfig(_) => ExitCode::InvalidConfig,
            Self::RuntimeFailure(_) => ExitCode::RuntimeFailure,
            Self::RequiredProfileFailed { .. } => ExitCode::RequiredProfileFailed,
            Self::AuthFailed(_) => ExitCode::AuthFailed,
            Self::TrustFailed(_) => ExitCode::TrustFailed,
            Self::LocalBindFailed { .. } => ExitCode::LocalBindFailed,
            Self::RemoteBindFailed { .. } => ExitCode::RemoteBindFailed,
            Self::ServiceManagerFailed(_) => ExitCode::ServiceManagerFailed,
            Self::UnsupportedPlatform(_) => ExitCode::UnsupportedPlatform,
            Self::DnsFailed(_) => ExitCode::DnsFailed,
            Self::NetworkUnreachable(_) => ExitCode::NetworkUnreachable,
            Self::KeepaliveTimeout { .. } => ExitCode::KeepaliveTimeout,
            Self::ReloadFailed(_) => ExitCode::ReloadFailed,
            Self::LoggingSinkUnavailable { .. } => ExitCode::LoggingSinkUnavailable,
            Self::StateLockFailed { .. } => ExitCode::StateLockFailed,
            Self::SecretUnavailable { .. } => ExitCode::SecretUnavailable,
            Self::SecretCryptoFailed(_) => ExitCode::SecretCryptoFailed,
            Self::KeyFailure(_) => ExitCode::KeyFailure,
            Self::PermissionDenied(_) => ExitCode::PermissionDenied,
            Self::ResourceExhausted(_) => ExitCode::ResourceExhausted,
            Self::RateLimited(_) => ExitCode::RateLimited,
            Self::FailoverExhausted { .. } => ExitCode::FailoverExhausted,
            Self::SnmpOrMetricsFailed(_) => ExitCode::SnmpOrMetricsFailed,
            Self::WindowsEventLogFailed(_) => ExitCode::WindowsEventLogFailed,
            Self::McpFailed(_) => ExitCode::McpFailed,
            Self::RemoteSinkRejected { .. } => ExitCode::RemoteSinkRejected,
            Self::PartialDegraded(_) => ExitCode::PartialDegraded,
            Self::HealthCheckFailed { .. } => ExitCode::HealthCheckFailed,
            Self::VersionOrMigrationFailed(_) => ExitCode::VersionOrMigrationFailed,
            Self::InternalError(_) => ExitCode::InternalError,
            Self::DiagnosticFailed { .. } => ExitCode::DiagnosticFailed,
            Self::DiagnosticBundleFailed(_) => ExitCode::DiagnosticBundleFailed,
            Self::BenchmarkFailed(_) => ExitCode::BenchmarkFailed,
            Self::BenchmarkRefused(_) => ExitCode::BenchmarkRefused,
            Self::SessionNotFound(_) => ExitCode::SessionNotFound,
            Self::SessionCloseFailed(_) => ExitCode::SessionCloseFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Result};
    use crate::exit_code::ExitCode;

    fn sample_errors() -> Vec<(Error, ExitCode)> {
        vec![
            (Error::InvalidArgs("x".into()), ExitCode::InvalidArgs),
            (Error::InvalidConfig("x".into()), ExitCode::InvalidConfig),
            (Error::RuntimeFailure("x".into()), ExitCode::RuntimeFailure),
            (
                Error::RequiredProfileFailed {
                    profile: "p".into(),
                    reason: "r".into(),
                },
                ExitCode::RequiredProfileFailed,
            ),
            (Error::AuthFailed("x".into()), ExitCode::AuthFailed),
            (Error::TrustFailed("x".into()), ExitCode::TrustFailed),
            (
                Error::LocalBindFailed {
                    address: "a".into(),
                    reason: "r".into(),
                },
                ExitCode::LocalBindFailed,
            ),
            (
                Error::RemoteBindFailed {
                    address: "a".into(),
                    reason: "r".into(),
                },
                ExitCode::RemoteBindFailed,
            ),
            (
                Error::ServiceManagerFailed("x".into()),
                ExitCode::ServiceManagerFailed,
            ),
            (
                Error::UnsupportedPlatform("x".into()),
                ExitCode::UnsupportedPlatform,
            ),
            (Error::DnsFailed("x".into()), ExitCode::DnsFailed),
            (
                Error::NetworkUnreachable("x".into()),
                ExitCode::NetworkUnreachable,
            ),
            (
                Error::KeepaliveTimeout { after_ms: 1000 },
                ExitCode::KeepaliveTimeout,
            ),
            (Error::ReloadFailed("x".into()), ExitCode::ReloadFailed),
            (
                Error::LoggingSinkUnavailable {
                    sink: "s".into(),
                    reason: "r".into(),
                },
                ExitCode::LoggingSinkUnavailable,
            ),
            (
                Error::StateLockFailed {
                    path: "/tmp".into(),
                    reason: "r".into(),
                },
                ExitCode::StateLockFailed,
            ),
            (
                Error::SecretUnavailable {
                    reference: "secret://a/b".into(),
                    reason: "r".into(),
                },
                ExitCode::SecretUnavailable,
            ),
            (
                Error::SecretCryptoFailed("x".into()),
                ExitCode::SecretCryptoFailed,
            ),
            (Error::KeyFailure("x".into()), ExitCode::KeyFailure),
            (
                Error::PermissionDenied("x".into()),
                ExitCode::PermissionDenied,
            ),
            (
                Error::ResourceExhausted("x".into()),
                ExitCode::ResourceExhausted,
            ),
            (Error::RateLimited("x".into()), ExitCode::RateLimited),
            (
                Error::FailoverExhausted {
                    profile: "p".into(),
                },
                ExitCode::FailoverExhausted,
            ),
            (
                Error::SnmpOrMetricsFailed("x".into()),
                ExitCode::SnmpOrMetricsFailed,
            ),
            (
                Error::WindowsEventLogFailed("x".into()),
                ExitCode::WindowsEventLogFailed,
            ),
            (Error::McpFailed("x".into()), ExitCode::McpFailed),
            (
                Error::RemoteSinkRejected {
                    sink: "s".into(),
                    reason: "r".into(),
                },
                ExitCode::RemoteSinkRejected,
            ),
            (
                Error::PartialDegraded(vec!["a".into()]),
                ExitCode::PartialDegraded,
            ),
            (
                Error::HealthCheckFailed {
                    check: "c".into(),
                    reason: "r".into(),
                },
                ExitCode::HealthCheckFailed,
            ),
            (
                Error::VersionOrMigrationFailed("x".into()),
                ExitCode::VersionOrMigrationFailed,
            ),
            (Error::InternalError("x".into()), ExitCode::InternalError),
            (
                Error::DiagnosticFailed {
                    check: "c".into(),
                    reason: "r".into(),
                },
                ExitCode::DiagnosticFailed,
            ),
            (
                Error::DiagnosticBundleFailed("x".into()),
                ExitCode::DiagnosticBundleFailed,
            ),
            (
                Error::BenchmarkFailed("x".into()),
                ExitCode::BenchmarkFailed,
            ),
            (
                Error::BenchmarkRefused("x".into()),
                ExitCode::BenchmarkRefused,
            ),
            (
                Error::SessionNotFound("x".into()),
                ExitCode::SessionNotFound,
            ),
            (
                Error::SessionCloseFailed("x".into()),
                ExitCode::SessionCloseFailed,
            ),
        ]
    }

    #[test]
    fn every_variant_maps_to_expected_exit_code() {
        let cases = sample_errors();
        // 37 non-success codes (ExitCode 1..=37) are all represented.
        assert_eq!(cases.len(), 37);
        for (err, expected) in cases {
            assert_eq!(err.exit_code(), expected, "{err}");
        }
    }

    #[test]
    fn display_is_non_empty() {
        for (err, _) in sample_errors() {
            assert!(!format!("{err}").is_empty());
        }
    }

    #[test]
    #[allow(clippy::unnecessary_literal_unwrap)]
    fn result_alias_works() {
        let r: Result<u32> = Ok(7);
        assert_eq!(r.unwrap(), 7);
        let r: Result<u32> = Err(Error::InternalError("nope".into()));
        assert_eq!(r.unwrap_err().exit_code(), ExitCode::InternalError);
    }
}
