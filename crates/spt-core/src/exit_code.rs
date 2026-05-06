//! Stable process exit codes defined by spec §7.4.
//!
//! These codes are part of the user-visible contract of the `spt` binary and
//! MUST NOT be reused or renumbered. Every variant maps to a single, distinct
//! `i32` value via [`From`].

/// Stable, user-visible exit codes for the `spt` binary.
///
/// The numeric value of each variant is part of the public CLI contract and
/// must never change. New conditions get new variants with new numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ExitCode {
    /// 0 — Successful completion.
    Success = 0,
    /// 1 — Invalid command-line arguments.
    InvalidArgs = 1,
    /// 2 — Configuration file failed to load or validate.
    InvalidConfig = 2,
    /// 3 — Generic runtime failure not covered by a more specific code.
    RuntimeFailure = 3,
    /// 4 — One or more profiles marked `required` failed to start or stay up.
    RequiredProfileFailed = 4,
    /// 5 — Authentication to a remote endpoint failed.
    AuthFailed = 5,
    /// 6 — Trust verification (host key, TLS pin, certificate) failed.
    TrustFailed = 6,
    /// 7 — A local listening bind failed.
    LocalBindFailed = 7,
    /// 8 — A remote/forwarded bind failed.
    RemoteBindFailed = 8,
    /// 9 — A service-manager operation (install, start, stop, ...) failed.
    ServiceManagerFailed = 9,
    /// 10 — Platform or feature is not supported.
    UnsupportedPlatform = 10,
    /// 11 — DNS resolution or the internal DNS resolver failed.
    DnsFailed = 11,
    /// 12 — Network unreachable or connection refused.
    NetworkUnreachable = 12,
    /// 13 — Keepalive timed out.
    KeepaliveTimeout = 13,
    /// 14 — `config reload` failed.
    ReloadFailed = 14,
    /// 15 — A required logging sink is unavailable.
    LoggingSinkUnavailable = 15,
    /// 16 — State directory or state-lock acquisition failed.
    StateLockFailed = 16,
    /// 17 — A referenced secret is unavailable, locked, or denied.
    SecretUnavailable = 17,
    /// 18 — Secret encryption or decryption failed.
    SecretCryptoFailed = 18,
    /// 19 — Key generation, parsing, or file-permission check failed.
    KeyFailure = 19,
    /// 20 — Permission denied.
    PermissionDenied = 20,
    /// 21 — Resource exhausted or out-of-memory.
    ResourceExhausted = 21,
    /// 22 — A rate limit or throttle policy rejected the operation.
    RateLimited = 22,
    /// 23 — All failover targets exhausted.
    FailoverExhausted = 23,
    /// 24 — SNMP agent or metrics exporter failed.
    SnmpOrMetricsFailed = 24,
    /// 25 — A Windows Event Log operation failed.
    WindowsEventLogFailed = 25,
    /// 26 — MCP server policy or operation failed.
    McpFailed = 26,
    /// 27 — A remote observability sink rejected delivered data.
    RemoteSinkRejected = 27,
    /// 28 — Partial success with degraded non-required profiles.
    PartialDegraded = 28,
    /// 29 — A health check failed.
    HealthCheckFailed = 29,
    /// 30 — Schema version or migration failure.
    VersionOrMigrationFailed = 30,
    /// 31 — Internal error (assertion, invariant, or `unreachable`).
    InternalError = 31,
    /// 32 — A diagnostic check reported failure.
    DiagnosticFailed = 32,
    /// 33 — Diagnostic bundle generation failed.
    DiagnosticBundleFailed = 33,
    /// 34 — A benchmark run failed.
    BenchmarkFailed = 34,
    /// 35 — Benchmark refused by safety policy.
    BenchmarkRefused = 35,
    /// 36 — Session not found.
    SessionNotFound = 36,
    /// 37 — Session close or drain failed.
    SessionCloseFailed = 37,
}

impl ExitCode {
    /// Numeric exit code as stipulated by spec §7.4.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        code as i32
    }
}

#[cfg(test)]
mod tests {
    use super::ExitCode;

    #[test]
    fn discriminants_match_spec() {
        // Spec §7.4: 38 stable codes, 0..=37, in this exact order.
        let expected: [(ExitCode, i32); 38] = [
            (ExitCode::Success, 0),
            (ExitCode::InvalidArgs, 1),
            (ExitCode::InvalidConfig, 2),
            (ExitCode::RuntimeFailure, 3),
            (ExitCode::RequiredProfileFailed, 4),
            (ExitCode::AuthFailed, 5),
            (ExitCode::TrustFailed, 6),
            (ExitCode::LocalBindFailed, 7),
            (ExitCode::RemoteBindFailed, 8),
            (ExitCode::ServiceManagerFailed, 9),
            (ExitCode::UnsupportedPlatform, 10),
            (ExitCode::DnsFailed, 11),
            (ExitCode::NetworkUnreachable, 12),
            (ExitCode::KeepaliveTimeout, 13),
            (ExitCode::ReloadFailed, 14),
            (ExitCode::LoggingSinkUnavailable, 15),
            (ExitCode::StateLockFailed, 16),
            (ExitCode::SecretUnavailable, 17),
            (ExitCode::SecretCryptoFailed, 18),
            (ExitCode::KeyFailure, 19),
            (ExitCode::PermissionDenied, 20),
            (ExitCode::ResourceExhausted, 21),
            (ExitCode::RateLimited, 22),
            (ExitCode::FailoverExhausted, 23),
            (ExitCode::SnmpOrMetricsFailed, 24),
            (ExitCode::WindowsEventLogFailed, 25),
            (ExitCode::McpFailed, 26),
            (ExitCode::RemoteSinkRejected, 27),
            (ExitCode::PartialDegraded, 28),
            (ExitCode::HealthCheckFailed, 29),
            (ExitCode::VersionOrMigrationFailed, 30),
            (ExitCode::InternalError, 31),
            (ExitCode::DiagnosticFailed, 32),
            (ExitCode::DiagnosticBundleFailed, 33),
            (ExitCode::BenchmarkFailed, 34),
            (ExitCode::BenchmarkRefused, 35),
            (ExitCode::SessionNotFound, 36),
            (ExitCode::SessionCloseFailed, 37),
        ];
        for (code, expected_value) in expected {
            assert_eq!(code.as_i32(), expected_value);
            assert_eq!(i32::from(code), expected_value);
        }
    }

    #[test]
    fn success_is_zero() {
        assert_eq!(i32::from(ExitCode::Success), 0);
    }

    #[test]
    fn copy_and_eq() {
        let a = ExitCode::AuthFailed;
        let b = a;
        assert_eq!(a, b);
    }
}
