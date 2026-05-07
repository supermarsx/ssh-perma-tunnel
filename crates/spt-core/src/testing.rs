//! Test facilities for `spt-core`.
//!
//! Available behind the `testing` feature flag (and automatically under
//! `cfg(test)`). Provides representative fixtures, deterministic ID
//! generators, and a redaction corpus that downstream crates use to verify
//! their integration with the core types.
//!
//! All randomness is seeded with `ChaCha20Rng` so output is reproducible
//! across runs and platforms.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::address::BindAddr;
use crate::error::Error;
use crate::id::{ConnectionId, ForwardId, ProfileId, SessionId};
use crate::redaction::RedactionMode;

/// Pre-built canonical fixtures.
pub mod fixtures {
    use super::{BindAddr, ConnectionId, Error, ForwardId, IpAddr, Ipv4Addr, Ipv6Addr, PathBuf,
        ProfileId, SessionId, SocketAddr};

    /// One representative instance of each [`Error`] variant.
    ///
    /// Each variant maps 1:1 to a `spt_core::ExitCode`. Useful for snapshot
    /// tests that exercise the error → exit-code path or `Display` formatting.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_core::testing::fixtures::sample_errors;
    /// let errs = sample_errors();
    /// assert!(errs.iter().any(|e| matches!(e, spt_core::Error::AuthFailed(_))));
    /// ```
    #[must_use]
    pub fn sample_errors() -> Vec<Error> {
        vec![
            Error::InvalidArgs("bad flag".into()),
            Error::InvalidConfig("missing version".into()),
            Error::RuntimeFailure("worker panic".into()),
            Error::RequiredProfileFailed {
                profile: "p1".into(),
                reason: "auth".into(),
            },
            Error::AuthFailed("publickey rejected".into()),
            Error::TrustFailed("host key mismatch".into()),
            Error::LocalBindFailed {
                address: "127.0.0.1:8080".into(),
                reason: "EADDRINUSE".into(),
            },
            Error::RemoteBindFailed {
                address: "0.0.0.0:443".into(),
                reason: "denied".into(),
            },
            Error::ServiceManagerFailed("systemctl: not found".into()),
            Error::UnsupportedPlatform("haiku".into()),
            Error::DnsFailed("NXDOMAIN".into()),
            Error::NetworkUnreachable("no route".into()),
            Error::KeepaliveTimeout { after_ms: 30_000 },
            Error::ReloadFailed("config invalid".into()),
            Error::LoggingSinkUnavailable {
                sink: "journald".into(),
                reason: "ENOENT".into(),
            },
            Error::StateLockFailed {
                path: PathBuf::from("/var/lib/spt/spt.lock"),
                reason: "locked".into(),
            },
            Error::SecretUnavailable {
                reference: "secret://ssh/key".into(),
                reason: "no entry".into(),
            },
            Error::SecretCryptoFailed("aead tag mismatch".into()),
            Error::KeyFailure("wrong passphrase".into()),
            Error::PermissionDenied("EACCES".into()),
            Error::ResourceExhausted("EMFILE".into()),
            Error::RateLimited("connection burst".into()),
            Error::FailoverExhausted {
                profile: "p1".into(),
            },
            Error::SnmpOrMetricsFailed("listener bind".into()),
            Error::WindowsEventLogFailed("source missing".into()),
            Error::McpFailed("transport closed".into()),
            Error::RemoteSinkRejected {
                sink: "https".into(),
                reason: "HTTP 503".into(),
            },
            Error::PartialDegraded(vec!["secondary".into()]),
            Error::HealthCheckFailed {
                check: "tcp_connect".into(),
                reason: "timeout".into(),
            },
            Error::VersionOrMigrationFailed("v0->v1".into()),
            Error::InternalError("unreachable".into()),
            Error::DiagnosticFailed {
                check: "dns".into(),
                reason: "no upstream".into(),
            },
            Error::DiagnosticBundleFailed("disk full".into()),
            Error::BenchmarkFailed("driver crash".into()),
            Error::BenchmarkRefused("safety policy".into()),
            Error::SessionNotFound("s-42".into()),
            Error::SessionCloseFailed("drain timeout".into()),
        ]
    }

    /// Representative [`BindAddr`] values: IPv4, IPv6, host:port, unix.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_core::testing::fixtures::sample_bind_addrs;
    /// assert_eq!(sample_bind_addrs().len(), 4);
    /// ```
    #[must_use]
    pub fn sample_bind_addrs() -> Vec<BindAddr> {
        vec![
            BindAddr::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22)),
            BindAddr::Tcp(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080)),
            BindAddr::TcpHostPort {
                host: "bastion.example.com".into(),
                port: 22,
            },
            BindAddr::Unix(PathBuf::from("/run/spt.sock")),
        ]
    }

    /// Generate `n` deterministic [`SessionId`]s seeded from `seed`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_core::testing::fixtures::sample_session_ids;
    /// let a = sample_session_ids(3, 42);
    /// let b = sample_session_ids(3, 42);
    /// assert_eq!(a, b);
    /// ```
    #[must_use]
    pub fn sample_session_ids(n: usize, seed: u64) -> Vec<SessionId> {
        super::seeded_ids(n, seed, |s| SessionId::new(s).expect("non-empty"))
    }

    /// Generate `n` deterministic [`ConnectionId`]s seeded from `seed`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_core::testing::fixtures::sample_connection_ids;
    /// assert_eq!(sample_connection_ids(2, 1).len(), 2);
    /// ```
    #[must_use]
    pub fn sample_connection_ids(n: usize, seed: u64) -> Vec<ConnectionId> {
        super::seeded_ids(n, seed, |s| ConnectionId::new(s).expect("non-empty"))
    }

    /// Generate `n` deterministic [`ProfileId`]s seeded from `seed`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_core::testing::fixtures::sample_profile_ids;
    /// assert_eq!(sample_profile_ids(1, 0).len(), 1);
    /// ```
    #[must_use]
    pub fn sample_profile_ids(n: usize, seed: u64) -> Vec<ProfileId> {
        super::seeded_ids(n, seed, |s| ProfileId::new(s).expect("non-empty"))
    }

    /// Generate `n` deterministic [`ForwardId`]s seeded from `seed`.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_core::testing::fixtures::sample_forward_ids;
    /// assert_eq!(sample_forward_ids(2, 7).len(), 2);
    /// ```
    #[must_use]
    pub fn sample_forward_ids(n: usize, seed: u64) -> Vec<ForwardId> {
        super::seeded_ids(n, seed, |s| ForwardId::new(s).expect("non-empty"))
    }
}

fn seeded_ids<T>(n: usize, seed: u64, build: impl Fn(String) -> T) -> Vec<T> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    (0..n)
        .map(|_| {
            let hi: u64 = rng.gen();
            let lo: u64 = rng.gen();
            build(format!("{hi:016x}{lo:016x}"))
        })
        .collect()
}

/// One-shot deterministic [`SessionId`].
///
/// # Examples
///
/// ```
/// use spt_core::testing::seeded_session_id;
/// assert_eq!(seeded_session_id(1), seeded_session_id(1));
/// ```
#[must_use]
pub fn seeded_session_id(seed: u64) -> SessionId {
    fixtures::sample_session_ids(1, seed)
        .pop()
        .expect("one element")
}

/// One-shot deterministic [`ConnectionId`].
///
/// # Examples
///
/// ```
/// use spt_core::testing::seeded_connection_id;
/// assert!(!seeded_connection_id(1).as_str().is_empty());
/// ```
#[must_use]
pub fn seeded_connection_id(seed: u64) -> ConnectionId {
    fixtures::sample_connection_ids(1, seed)
        .pop()
        .expect("one element")
}

/// One-shot deterministic [`ProfileId`].
///
/// # Examples
///
/// ```
/// use spt_core::testing::seeded_profile_id;
/// assert!(!seeded_profile_id(0).as_str().is_empty());
/// ```
#[must_use]
pub fn seeded_profile_id(seed: u64) -> ProfileId {
    fixtures::sample_profile_ids(1, seed)
        .pop()
        .expect("one element")
}

/// One-shot deterministic [`ForwardId`].
///
/// # Examples
///
/// ```
/// use spt_core::testing::seeded_forward_id;
/// assert!(!seeded_forward_id(0).as_str().is_empty());
/// ```
#[must_use]
pub fn seeded_forward_id(seed: u64) -> ForwardId {
    fixtures::sample_forward_ids(1, seed)
        .pop()
        .expect("one element")
}

/// Redaction test corpus: `(input, mode, must_contain)` triples.
pub mod redaction {
    use super::RedactionMode;

    /// Triples of `(input, mode, expected_substring_in_output)`.
    ///
    /// Each entry is a real-world-ish snippet that the [`crate::redact`]
    /// function should scrub. The third tuple element is a substring the
    /// redacted output is required to contain (typically `"[REDACTED]"`),
    /// or — for `None` mode — the original input.
    ///
    /// At least 8 cases per mode (`None`, `Standard`, `Strict`).
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_core::{redact, testing::redaction::test_corpus};
    /// for (input, mode, must_contain) in test_corpus() {
    ///     let out = redact(&input, mode);
    ///     assert!(out.contains(&must_contain), "{input:?} -> {out:?}");
    /// }
    /// ```
    #[must_use]
    pub fn test_corpus() -> Vec<(String, RedactionMode, String)> {
        let standard: &[(&str, &str)] = &[
            ("Authorization: Bearer abc.def_123", "[REDACTED]"),
            ("authorization: bearer XYZ.token-1", "[REDACTED]"),
            ("Authorization: Basic dXNlcjpwYXNz", "[REDACTED]"),
            ("password = \"hunter2\"", "[REDACTED]"),
            ("passphrase='swordfish'", "[REDACTED]"),
            ("api_key=sk-12345", "[REDACTED]"),
            ("token=abcdef", "[REDACTED]"),
            (
                "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----",
                "[REDACTED]",
            ),
        ];
        let strict: &[(&str, &str)] = &[
            ("client 1.2.3.4", "[REDACTED]"),
            ("server 10.0.0.1", "[REDACTED]"),
            ("from 192.168.1.5", "[REDACTED]"),
            ("v6 ::1", "[REDACTED]"),
            ("v6 fe80::abcd:1", "[REDACTED]"),
            ("v6 2001:db8::1", "[REDACTED]"),
            ("user alice@example.com", "[REDACTED]"),
            ("notify bob+filter@sub.domain.org", "[REDACTED]"),
        ];
        let none_cases: &[&str] = &[
            "password=hunter2",
            "1.2.3.4",
            "alice@example.com",
            "Authorization: Bearer T",
            "-----BEGIN PRIVATE KEY-----X-----END PRIVATE KEY-----",
            "token=abc",
            "::1",
            "passphrase='x'",
        ];

        let mut out = Vec::with_capacity(standard.len() + strict.len() + none_cases.len());
        for (input, expect) in standard {
            out.push(((*input).to_string(), RedactionMode::Standard, (*expect).to_string()));
        }
        for (input, expect) in strict {
            out.push(((*input).to_string(), RedactionMode::Strict, (*expect).to_string()));
        }
        for input in none_cases {
            // `None` is passthrough; the input is its own "expected substring".
            out.push(((*input).to_string(), RedactionMode::None, (*input).to_string()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact;

    #[test]
    fn sample_errors_covers_every_variant_one_to_one() {
        let errs = fixtures::sample_errors();
        // 37 non-success exit codes (1..=37).
        assert_eq!(errs.len(), 37);
        // Every error maps to an exit code without panicking.
        for e in &errs {
            let _ = e.exit_code();
        }
    }

    #[test]
    fn sample_bind_addrs_round_trip_via_display() {
        for a in fixtures::sample_bind_addrs() {
            let s = a.to_string();
            let parsed = BindAddr::parse(&s).expect("re-parse");
            assert_eq!(a, parsed, "round-trip {s}");
        }
    }

    #[test]
    fn seeded_ids_are_deterministic_across_calls() {
        let a = fixtures::sample_session_ids(4, 7);
        let b = fixtures::sample_session_ids(4, 7);
        assert_eq!(a, b);
        let c = fixtures::sample_session_ids(4, 8);
        assert_ne!(a, c);
    }

    #[test]
    fn seeded_one_shot_helpers_match_first_of_batch() {
        let one = seeded_session_id(99);
        let many = fixtures::sample_session_ids(1, 99);
        assert_eq!(one, many[0]);
    }

    #[test]
    fn redaction_corpus_has_eight_per_mode() {
        let corpus = redaction::test_corpus();
        let mut counts = (0, 0, 0);
        for (_, mode, _) in &corpus {
            match mode {
                RedactionMode::None => counts.0 += 1,
                RedactionMode::Standard => counts.1 += 1,
                RedactionMode::Strict => counts.2 += 1,
            }
        }
        assert!(counts.0 >= 8);
        assert!(counts.1 >= 8);
        assert!(counts.2 >= 8);
    }

    #[test]
    fn redaction_corpus_actually_redacts() {
        for (input, mode, must_contain) in redaction::test_corpus() {
            let out = redact(&input, mode);
            assert!(
                out.contains(&must_contain),
                "input={input:?} mode={mode:?} got={out:?} expected to contain {must_contain:?}"
            );
        }
    }
}
