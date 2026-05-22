//! Network-error enrichment helpers (t8-A2).
//!
//! The t7-era network call-sites in this crate construct `Error::LocalBindFailed`
//! / `Error::RuntimeFailure` directly. The t8-A2 brief asks for richer
//! diagnostics on the **`NetworkUnreachable`** (spec §7.4 exit code 12) class
//! of failures — connect failures, DNS NXDOMAIN, TCP RST during handshake,
//! ECONNREFUSED, ETIMEDOUT, ENETUNREACH, EHOSTUNREACH — so an operator hitting
//! a transient blip sees `retry: retry with backoff` while a typo'd hostname
//! shows `retry: not retryable`.
//!
//! `spt-net` itself does **not** call `connect(2)` — that lives in `spt-ssh2`,
//! `spt-supervisor`, and other higher-level crates. Rather than touching their
//! files (locked to other executors), this module ships the helpers and tests
//! the helpers; the higher-level crates will adopt them in their own files
//! (per A1's pattern of `spt_core::Error::invalid_config(Diagnostic::…)`).
//!
//! # Usage from a calling crate
//!
//! ```ignore
//! use spt_net::{classify_io_error, network_unreachable_from_io};
//!
//! match tokio::net::TcpStream::connect(&addr).await {
//!     Ok(s) => s,
//!     Err(io) => return Err(network_unreachable_from_io(&addr.to_string(), &io)),
//! }
//! ```

use std::io;

use spt_core::{Diagnostic, Error, RetryAdvice};

/// Coarse classification of a network failure used to pick a [`RetryAdvice`]
/// and a remediation hint.
///
/// We map [`std::io::ErrorKind`] (and a few `raw_os_error()` codes the
/// stdlib still stuffs into `ErrorKind::Uncategorized`) onto these classes.
/// The categories are deliberately broad — the per-class remediation text
/// is what the operator sees, not the enum name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkErrorKind {
    /// TCP RST received during handshake. Often transient (server starting
    /// up, sshd reloading config).
    ConnectionReset,
    /// Server actively refused (RST on SYN). Either the port is closed or
    /// a firewall is denying. Worth retrying with backoff in case it's a
    /// race against service startup, but the operator should sanity-check
    /// the port first.
    ConnectionRefused,
    /// TCP timeout — neither SYN-ACK nor RST returned. Almost always
    /// transient (loss / saturation) on long-haul links.
    TimedOut,
    /// `ENETUNREACH`. Often a missing default route — retry with backoff,
    /// but flag the route problem in the fix-it text.
    NetworkUnreachable,
    /// `EHOSTUNREACH`. Specific host not routable. Transient on flapping
    /// links; the fix-it text points at the routing layer.
    HostUnreachable,
    /// DNS lookup failed (NXDOMAIN or temporary resolver failure). The
    /// caller passes a more specific [`RetryAdvice`] via [`dns_failure`].
    DnsFailure,
    /// Generic / unclassified network error.
    Other,
}

impl NetworkErrorKind {
    /// Retry policy hint for this failure class.
    ///
    /// DNS failures intentionally default to [`RetryAdvice::RetryWithBackoff`]
    /// here; the caller can override via [`dns_failure`] when it knows the
    /// resolver returned NXDOMAIN (which is `NotRetryable`).
    #[must_use]
    pub fn retry_advice(self) -> RetryAdvice {
        // All currently-classified network failures default to retry-with-backoff;
        // DNS failures only flip to `NotRetryable` when the caller passes
        // `nxdomain = true` via [`dns_failure`].
        match self {
            Self::ConnectionReset
            | Self::ConnectionRefused
            | Self::TimedOut
            | Self::NetworkUnreachable
            | Self::HostUnreachable
            | Self::DnsFailure
            | Self::Other => RetryAdvice::RetryWithBackoff,
        }
    }

    /// Short imperative summary used as the diagnostic `what` field.
    fn what(self, endpoint: &str) -> String {
        match self {
            Self::ConnectionReset => format!("Failed to connect to `{endpoint}` — TCP RST"),
            Self::ConnectionRefused => {
                format!("Failed to connect to `{endpoint}` — connection refused")
            }
            Self::TimedOut => format!("Failed to connect to `{endpoint}` — timed out"),
            Self::NetworkUnreachable => {
                format!("Failed to connect to `{endpoint}` — network unreachable")
            }
            Self::HostUnreachable => {
                format!("Failed to connect to `{endpoint}` — host unreachable")
            }
            Self::DnsFailure => format!("Failed to resolve `{endpoint}`"),
            Self::Other => format!("Network failure talking to `{endpoint}`"),
        }
    }

    /// Remediation hint used as the diagnostic `how_to_fix` field.
    fn how_to_fix(self) -> &'static str {
        match self {
            Self::ConnectionReset => {
                "The peer accepted the TCP handshake then sent a RST. This often \
                 means sshd is restarting or rate-limiting from a fail2ban-style \
                 jail. Wait a few seconds and retry, or check the server's \
                 /var/log/auth.log."
            }
            Self::ConnectionRefused => {
                "The peer rejected the SYN. Verify the port number, that sshd \
                 (or your target service) is listening (`ss -lntp` on Linux, \
                 `netstat -ano` on Windows), and that no firewall is blocking \
                 inbound traffic."
            }
            Self::TimedOut => {
                "Neither SYN-ACK nor RST returned within the kernel's TCP \
                 timeout. Likely transient loss/saturation; retry with backoff. \
                 If it persists, check the route with `mtr <host>` or `tcptraceroute`."
            }
            Self::NetworkUnreachable => {
                "The local routing table has no route to the destination network. \
                 Check `ip route` / `route print` for a default gateway and the \
                 link's up state."
            }
            Self::HostUnreachable => {
                "The router replied with ICMP `host unreachable`. The destination \
                 host is down or unreachable on the destination network. Retry \
                 with backoff and verify the host is up."
            }
            Self::DnsFailure => {
                "DNS lookup failed. Verify the hostname is spelt correctly, that \
                 the resolver (`/etc/resolv.conf` / system DNS) is configured, \
                 and that no DNSSEC validation is failing."
            }
            Self::Other => {
                "Network operation failed. Retry with backoff; if it persists, \
                 capture a packet trace with `tcpdump -i any host <host>` to \
                 narrow down the failure."
            }
        }
    }
}

/// Classify an [`io::Error`] returned by `connect(2)` / `read(2)` / `write(2)`
/// into a [`NetworkErrorKind`].
///
/// Recognised kinds: `ConnectionReset`, `ConnectionRefused`, `TimedOut`,
/// `NetworkUnreachable`, `HostUnreachable`. Everything else falls through to
/// [`NetworkErrorKind::Other`] — including stdlib `Uncategorized` errors
/// whose `raw_os_error()` doesn't correspond to a well-known errno on the
/// current platform.
#[must_use]
pub fn classify_io_error(err: &io::Error) -> NetworkErrorKind {
    match err.kind() {
        io::ErrorKind::ConnectionReset => NetworkErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionRefused => NetworkErrorKind::ConnectionRefused,
        io::ErrorKind::TimedOut => NetworkErrorKind::TimedOut,
        io::ErrorKind::NotFound => NetworkErrorKind::Other,
        _ => {
            // stdlib leaves `ENETUNREACH` / `EHOSTUNREACH` in
            // `ErrorKind::Uncategorized` on stable Rust 1.85, so reach
            // through to `raw_os_error()` for the well-known errno values
            // on Unix. On Windows the values differ
            // (WSAENETUNREACH = 10051, WSAEHOSTUNREACH = 10065).
            match err.raw_os_error() {
                #[cfg(unix)]
                Some(101) => NetworkErrorKind::NetworkUnreachable, // ENETUNREACH
                #[cfg(unix)]
                Some(113) => NetworkErrorKind::HostUnreachable, // EHOSTUNREACH
                #[cfg(windows)]
                Some(10051) => NetworkErrorKind::NetworkUnreachable, // WSAENETUNREACH
                #[cfg(windows)]
                Some(10065) => NetworkErrorKind::HostUnreachable, // WSAEHOSTUNREACH
                _ => NetworkErrorKind::Other,
            }
        }
    }
}

/// Build a [`Error::NetworkUnreachableDiagnostic`] from an explicit endpoint,
/// failure class, and optional underlying reason.
///
/// Use this when you already know the [`NetworkErrorKind`] (e.g. a higher-
/// level state machine that distinguishes `ConnectionRefused` from a DNS
/// failure on its own).
#[must_use]
pub fn network_unreachable_with(
    endpoint: &str,
    kind: NetworkErrorKind,
    why: Option<&str>,
) -> Error {
    let mut b = Diagnostic::what(kind.what(endpoint))
        .how_to_fix(kind.how_to_fix())
        .endpoint(endpoint)
        .retry_advice(kind.retry_advice());
    if let Some(w) = why {
        b = b.why(w);
    }
    Error::network_unreachable(b.build())
}

/// Build a [`Error::NetworkUnreachableDiagnostic`] from an [`io::Error`].
///
/// Wraps [`classify_io_error`] + [`network_unreachable_with`] so the typical
/// `match connect(addr) { Err(io) => ... }` site can stay a one-liner.
#[must_use]
pub fn network_unreachable_from_io(endpoint: &str, err: &io::Error) -> Error {
    let kind = classify_io_error(err);
    network_unreachable_with(endpoint, kind, Some(&err.to_string()))
}

/// Build a [`Error::NetworkUnreachableDiagnostic`] for a DNS failure.
///
/// `nxdomain = true` flips the [`RetryAdvice`] to `NotRetryable` (the
/// authoritative name servers said the name does not exist — no amount of
/// retrying changes that). `nxdomain = false` keeps the default
/// [`RetryAdvice::RetryWithBackoff`] (resolver hiccup, SERVFAIL, etc.).
#[must_use]
pub fn dns_failure(name: &str, nxdomain: bool, why: Option<&str>) -> Error {
    let retry = if nxdomain {
        RetryAdvice::NotRetryable
    } else {
        RetryAdvice::RetryWithBackoff
    };
    let mut b = Diagnostic::what(NetworkErrorKind::DnsFailure.what(name))
        .how_to_fix(NetworkErrorKind::DnsFailure.how_to_fix())
        .endpoint(name)
        .retry_advice(retry);
    if let Some(w) = why {
        b = b.why(w);
    }
    Error::network_unreachable(b.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error as IoError, ErrorKind};

    #[test]
    fn connection_refused_carries_endpoint_and_retry_with_backoff() {
        let err = network_unreachable_with(
            "bastion.example.com:22",
            NetworkErrorKind::ConnectionRefused,
            Some("ECONNREFUSED"),
        );
        let d = err.diagnostic().expect("structured diagnostic");
        assert_eq!(d.endpoint.as_deref(), Some("bastion.example.com:22"));
        assert_eq!(d.retry_advice, Some(RetryAdvice::RetryWithBackoff));
        assert!(d.how_to_fix.as_deref().unwrap().contains("listening"));
        assert!(d.what.contains("connection refused"));
        assert!(d.why.as_deref().unwrap().contains("ECONNREFUSED"));
    }

    #[test]
    fn dns_nxdomain_is_not_retryable() {
        let err = dns_failure("doesnotexist.example", true, Some("NXDOMAIN"));
        let d = err.diagnostic().expect("structured diagnostic");
        assert_eq!(d.retry_advice, Some(RetryAdvice::NotRetryable));
        assert!(d.what.contains("Failed to resolve"));
        assert_eq!(d.endpoint.as_deref(), Some("doesnotexist.example"));
    }

    #[test]
    fn dns_servfail_keeps_backoff() {
        let err = dns_failure("flaky.example", false, Some("SERVFAIL"));
        let d = err.diagnostic().expect("structured diagnostic");
        assert_eq!(d.retry_advice, Some(RetryAdvice::RetryWithBackoff));
    }

    #[test]
    fn classify_io_recognises_known_kinds() {
        let reset = IoError::from(ErrorKind::ConnectionReset);
        assert_eq!(classify_io_error(&reset), NetworkErrorKind::ConnectionReset);
        let refused = IoError::from(ErrorKind::ConnectionRefused);
        assert_eq!(
            classify_io_error(&refused),
            NetworkErrorKind::ConnectionRefused,
        );
        let timed = IoError::from(ErrorKind::TimedOut);
        assert_eq!(classify_io_error(&timed), NetworkErrorKind::TimedOut);
    }

    #[test]
    fn network_unreachable_from_io_picks_classification() {
        let io_err = IoError::from(ErrorKind::TimedOut);
        let err = network_unreachable_from_io("10.0.0.1:22", &io_err);
        let d = err.diagnostic().expect("structured");
        assert!(d.what.contains("timed out"));
        assert_eq!(d.endpoint.as_deref(), Some("10.0.0.1:22"));
        assert_eq!(d.retry_advice, Some(RetryAdvice::RetryWithBackoff));
    }

    #[test]
    fn exit_code_inherits_network_unreachable() {
        use spt_core::ExitCode;
        let err = network_unreachable_with("h:22", NetworkErrorKind::TimedOut, None);
        assert_eq!(err.exit_code(), ExitCode::NetworkUnreachable);
    }

    #[test]
    fn every_kind_renders_distinct_what_text() {
        let kinds = [
            NetworkErrorKind::ConnectionReset,
            NetworkErrorKind::ConnectionRefused,
            NetworkErrorKind::TimedOut,
            NetworkErrorKind::NetworkUnreachable,
            NetworkErrorKind::HostUnreachable,
            NetworkErrorKind::DnsFailure,
            NetworkErrorKind::Other,
        ];
        let texts: Vec<String> = kinds.iter().map(|k| k.what("h:22")).collect();
        let unique: std::collections::HashSet<&String> = texts.iter().collect();
        assert_eq!(
            unique.len(),
            texts.len(),
            "every kind must produce a distinct `what` line",
        );
    }
}
