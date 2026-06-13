//! Helpers for protocol backends implementing remote (server-listener) TCP
//! forwards.
//!
//! Layering note: the SSH2/SSH3 backend issues the protocol-level
//! `tcpip-forward` (or SSH3 equivalent) request, then receives a stream of
//! accepted inbound connections from the server. For each, it must connect to
//! the configured local target and bridge the two streams with
//! [`crate::bidir::copy_bidirectional_throttled`].
//!
//! This module provides the small, backend-agnostic helper
//! [`connect_target`] which honours `BindAddr` semantics for the local target.

use std::time::Duration;

use spt_core::{BindAddr, Error, Result};
use spt_net::diag::{network_unreachable_from_io, network_unreachable_with, NetworkErrorKind};
use tokio::net::TcpStream;

/// Connect to `target`. Honours `BindAddr` variants:
///
/// * [`BindAddr::Tcp`]/[`BindAddr::TcpHostPort`] → DNS-resolved TCP connect.
/// * [`BindAddr::Unix`] → unsupported on Windows; otherwise a UDS connect is
///   *not* supported here because we only return [`TcpStream`]; backends that
///   need UDS targets must compose their own helper.
///
/// `timeout` defaults to a generous 30s when `None`.
pub async fn connect_target(target: &BindAddr, timeout: Option<Duration>) -> Result<TcpStream> {
    let timeout = timeout.unwrap_or_else(|| Duration::from_secs(30));
    match target {
        BindAddr::Tcp(sock) => {
            // E7-F11: classify connect failures into structured
            // `NetworkUnreachable` diagnostics (retry advice + fix-it text,
            // exit code 12) via spt-net's diag helpers instead of a bare string.
            let endpoint = sock.to_string();
            let s = tokio::time::timeout(timeout, TcpStream::connect(sock))
                .await
                .map_err(|_| {
                    network_unreachable_with(
                        &endpoint,
                        NetworkErrorKind::TimedOut,
                        Some("connect timed out"),
                    )
                })?
                .map_err(|e| network_unreachable_from_io(&endpoint, &e))?;
            Ok(s)
        }
        BindAddr::TcpHostPort { host, port } => {
            // E7-F11: structured diagnostic on connect failure (see above).
            let endpoint = format!("{host}:{port}");
            let s = tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), *port)))
                .await
                .map_err(|_| {
                    network_unreachable_with(
                        &endpoint,
                        NetworkErrorKind::TimedOut,
                        Some("connect timed out"),
                    )
                })?
                .map_err(|e| network_unreachable_from_io(&endpoint, &e))?;
            Ok(s)
        }
        BindAddr::Unix(_) => Err(Error::UnsupportedPlatform(
            "unix-socket targets not supported by remote_tcp::connect_target".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn connects_to_listening_target() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let _accept = tokio::spawn(async move {
            let _ = l.accept().await;
        });
        let target = BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap();
        let s = connect_target(&target, Some(Duration::from_secs(2)))
            .await
            .unwrap();
        drop(s);
    }

    #[tokio::test]
    async fn refuses_unix_target() {
        let target = BindAddr::parse("unix:///tmp/spt-test.sock").unwrap();
        let r = connect_target(&target, Some(Duration::from_millis(100))).await;
        assert!(matches!(r, Err(Error::UnsupportedPlatform(_))));
    }

    // ---- Timeout / connect-refused / IPv6 / DNS coverage ----

    /// Connecting to a closed loopback port via [`BindAddr::Tcp`] must surface
    /// a structured `NetworkUnreachable` diagnostic (E7-F11): classified by the
    /// spt-net diag helper, carrying the endpoint, a retry advice, and a fix-it
    /// hint — exit code 12. (The exact OS error kind differs per platform —
    /// Linux returns ECONNREFUSED, Windows can surface a timeout — so we assert
    /// the structured contract, not a specific classification.)
    #[tokio::test]
    async fn refuses_closed_tcp_socket() {
        use spt_core::{ExitCode, RetryAdvice};
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let target = BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap();
        let err = connect_target(&target, Some(Duration::from_secs(2)))
            .await
            .expect_err("connect to closed port must fail");
        assert_eq!(err.exit_code(), ExitCode::NetworkUnreachable);
        let d = err
            .diagnostic()
            .expect("connect failure must carry a structured diagnostic");
        assert_eq!(
            d.endpoint.as_deref(),
            Some(format!("127.0.0.1:{port}").as_str())
        );
        // Every network failure class the helper produces here is retryable
        // with backoff (the adoption upgraded the bare string to advice-bearing).
        assert_eq!(d.retry_advice, Some(RetryAdvice::RetryWithBackoff));
        assert!(
            d.how_to_fix.is_some(),
            "structured diagnostic must carry fix-it text: {d:?}"
        );
    }

    /// Same as above but via the [`BindAddr::TcpHostPort`] branch — structured
    /// diagnostic with exit code 12 (E7-F11).
    #[tokio::test]
    async fn refuses_closed_tcphostport() {
        use spt_core::ExitCode;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let target = BindAddr::TcpHostPort {
            host: "127.0.0.1".into(),
            port,
        };
        let err = connect_target(&target, Some(Duration::from_secs(2)))
            .await
            .expect_err("connect to closed port must fail");
        assert_eq!(err.exit_code(), ExitCode::NetworkUnreachable);
        assert!(
            err.diagnostic().is_some(),
            "connect failure must carry a structured diagnostic"
        );
    }

    /// TEST-NET-1 (192.0.2.0/24, RFC 5737) is documented as unrouteable.
    /// The timeout arm yields a structured `TimedOut` diagnostic (E7-F11).
    #[tokio::test]
    async fn connect_timeout_tcp() {
        use spt_core::ExitCode;
        let target = BindAddr::Tcp("192.0.2.1:65000".parse().unwrap());
        let err = connect_target(&target, Some(Duration::from_millis(50)))
            .await
            .expect_err("unrouteable connect must fail");
        assert_eq!(err.exit_code(), ExitCode::NetworkUnreachable);
        assert!(err.diagnostic().is_some());
    }

    /// TcpHostPort timeout/unrouteable path — structured diagnostic.
    #[tokio::test]
    async fn connect_timeout_tcphostport() {
        use spt_core::ExitCode;
        let target = BindAddr::TcpHostPort {
            host: "192.0.2.2".into(),
            port: 65001,
        };
        let err = connect_target(&target, Some(Duration::from_millis(50)))
            .await
            .expect_err("unrouteable connect must fail");
        assert_eq!(err.exit_code(), ExitCode::NetworkUnreachable);
        assert!(err.diagnostic().is_some());
    }

    /// DNS resolution failure: ".invalid" TLD is reserved (RFC 6761). The
    /// resolver error flows through `classify_io_error` and surfaces as a
    /// structured `NetworkUnreachable` diagnostic carrying the endpoint.
    #[tokio::test]
    async fn dns_failure_returns_network_unreachable() {
        use spt_core::ExitCode;
        let target = BindAddr::TcpHostPort {
            host: "no-such-host.invalid".into(),
            port: 22,
        };
        let err = connect_target(&target, Some(Duration::from_secs(2)))
            .await
            .expect_err("DNS lookup of reserved .invalid TLD must fail");
        assert_eq!(err.exit_code(), ExitCode::NetworkUnreachable);
        let d = err
            .diagnostic()
            .expect("DNS failure must carry a structured diagnostic");
        assert_eq!(d.endpoint.as_deref(), Some("no-such-host.invalid:22"));
    }

    /// IPv6 loopback via [`BindAddr::Tcp`].
    #[tokio::test]
    async fn ipv6_loopback_tcp() {
        let bind = match TcpListener::bind("[::1]:0").await {
            Ok(l) => l,
            Err(_) => return,
        };
        let port = bind.local_addr().unwrap().port();
        let _accept = tokio::spawn(async move {
            let _ = bind.accept().await;
        });
        let target = BindAddr::Tcp(format!("[::1]:{port}").parse().unwrap());
        let s = connect_target(&target, Some(Duration::from_secs(2)))
            .await
            .unwrap();
        drop(s);
    }

    /// IPv6 loopback via [`BindAddr::TcpHostPort`].
    #[tokio::test]
    async fn ipv6_loopback_tcphostport() {
        let bind = match TcpListener::bind("[::1]:0").await {
            Ok(l) => l,
            Err(_) => return,
        };
        let port = bind.local_addr().unwrap().port();
        let _accept = tokio::spawn(async move {
            let _ = bind.accept().await;
        });
        let target = BindAddr::TcpHostPort {
            host: "::1".into(),
            port,
        };
        let s = connect_target(&target, Some(Duration::from_secs(2)))
            .await
            .unwrap();
        drop(s);
    }

    /// `None` timeout exercises the default-30s branch with a live listener.
    #[tokio::test]
    async fn default_timeout_when_none() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let _accept = tokio::spawn(async move {
            let _ = l.accept().await;
        });
        let target = BindAddr::TcpHostPort {
            host: "127.0.0.1".into(),
            port,
        };
        let s = connect_target(&target, None).await.unwrap();
        drop(s);
    }

    /// Unix targets are always rejected, regardless of timeout argument.
    #[tokio::test]
    async fn unix_target_rejects_even_with_none_timeout() {
        let target = BindAddr::Unix("/tmp/never.sock".into());
        let r = connect_target(&target, None).await;
        assert!(matches!(r, Err(Error::UnsupportedPlatform(_))));
    }

    /// E7-F11 (call-site adoption): a connect to an unreachable target must
    /// yield a *classified* `spt_net::diag` diagnostic, not a generic opaque
    /// error. The exact `NetworkErrorKind` is platform- and timing-dependent
    /// for a closed loopback port (ECONNREFUSED on Linux; on Windows the SYN
    /// retry can outlast the connect deadline and surface as a timeout), so we
    /// don't pin one kind. Instead we assert the produced (`what`, `how_to_fix`)
    /// pair is byte-identical to one the diag helper emits — proving the call
    /// site is wired through `network_unreachable_*` rather than an ad-hoc
    /// string — alongside the structured-contract fields.
    #[tokio::test]
    async fn unreachable_target_yields_classified_error() {
        use spt_core::{ExitCode, RetryAdvice};
        use spt_net::diag::{network_unreachable_with, NetworkErrorKind};

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l); // nothing is listening now
        let endpoint = format!("127.0.0.1:{port}");
        let sock: std::net::SocketAddr = endpoint.parse().unwrap();

        let actual = connect_target(&BindAddr::Tcp(sock), Some(Duration::from_secs(2)))
            .await
            .expect_err("connect_target to a closed port must fail");

        // Contract: structured, exit code 12, endpoint preserved, retryable.
        assert_eq!(actual.exit_code(), ExitCode::NetworkUnreachable);
        let ad = actual
            .diagnostic()
            .expect("connect_target must yield a classified diagnostic");
        assert_eq!(ad.endpoint.as_deref(), Some(endpoint.as_str()));
        assert_eq!(ad.retry_advice, Some(RetryAdvice::RetryWithBackoff));

        // Provenance: the (what, how_to_fix) pair must match one the diag
        // helper produces for the same endpoint — i.e. it came from
        // `spt_net::diag`, not a hand-rolled format string.
        let helper_pairs: Vec<_> = [
            NetworkErrorKind::ConnectionReset,
            NetworkErrorKind::ConnectionRefused,
            NetworkErrorKind::TimedOut,
            NetworkErrorKind::NetworkUnreachable,
            NetworkErrorKind::HostUnreachable,
            NetworkErrorKind::Other,
        ]
        .into_iter()
        .map(|k| {
            let e = network_unreachable_with(&endpoint, k, None);
            let d = e.diagnostic().unwrap().clone();
            (d.what, d.how_to_fix)
        })
        .collect();
        assert!(
            helper_pairs.contains(&(ad.what.clone(), ad.how_to_fix.clone())),
            "diagnostic did not come from spt_net::diag: {ad:?}"
        );
    }
}
