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
            let s = tokio::time::timeout(timeout, TcpStream::connect(sock))
                .await
                .map_err(|_| Error::NetworkUnreachable(format!("connect timeout: {sock}")))?
                .map_err(|e| Error::NetworkUnreachable(format!("connect {sock}: {e}")))?;
            Ok(s)
        }
        BindAddr::TcpHostPort { host, port } => {
            let s = tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), *port)))
                .await
                .map_err(|_| Error::NetworkUnreachable(format!("connect timeout: {host}:{port}")))?
                .map_err(|e| Error::NetworkUnreachable(format!("connect {host}:{port}: {e}")))?;
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
    /// a `NetworkUnreachable` error (connection refused branch, not timeout).
    #[tokio::test]
    async fn refuses_closed_tcp_socket() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let target = BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap();
        let r = connect_target(&target, Some(Duration::from_secs(2))).await;
        match r {
            Err(Error::NetworkUnreachable(msg)) => {
                assert!(msg.contains("connect"), "msg={msg}");
            }
            other => panic!("expected NetworkUnreachable, got {other:?}"),
        }
    }

    /// Same as above but via the [`BindAddr::TcpHostPort`] branch.
    #[tokio::test]
    async fn refuses_closed_tcphostport() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let target = BindAddr::TcpHostPort {
            host: "127.0.0.1".into(),
            port,
        };
        let r = connect_target(&target, Some(Duration::from_secs(2))).await;
        assert!(matches!(r, Err(Error::NetworkUnreachable(_))));
    }

    /// TEST-NET-1 (192.0.2.0/24, RFC 5737) is documented as unrouteable.
    #[tokio::test]
    async fn connect_timeout_tcp() {
        let target = BindAddr::Tcp("192.0.2.1:65000".parse().unwrap());
        let r = connect_target(&target, Some(Duration::from_millis(50))).await;
        assert!(matches!(r, Err(Error::NetworkUnreachable(_))));
    }

    /// TcpHostPort timeout/unrouteable path.
    #[tokio::test]
    async fn connect_timeout_tcphostport() {
        let target = BindAddr::TcpHostPort {
            host: "192.0.2.2".into(),
            port: 65001,
        };
        let r = connect_target(&target, Some(Duration::from_millis(50))).await;
        assert!(matches!(r, Err(Error::NetworkUnreachable(_))));
    }

    /// DNS resolution failure: ".invalid" TLD is reserved (RFC 6761).
    #[tokio::test]
    async fn dns_failure_returns_network_unreachable() {
        let target = BindAddr::TcpHostPort {
            host: "no-such-host.invalid".into(),
            port: 22,
        };
        let r = connect_target(&target, Some(Duration::from_secs(2))).await;
        match r {
            Err(Error::NetworkUnreachable(msg)) => {
                assert!(msg.contains("no-such-host.invalid"));
            }
            other => panic!("expected NetworkUnreachable, got {other:?}"),
        }
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
}
