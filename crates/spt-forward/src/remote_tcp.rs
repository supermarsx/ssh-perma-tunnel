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
}
