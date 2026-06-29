//! Connect dispatcher — plain TCP vs obfuscated.
//!
//! `connect_to_endpoint` is the single entry point used by both the russh
//! and libssh2 paths. It returns a duplex byte stream that the SSH client
//! then handshakes over.
//!
//! ## Layout
//!
//! * No obfuscation configured (`obfs_cfg.is_none()`): direct `TcpStream::connect`.
//! * Obfuscation configured: delegate to `spt_obfs::transport_for` and
//!   call `ObfsTransport::connect`. The audit hook fires from inside the
//!   obfuscation crate.
//!
//! The function is intentionally async + cancellation-safe — the supervisor
//! attaches the connect timeout via `tokio::time::timeout`.

use std::sync::Arc;

use spt_core::{Error, Result};
use spt_obfs::transport::AsyncReadWrite;
use spt_obfs::{transport_for_with_secret, AuditHook, NoopAuditHook, ObfsConfig};
use tokio::net::TcpStream;

/// Outcome of a connect attempt.
///
/// The enum lets the SSH client pick its handshake path: `Plain` lands a
/// concrete `TcpStream` (preserving any `socket2` tuning the legacy path
/// applies), while `Obfuscated` returns the type-erased async stream.
pub enum ConnectStream {
    /// Direct TCP connection.
    Plain(TcpStream),
    /// Obfuscated stream — already handshaken at the obfuscation layer.
    Obfuscated(Box<dyn AsyncReadWrite>),
}

impl ConnectStream {
    /// Static transport identifier for logs / metrics.
    #[must_use]
    pub fn transport_name(&self) -> &'static str {
        match self {
            ConnectStream::Plain(_) => "tcp",
            ConnectStream::Obfuscated(_) => "obfs",
        }
    }
}

/// Connect to `target` (canonical `host:port`), optionally through an
/// obfuscation transport.
///
/// `obfs_cfg = None` selects the legacy plain-TCP path.
///
/// `obfs_secret` carries the already-resolved obfs secret (currently only the
/// Shadowsocks `password`). The caller resolves the transport's
/// [`ObfsConfig::password_ref`] through the secrets backend chain — the same
/// chain the SSH auth path uses — and passes the resulting bytes here. The
/// bytes are threaded into the transport so a `secret://`/`file://`-backed
/// Shadowsocks password actually keys the AEAD framing. Transports that need
/// no secret ignore it.
pub async fn connect_to_endpoint(
    target: &str,
    obfs_cfg: Option<&ObfsConfig>,
    audit: Option<Arc<dyn AuditHook>>,
    obfs_secret: Option<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<ConnectStream> {
    match obfs_cfg {
        None => {
            let sock = TcpStream::connect(target)
                .await
                .map_err(|e| Error::NetworkUnreachable(format!("tcp connect {target}: {e}")))?;
            Ok(ConnectStream::Plain(sock))
        }
        Some(cfg) => {
            let audit = audit.unwrap_or_else(|| Arc::new(NoopAuditHook));
            let mut transport = transport_for_with_secret(cfg, audit, obfs_secret)?;
            let stream = transport.connect(target).await?;
            Ok(ConnectStream::Obfuscated(stream))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_obfs::audit::MockAuditHook;
    use spt_obfs::ObfsConfig as Cfg;

    #[tokio::test]
    async fn plain_path_returns_plain_variant() {
        // We can't dial real TCP in this unit test, but we can drive the
        // None branch to the point where it would call TcpStream::connect
        // by passing a clearly-bad target — the error type confirms we
        // took the plain path.
        let r = connect_to_endpoint("127.0.0.1:1", None, None, None).await;
        match r {
            Err(Error::NetworkUnreachable(_)) | Ok(ConnectStream::Plain(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("unexpected non-Plain ConnectStream"),
        }
    }

    #[tokio::test]
    async fn obfuscated_path_routes_to_dispatcher_and_fires_audit() {
        let cfg = Cfg::Obfs4 {
            node_id: [1; 20],
            public_key: [2; 32],
            iat_mode: 0,
        };
        let audit = Arc::new(MockAuditHook::new());
        let _ = connect_to_endpoint("x:22", Some(&cfg), Some(audit.clone()), None).await;
        let entries = audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "obfs4");
        assert_eq!(entries[0].1, "x:22");
    }
}
