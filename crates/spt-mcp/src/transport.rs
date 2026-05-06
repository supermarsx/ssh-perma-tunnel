//! JSON-RPC transports for the MCP server.
//!
//! Two transports are supported:
//!
//! - [`stdio::StdioTransport`] — line-delimited JSON-RPC over stdin/stdout
//!   (single connection).
//! - [`loopback::LoopbackTransport`] — JSON-RPC-over-TCP bound to a loopback
//!   address (`127.0.0.1` / `[::1]`), accepting multiple concurrent clients.
//!
//! All transports produce/consume newline-delimited JSON-RPC frames using the
//! shared [`read_request`] / [`write_response`] helpers.
//!
//! # Server selection
//!
//! [`McpPolicy`](crate::policy::McpPolicy) carries a [`TransportConfig`] that
//! tells the binary which transport to construct. The two transports
//! implement the [`Transport`] trait so [`crate::server::McpServer::run`]
//! is transport-agnostic.

use crate::protocol::{Request, Response};
use crate::server::McpServerInner;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// Transport variant marker. Used by config and metrics labelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// Line-delimited JSON-RPC over stdin/stdout.
    Stdio,
    /// Loopback TCP — multiple concurrent clients.
    #[serde(alias = "loopback_tcp")]
    Loopback,
}

impl Default for TransportKind {
    fn default() -> Self {
        Self::Stdio
    }
}

/// Loopback TCP bind config (`[mcp.loopback_tcp]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoopbackConfig {
    /// Address to bind. Must resolve to a loopback IP.
    pub bind: String,
}

impl Default for LoopbackConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:7777".to_owned(),
        }
    }
}

/// Top-level transport selection in `[mcp]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    /// Transport variant.
    pub transport: TransportKind,
    /// Loopback-TCP bind details (only honoured when `transport == Loopback`).
    pub loopback_tcp: LoopbackConfig,
}

/// Transport-agnostic interface implemented by `stdio` and loopback TCP.
///
/// Each implementation owns its own accept/dispatch loop and uses the shared
/// [`McpServerInner`] for request handling. Loopback spawns one task per
/// accepted connection; stdio runs the single connection inline.
#[async_trait]
pub trait Transport: Send + 'static {
    /// Drive the transport until it closes (EOF on stdio; ctrl-c / shutdown
    /// on loopback). Errors here propagate up to `spt-bin`.
    async fn serve(self, inner: Arc<McpServerInner>) -> crate::Result<()>;
}

/// Read one JSON-RPC request from a buffered reader. Returns `Ok(None)` on
/// clean EOF.
pub async fn read_request<R>(reader: &mut R) -> crate::Result<Option<Request>>
where
    R: AsyncBufReadExt + Unpin,
{
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        // Empty line — treat as no request, ask caller to loop.
        return Ok(Some(Request {
            jsonrpc: "2.0".to_owned(),
            id: None,
            method: String::new(),
            params: None,
        }));
    }
    let req = serde_json::from_str::<Request>(trimmed)?;
    Ok(Some(req))
}

/// Write one JSON-RPC response, followed by a newline and a flush.
pub async fn write_response<W>(writer: &mut W, response: &Response) -> crate::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = serde_json::to_vec(response)?;
    writer.write_all(&body).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

/// Write a JSON-RPC notification (server→client, no `id`).
pub async fn write_notification<W>(
    writer: &mut W,
    method: &str,
    params: Value,
) -> crate::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let note = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    });
    let body = serde_json::to_vec(&note)?;
    writer.write_all(&body).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

/// Drive a single newline-framed JSON-RPC peer to completion.
///
/// The caller supplies any `AsyncBufRead + AsyncWrite` pair. Used by both
/// stdio and the per-connection task of the loopback transport.
pub async fn run_connection<R, W>(
    inner: Arc<McpServerInner>,
    reader: &mut R,
    writer: &mut W,
) -> crate::Result<()>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let req = match read_request(reader).await? {
            None => break,                              // EOF
            Some(r) if r.method.is_empty() => continue, // empty line
            Some(r) => r,
        };
        if req.is_notification() {
            inner.note(&req);
            continue;
        }
        let response = inner.dispatch(req).await;
        write_response(writer, &response).await?;
    }
    writer.flush().await?;
    Ok(())
}

/// Stdio transport.
pub mod stdio {
    use super::{run_connection, McpServerInner, Transport};
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::io::{stdin, stdout, BufReader};

    /// Line-delimited JSON-RPC over stdin/stdout. Single connection.
    #[derive(Debug, Default)]
    pub struct StdioTransport;

    impl StdioTransport {
        /// Construct a new stdio transport.
        #[must_use]
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl Transport for StdioTransport {
        async fn serve(self, inner: Arc<McpServerInner>) -> crate::Result<()> {
            let mut reader = BufReader::new(stdin());
            let mut writer = stdout();
            run_connection(inner, &mut reader, &mut writer).await
        }
    }
}

/// Loopback TCP transport.
pub mod loopback {
    use super::{run_connection, McpServerInner, Transport};
    use async_trait::async_trait;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::BufReader;
    use tokio::net::TcpListener;

    /// JSON-RPC server bound to a loopback TCP address.
    ///
    /// Refuses any non-loopback peer with [`crate::Error::PolicyDenied`] and
    /// drops the connection without dispatching the frame. Each accepted
    /// connection is handled on its own task so concurrent clients are
    /// supported.
    pub struct LoopbackTransport {
        listener: TcpListener,
    }

    impl LoopbackTransport {
        /// Bind to the requested address.
        ///
        /// Returns [`crate::Error::PolicyDenied`] if `addr` does not resolve
        /// to a loopback IP — the transport refuses to listen on a routable
        /// interface.
        pub async fn bind(addr: &str) -> crate::Result<Self> {
            let parsed: SocketAddr = addr.parse().map_err(|e| {
                crate::Error::InvalidParams(format!("invalid loopback bind '{addr}': {e}"))
            })?;
            if !parsed.ip().is_loopback() {
                return Err(crate::Error::PolicyDenied(format!(
                    "refusing to bind MCP loopback transport on non-loopback address {parsed}"
                )));
            }
            let listener = TcpListener::bind(parsed).await?;
            Ok(Self { listener })
        }

        /// Address the listener is actually bound to (useful when the caller
        /// requested an OS-assigned port via `:0`).
        pub fn local_addr(&self) -> crate::Result<SocketAddr> {
            Ok(self.listener.local_addr()?)
        }
    }

    #[async_trait]
    impl Transport for LoopbackTransport {
        async fn serve(self, inner: Arc<McpServerInner>) -> crate::Result<()> {
            loop {
                let (stream, peer) = self.listener.accept().await?;
                if !peer.ip().is_loopback() {
                    tracing::warn!(
                        peer = %peer,
                        "refusing non-loopback peer on MCP loopback transport"
                    );
                    drop(stream);
                    continue;
                }
                let inner = inner.clone();
                tokio::spawn(async move {
                    let (read_half, mut write_half) = stream.into_split();
                    let mut reader = BufReader::new(read_half);
                    if let Err(e) = run_connection(inner, &mut reader, &mut write_half).await {
                        tracing::warn!(peer = %peer, error = %e, "MCP loopback connection ended with error");
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_config_round_trips_loopback_alias() {
        let json = serde_json::json!({
            "transport": "loopback_tcp",
            "loopback_tcp": {"bind": "127.0.0.1:0"}
        });
        let cfg: TransportConfig = serde_json::from_value(json).unwrap();
        assert!(matches!(cfg.transport, TransportKind::Loopback));
        assert_eq!(cfg.loopback_tcp.bind, "127.0.0.1:0");
    }

    #[test]
    fn transport_kind_default_is_stdio() {
        assert_eq!(TransportKind::default(), TransportKind::Stdio);
    }

    #[tokio::test]
    async fn loopback_bind_rejects_non_loopback() {
        let res = loopback::LoopbackTransport::bind("0.0.0.0:0").await;
        assert!(matches!(res, Err(crate::Error::PolicyDenied(_))));
    }

    #[tokio::test]
    async fn loopback_bind_accepts_v4_loopback() {
        let t = loopback::LoopbackTransport::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = t.local_addr().expect("local_addr");
        assert!(addr.ip().is_loopback());
    }
}
