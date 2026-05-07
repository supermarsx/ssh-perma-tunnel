//! Test facilities for `spt-mcp`.
//!
//! Re-exports the in-memory [`RecordingController`] and the existing
//! [`MockAuditSink`] under one module, plus a [`RecordingTransport`] that
//! captures every JSON-RPC frame on the wire and exposes
//! `client_send` / `client_recv` so tests can drive the server like a real
//! client would. Combined with [`make_test_server`] this is enough to exercise
//! the full `initialize` → `resources/list` → `tools/list` → `tools/call` flow
//! end-to-end without spawning an OS process or binding a TCP socket.
//!
//! ```no_run
//! use spt_mcp::testing::{make_test_server, handshake};
//!
//! # async fn demo() -> spt_mcp::Result<()> {
//! let mut h = make_test_server();
//! let server_task = tokio::spawn(h.server.run(h.transport));
//! let init = handshake(&mut h.client).await?;
//! assert_eq!(init.protocol_version, "2024-11-05");
//! drop(h.client);                     // close → server task exits
//! let _ = server_task.await;
//! # Ok(()) }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::Mutex as AsyncMutex;

use crate::policy::{McpPolicy, Policy};
use crate::protocol::{Response, ToolDescriptor};
use crate::server::{McpServer, McpServerInner};
use crate::sources::{DynConfigSource, DynStateSource};
use crate::transport::{run_connection, Transport};

pub use crate::audit::test_support::MockAuditSink;
pub use crate::controller::testing::{ControllerCall, RecordingController};
pub use crate::sources::NoopSources;

/// One captured frame on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Frame {
    /// Frame sent client → server.
    ClientToServer(String),
    /// Frame sent server → client.
    ServerToClient(String),
}

/// In-memory transport built around a pair of `tokio::io::DuplexStream`s.
///
/// One end is owned by the [`McpServer`] (the server reads requests + writes
/// responses). The other end is owned by the test (a [`TransportClientHandle`]).
/// Every frame that crosses the wire is appended to `observed` so the test can
/// inspect the protocol after the run.
pub struct RecordingTransport {
    server_stream: DuplexStream,
    observed: Arc<Mutex<Vec<Frame>>>,
}

impl RecordingTransport {
    /// Snapshot of frames seen on this transport so far.
    #[must_use]
    pub fn observed(&self) -> Vec<Frame> {
        self.observed.lock().clone()
    }
}

#[async_trait]
impl Transport for RecordingTransport {
    async fn serve(self, inner: Arc<McpServerInner>) -> crate::Result<()> {
        let (read_half, write_half) = tokio::io::split(self.server_stream);
        let mut reader = BufReader::new(read_half);
        let mut writer = TapWriter {
            inner: write_half,
            observed: self.observed.clone(),
        };
        run_connection(inner, &mut reader, &mut writer).await
    }
}

/// Wrapper that captures every fully-written buffer as a
/// [`Frame::ServerToClient`].
struct TapWriter {
    inner: WriteHalf<DuplexStream>,
    observed: Arc<Mutex<Vec<Frame>>>,
}

impl tokio::io::AsyncWrite for TapWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let res = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                let chunk = String::from_utf8_lossy(&buf[..*n]).into_owned();
                self.observed.lock().push(Frame::ServerToClient(chunk));
            }
        }
        res
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Test-side handle that drives the [`RecordingTransport`].
///
/// `client_send` writes one JSON value followed by a newline and records it
/// as a [`Frame::ClientToServer`]. `client_recv` reads one newline-delimited
/// JSON response and parses it.
pub struct TransportClientHandle {
    reader: AsyncMutex<BufReader<ReadHalf<DuplexStream>>>,
    writer: AsyncMutex<WriteHalf<DuplexStream>>,
    observed: Arc<Mutex<Vec<Frame>>>,
    next_id: AsyncMutex<i64>,
}

impl TransportClientHandle {
    /// Send one request frame. The body is serialized to one line of JSON.
    pub async fn client_send(&self, value: &Value) -> crate::Result<()> {
        let body = serde_json::to_string(value)?;
        self.observed
            .lock()
            .push(Frame::ClientToServer(format!("{body}\n")));
        let mut w = self.writer.lock().await;
        w.write_all(body.as_bytes()).await?;
        w.write_all(b"\n").await?;
        w.flush().await?;
        Ok(())
    }

    /// Receive exactly one newline-delimited response frame.
    pub async fn client_recv(&self) -> crate::Result<Response> {
        let mut r = self.reader.lock().await;
        let mut line = String::new();
        let n = r.read_line(&mut line).await?;
        if n == 0 {
            return Err(crate::Error::Internal("transport closed".into()));
        }
        let resp: Response = serde_json::from_str(line.trim())?;
        Ok(resp)
    }

    /// Issue an RPC by method name and await one response. Auto-increments id.
    pub async fn rpc(&self, method: &str, params: Value) -> crate::Result<Response> {
        let id = {
            let mut g = self.next_id.lock().await;
            let v = *g;
            *g += 1;
            v
        };
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        self.client_send(&req).await?;
        self.client_recv().await
    }

    /// Snapshot of frames observed on the underlying transport.
    #[must_use]
    pub fn observed(&self) -> Vec<Frame> {
        self.observed.lock().clone()
    }
}

/// Result of [`make_test_server`] — a wired-up server and a paired client.
pub struct TestServerHarness {
    /// The server, ready to be driven via `server.run(harness.transport)`.
    pub server: McpServer,
    /// The recording transport. Pass to `server.run`.
    pub transport: RecordingTransport,
    /// The test-side client handle.
    pub client: TransportClientHandle,
    /// Recording controller (clone before passing for inspection if desired).
    pub controller: RecordingController,
    /// In-memory audit sink (clone for inspection).
    pub audit: MockAuditSink,
}

/// Build a ready-to-run MCP server with all-in-memory dependencies and a
/// connected [`RecordingTransport`]. The returned policy has `enabled = true`
/// and the full set of mutating tools allow-listed so tests can exercise the
/// write path without an extra builder step.
///
/// ```no_run
/// use spt_mcp::testing::make_test_server;
/// let h = make_test_server();
/// assert_eq!(h.audit.snapshot().len(), 0);
/// ```
#[must_use]
pub fn make_test_server() -> TestServerHarness {
    let policy = McpPolicy {
        enabled: true,
        allow_write_tools: crate::policy::WRITE_TOOLS.iter().map(|s| (*s).to_owned()).collect(),
        ..Default::default()
    };
    let audit = MockAuditSink::new();
    let controller = RecordingController::new();
    let sources = Arc::new(NoopSources);
    let server = McpServer::new(
        Policy::new(policy),
        Arc::new(audit.clone()),
        Arc::new(controller.clone()),
        sources.clone() as DynConfigSource,
        sources as DynStateSource,
    );

    let (server_end, client_end) = tokio::io::duplex(64 * 1024);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        server_stream: server_end,
        observed: observed.clone(),
    };
    let (cr, cw) = tokio::io::split(client_end);
    let client = TransportClientHandle {
        reader: AsyncMutex::new(BufReader::new(cr)),
        writer: AsyncMutex::new(cw),
        observed,
        next_id: AsyncMutex::new(1),
    };

    TestServerHarness {
        server,
        transport,
        client,
        controller,
        audit,
    }
}

/// Minimal `initialize` response shape used by [`handshake`].
#[derive(Debug, Clone, Deserialize)]
pub struct InitializeResponse {
    /// Echoed protocol version, e.g. `"2024-11-05"`.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Server identity block.
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

/// `serverInfo` block returned by `initialize`.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerInfo {
    /// Server name.
    pub name: String,
    /// Server version.
    pub version: String,
}

/// Drive the standard MCP `initialize` exchange and return the parsed result.
///
/// ```no_run
/// use spt_mcp::testing::{make_test_server, handshake};
/// # async fn demo() -> spt_mcp::Result<()> {
/// let mut h = make_test_server();
/// let server_task = tokio::spawn(h.server.run(h.transport));
/// let init = handshake(&mut h.client).await?;
/// assert_eq!(init.protocol_version, "2024-11-05");
/// drop(h.client);
/// let _ = server_task.await;
/// # Ok(()) }
/// ```
pub async fn handshake(client: &mut TransportClientHandle) -> crate::Result<InitializeResponse> {
    let resp = client
        .rpc(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "spt-mcp-test-client", "version": "0.0.0"},
                "capabilities": {}
            }),
        )
        .await?;
    if let Some(err) = resp.error {
        return Err(crate::Error::Internal(format!(
            "initialize failed: code={} message={}",
            err.code, err.message
        )));
    }
    let result = resp
        .result
        .ok_or_else(|| crate::Error::Internal("initialize: missing result".into()))?;
    let parsed: InitializeResponse = serde_json::from_value(result)
        .map_err(|e| crate::Error::Internal(format!("initialize: parse: {e}")))?;
    Ok(parsed)
}

/// Convenience assertion: a tool with the given name is present.
///
/// ```
/// # use spt_mcp::protocol::ToolDescriptor;
/// # use serde_json::json;
/// use spt_mcp::testing::assert_tool_listed;
/// let tools = vec![ToolDescriptor {
///     name: "tunnel_status".into(),
///     description: "x".into(),
///     input_schema: json!({}),
/// }];
/// assert_tool_listed(&tools, "tunnel_status");
/// ```
pub fn assert_tool_listed(tools: &[ToolDescriptor], name: &str) {
    assert!(
        tools.iter().any(|t| t.name == name),
        "tool `{name}` not present; available={:?}",
        tools.iter().map(|t| &t.name).collect::<Vec<_>>()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handshake_then_resources_and_tools() {
        let h = make_test_server();
        let server_task = tokio::spawn(h.server.run(h.transport));
        let mut client = h.client;

        let init = handshake(&mut client).await.expect("init");
        assert_eq!(init.protocol_version, "2024-11-05");
        assert_eq!(init.server_info.name, "spt-mcp");

        let r = client
            .rpc("resources/list", serde_json::json!({}))
            .await
            .unwrap();
        let resources = r.result.unwrap()["resources"].as_array().cloned().unwrap();
        assert_eq!(resources.len(), 16);

        let r = client
            .rpc("tools/list", serde_json::json!({}))
            .await
            .unwrap();
        let tools_v = r.result.unwrap()["tools"].clone();
        let tools: Vec<ToolDescriptor> = serde_json::from_value(tools_v).unwrap();
        assert_eq!(tools.len(), crate::tools::ALL_TOOL_NAMES.len());
        assert_tool_listed(&tools, "tunnel_status");

        drop(client);
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn write_denied_without_allow_list() {
        // Build a server with empty allow_write_tools.
        let policy = McpPolicy {
            enabled: true,
            allow_write_tools: Vec::new(),
            ..Default::default()
        };
        let sources = Arc::new(NoopSources);
        let server = McpServer::new(
            Policy::new(policy),
            Arc::new(MockAuditSink::new()),
            Arc::new(RecordingController::new()),
            sources.clone() as DynConfigSource,
            sources as DynStateSource,
        );
        let (server_end, client_end) = tokio::io::duplex(64 * 1024);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let transport = RecordingTransport {
            server_stream: server_end,
            observed: observed.clone(),
        };
        let (cr, cw) = tokio::io::split(client_end);
        let mut client = TransportClientHandle {
            reader: AsyncMutex::new(BufReader::new(cr)),
            writer: AsyncMutex::new(cw),
            observed,
            next_id: AsyncMutex::new(1),
        };
        let task = tokio::spawn(server.run(transport));
        let _ = handshake(&mut client).await.unwrap();
        let r = client
            .rpc(
                "tools/call",
                serde_json::json!({
                    "name": "forward_add",
                    "arguments": {"profile": "p", "forward": {"name":"x","type":"local","transport":"tcp"}}
                }),
            )
            .await
            .unwrap();
        assert!(r.error.is_some(), "expected error response");
        let err = r.error.unwrap();
        assert_eq!(err.code, -32001, "expected PolicyDenied code");
        drop(client);
        let _ = task.await;
    }
}
