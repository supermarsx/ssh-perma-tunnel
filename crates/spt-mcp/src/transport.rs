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

/// Outcome of reading one frame in the resilient connection loop (E8-F15).
///
/// Unlike [`read_request`], a malformed JSON line does **not** abort the
/// connection: it is surfaced as [`FrameRead::ParseError`] so the loop can
/// answer a JSON-RPC `-32700` and keep serving subsequent frames.
enum FrameRead {
    /// A well-formed request frame (may be a blank/notification line).
    Request(Request),
    /// The line was not valid JSON-RPC; the loop should reply `-32700` and
    /// continue. Carries the parser message for diagnostics.
    ParseError(String),
    /// Clean EOF — the loop should exit.
    Eof,
}

/// Read one frame, mapping a malformed line to [`FrameRead::ParseError`]
/// rather than propagating an error that tears down the connection.
async fn read_frame<R>(reader: &mut R) -> crate::Result<FrameRead>
where
    R: AsyncBufReadExt + Unpin,
{
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(FrameRead::Eof);
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(FrameRead::Request(Request {
            jsonrpc: "2.0".to_owned(),
            id: None,
            method: String::new(),
            params: None,
        }));
    }
    match serde_json::from_str::<Request>(trimmed) {
        Ok(req) => Ok(FrameRead::Request(req)),
        Err(e) => Ok(FrameRead::ParseError(e.to_string())),
    }
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
pub async fn write_notification<W>(writer: &mut W, method: &str, params: Value) -> crate::Result<()>
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
    run_connection_inner(inner, reader, writer, /* with_notify */ false).await
}

/// Same as [`run_connection`] but multiplexes server→client JSON-RPC
/// notifications onto the same writer. Streaming tools (e.g.
/// `stats_subscribe`) push values onto a per-connection mpsc; this loop
/// drains the channel as `notifications/stats/tick` frames between
/// inbound requests.
pub async fn run_connection_with_notifications<R, W>(
    inner: Arc<McpServerInner>,
    reader: &mut R,
    writer: &mut W,
) -> crate::Result<()>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWrite + Unpin,
{
    run_connection_inner(inner, reader, writer, /* with_notify */ true).await
}

/// Maximum rejected `initialize` attempts before a connection is dropped
/// (E8-F15). Loopback-mitigated, but bounds token-guess grinding on a single
/// socket.
const MAX_FAILED_INITIALIZES: u32 = 5;

async fn run_connection_inner<R, W>(
    inner: Arc<McpServerInner>,
    reader: &mut R,
    writer: &mut W,
    with_notify: bool,
) -> crate::Result<()>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::sync::mpsc;
    let (notify_tx, mut notify_rx) = mpsc::channel::<Value>(64);
    // Track whether `initialize` has succeeded for this connection. When the
    // server has an auth token configured, every other method is rejected
    // until initialize succeeds.
    let mut initialized = false;
    let needs_token = inner.auth_token().is_some();
    // Cap failed `initialize` attempts per connection (E8-F15). On a
    // token-gated loopback listener an unbounded retry loop lets a local peer
    // grind through token guesses on one socket; after this many rejected
    // initializes we drop the connection (loopback-mitigated, but cheap to
    // bound). Successful initialize resets the budget implicitly by setting
    // `initialized = true`, after which this counter is no longer consulted.
    let mut failed_initializes: u32 = 0;
    loop {
        tokio::select! {
            biased;
            // Drain pending notifications first so they are not delayed by a
            // long-running request read.
            maybe_payload = notify_rx.recv(), if with_notify => {
                match maybe_payload {
                    Some(payload) => {
                        write_notification(writer, "notifications/stats/tick", payload).await?;
                    }
                    None => {
                        // All notify_tx senders have dropped. This shouldn't
                        // happen — we hold the original — but treat it as a
                        // disabled arm rather than a loop exit.
                        tracing::trace!("notify_rx returned None — channel closed");
                    }
                }
            }
            frame = read_frame(reader) => {
                let req = match frame? {
                    FrameRead::Eof => {
                        tracing::trace!("read_frame: EOF — closing connection");
                        break;
                    }
                    // Malformed JSON: answer JSON-RPC -32700 and keep the
                    // connection alive (E8-F15). The id is unknown, so per
                    // JSON-RPC we reply with a null id.
                    FrameRead::ParseError(msg) => {
                        tracing::debug!(error = %msg, "MCP frame parse error — replying -32700, continuing");
                        let resp = crate::protocol::Response::err(
                            crate::protocol::Id::Null,
                            -32700,
                            format!("parse error: {msg}"),
                        );
                        write_response(writer, &resp).await?;
                        continue;
                    }
                    FrameRead::Request(r) if r.method.is_empty() => continue,
                    FrameRead::Request(r) => r,
                };
                if req.is_notification() {
                    inner.note(&req);
                    continue;
                }
                if needs_token && !initialized && req.method != "initialize" {
                    let resp = crate::protocol::Response::err(
                        req.id.clone().unwrap_or(crate::protocol::Id::Null),
                        crate::Error::PolicyDenied("not initialized".to_owned()).rpc_code(),
                        "MCP loopback requires authenticated initialize",
                    );
                    write_response(writer, &resp).await?;
                    break;
                }
                let is_init = req.method == "initialize";
                let notify_for_call = if with_notify { Some(notify_tx.clone()) } else { None };
                let response = inner.dispatch_with_notify(req, notify_for_call).await;
                let success = response.error.is_none();
                write_response(writer, &response).await?;
                if is_init {
                    if success {
                        initialized = true;
                    } else {
                        // Cap failed initialize attempts per connection
                        // (E8-F15) — drop after too many rejected tokens.
                        failed_initializes += 1;
                        if failed_initializes >= MAX_FAILED_INITIALIZES {
                            tracing::warn!(
                                attempts = failed_initializes,
                                "too many failed MCP initialize attempts — closing connection"
                            );
                            break;
                        }
                    }
                }
            }
        }
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
    use super::{McpServerInner, Transport};
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
                    if let Err(e) = super::run_connection_with_notifications(
                        inner,
                        &mut reader,
                        &mut write_half,
                    )
                    .await
                    {
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

    #[test]
    fn transport_kind_round_trips_stdio() {
        let json = serde_json::json!({"transport": "stdio"});
        let cfg: TransportConfig = serde_json::from_value(json).unwrap();
        assert!(matches!(cfg.transport, TransportKind::Stdio));
    }

    #[test]
    fn transport_kind_round_trips_canonical_loopback() {
        let json = serde_json::json!({"transport": "loopback"});
        let cfg: TransportConfig = serde_json::from_value(json).unwrap();
        assert!(matches!(cfg.transport, TransportKind::Loopback));
    }

    #[test]
    fn loopback_config_default_127_7777() {
        let lc = LoopbackConfig::default();
        assert_eq!(lc.bind, "127.0.0.1:7777");
    }

    #[test]
    fn transport_config_default_is_stdio_with_default_loopback() {
        let cfg = TransportConfig::default();
        assert!(matches!(cfg.transport, TransportKind::Stdio));
        assert_eq!(cfg.loopback_tcp.bind, "127.0.0.1:7777");
    }

    #[test]
    fn transport_kind_eq_and_copy() {
        let a = TransportKind::Loopback;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(TransportKind::Stdio, TransportKind::Loopback);
    }

    #[tokio::test]
    async fn read_request_returns_none_on_eof() {
        let cursor = std::io::Cursor::new(Vec::<u8>::new());
        let mut reader = tokio::io::BufReader::new(cursor);
        let req = read_request(&mut reader).await.unwrap();
        assert!(req.is_none());
    }

    #[tokio::test]
    async fn read_request_empty_line_returns_blank_request() {
        let cursor = std::io::Cursor::new(b"\n".to_vec());
        let mut reader = tokio::io::BufReader::new(cursor);
        let req = read_request(&mut reader).await.unwrap().unwrap();
        assert!(req.method.is_empty());
        assert!(req.id.is_none());
    }

    #[tokio::test]
    async fn read_request_parses_one_frame() {
        let cursor = std::io::Cursor::new(
            br#"{"jsonrpc":"2.0","id":1,"method":"ping"}
"#
            .to_vec(),
        );
        let mut reader = tokio::io::BufReader::new(cursor);
        let req = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.method, "ping");
        assert!(req.id.is_some());
    }

    #[tokio::test]
    async fn read_request_invalid_json_errors() {
        let cursor = std::io::Cursor::new(b"{not json\n".to_vec());
        let mut reader = tokio::io::BufReader::new(cursor);
        let err = read_request(&mut reader).await.unwrap_err();
        assert!(matches!(err, crate::Error::Json(_)));
    }

    #[tokio::test]
    async fn write_response_emits_line_then_newline() {
        let resp = Response::ok(crate::protocol::Id::Num(7), serde_json::json!({"ok": true}));
        let mut buf = Vec::<u8>::new();
        write_response(&mut buf, &resp).await.unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.ends_with('\n'));
        let parsed: Response = serde_json::from_str(s.trim()).unwrap();
        assert!(matches!(parsed.id, crate::protocol::Id::Num(7)));
        assert!(parsed.result.is_some());
    }

    #[tokio::test]
    async fn write_notification_has_no_id_field() {
        let mut buf = Vec::<u8>::new();
        write_notification(&mut buf, "x/y", serde_json::json!({"tick": 1}))
            .await
            .unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], "x/y");
        assert_eq!(v["params"]["tick"], 1);
        assert!(v.get("id").is_none());
    }

    #[tokio::test]
    async fn loopback_bind_invalid_address_errors() {
        let res = loopback::LoopbackTransport::bind("not::an::addr").await;
        assert!(matches!(res, Err(crate::Error::InvalidParams(_))));
    }

    #[tokio::test]
    async fn loopback_bind_v6_loopback_ok() {
        let res = loopback::LoopbackTransport::bind("[::1]:0").await;
        match res {
            Ok(t) => assert!(t.local_addr().unwrap().ip().is_loopback()),
            Err(crate::Error::Io(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_connection_closes_cleanly_on_eof() {
        use crate::audit::NoopAuditSink;
        use crate::controller::NoopController;
        use crate::policy::{McpPolicy, Policy};
        use crate::server::McpServer;
        use crate::sources::NoopSources;
        let sources = Arc::new(NoopSources);
        let server = McpServer::new(
            Policy::new(McpPolicy {
                enabled: true,
                ..Default::default()
            }),
            Arc::new(NoopAuditSink),
            Arc::new(NoopController),
            sources.clone() as crate::sources::DynConfigSource,
            sources as crate::sources::DynStateSource,
        );
        let inner = server.inner();

        let cursor = std::io::Cursor::new(Vec::<u8>::new());
        let mut reader = tokio::io::BufReader::new(cursor);
        let mut writer: Vec<u8> = Vec::new();
        run_connection(inner, &mut reader, &mut writer)
            .await
            .unwrap();
        assert!(writer.is_empty());
    }

    /// A malformed JSON frame must NOT tear down the connection: the loop
    /// answers JSON-RPC -32700 and keeps serving subsequent frames (E8-F15).
    #[tokio::test]
    async fn parse_error_frame_does_not_kill_session() {
        use crate::audit::NoopAuditSink;
        use crate::controller::NoopController;
        use crate::policy::{McpPolicy, Policy};
        use crate::server::McpServer;
        use crate::sources::NoopSources;
        let sources = Arc::new(NoopSources);
        let server = McpServer::new(
            Policy::new(McpPolicy {
                enabled: true,
                ..Default::default()
            }),
            Arc::new(NoopAuditSink),
            Arc::new(NoopController),
            sources.clone() as crate::sources::DynConfigSource,
            sources as crate::sources::DynStateSource,
        );
        let inner = server.inner();

        // Frame 1: garbage. Frame 2: a valid ping. The session must answer
        // both and then close cleanly on EOF.
        let body =
            b"{not json at all\n{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n".to_vec();
        let cursor = std::io::Cursor::new(body);
        let mut reader = tokio::io::BufReader::new(cursor);
        let mut writer: Vec<u8> = Vec::new();
        run_connection(inner, &mut reader, &mut writer)
            .await
            .expect("a parse error must not propagate out of the connection");

        let out = String::from_utf8(writer).unwrap();
        let mut lines = out.lines();
        let first: Response =
            serde_json::from_str(lines.next().expect("parse-error reply")).unwrap();
        let err = first.error.expect("first frame is an error reply");
        assert_eq!(
            err.code, -32700,
            "malformed frame answered with parse error"
        );
        let second: Response =
            serde_json::from_str(lines.next().expect("ping reply after parse error")).unwrap();
        assert!(second.error.is_none(), "ping after parse error succeeds");
        assert_eq!(second.result.unwrap()["pong"], true);
    }

    /// A token-gated connection drops after too many failed initialize
    /// attempts rather than looping forever (E8-F15).
    #[tokio::test]
    async fn failed_initializes_are_capped() {
        use crate::audit::NoopAuditSink;
        use crate::controller::NoopController;
        use crate::policy::{McpPolicy, Policy};
        use crate::server::McpServer;
        use crate::sources::NoopSources;
        let sources = Arc::new(NoopSources);
        let server = McpServer::new(
            Policy::new(McpPolicy {
                enabled: true,
                ..Default::default()
            }),
            Arc::new(NoopAuditSink),
            Arc::new(NoopController),
            sources.clone() as crate::sources::DynConfigSource,
            sources as crate::sources::DynStateSource,
        )
        .with_auth_token("correct-horse");
        let inner = server.inner();

        // Ten initialize attempts all carrying the wrong token. The loop must
        // give up well before draining all ten (cap is 5).
        let bad = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"token\":\"wrong\"}}\n";
        let body = bad.repeat(10).into_bytes();
        let cursor = std::io::Cursor::new(body);
        let mut reader = tokio::io::BufReader::new(cursor);
        let mut writer: Vec<u8> = Vec::new();
        run_connection(inner, &mut reader, &mut writer)
            .await
            .expect("capped close is not an error");
        let out = String::from_utf8(writer).unwrap();
        let replies = out.lines().count();
        assert!(
            replies <= 5,
            "expected the loop to drop after <=5 failed initializes, got {replies} replies"
        );
    }

    #[tokio::test]
    async fn run_connection_handles_notification_frames() {
        use crate::audit::NoopAuditSink;
        use crate::controller::NoopController;
        use crate::policy::{McpPolicy, Policy};
        use crate::server::McpServer;
        use crate::sources::NoopSources;
        let sources = Arc::new(NoopSources);
        let server = McpServer::new(
            Policy::new(McpPolicy {
                enabled: true,
                ..Default::default()
            }),
            Arc::new(NoopAuditSink),
            Arc::new(NoopController),
            sources.clone() as crate::sources::DynConfigSource,
            sources as crate::sources::DynStateSource,
        );
        let inner = server.inner();

        let body = br#"{"jsonrpc":"2.0","method":"some/notif"}
"#
        .to_vec();
        let cursor = std::io::Cursor::new(body);
        let mut reader = tokio::io::BufReader::new(cursor);
        let mut writer: Vec<u8> = Vec::new();
        run_connection(inner, &mut reader, &mut writer)
            .await
            .unwrap();
        assert!(writer.is_empty(), "notifications must not be replied to");
    }
}
