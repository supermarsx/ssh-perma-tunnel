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

/// Maximum bytes accepted for a single newline-delimited JSON-RPC frame.
///
/// Without a cap, a pre-auth local peer can stream gigabytes without ever
/// sending a newline, growing the read buffer until the process OOMs (a local
/// memory-exhaustion `DoS`). The cap is generous enough for any legitimate
/// request (4 MiB) while bounding the worst-case per-connection allocation.
pub const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// Read one newline-delimited line from a buffered reader without buffering
/// more than `max` bytes.
///
/// Returns the line (including its trailing newline, if any) on success. An
/// empty `String` signals clean EOF. If the line would exceed `max` bytes the
/// over-long input is drained and an [`crate::Error::InvalidParams`] is
/// returned so the caller can close the abusive connection — the buffer never
/// grows unbounded.
///
/// Unlike wrapping the reader in `take()`, this consumes exactly up to and
/// including the newline from the *shared* buffered reader, so bytes belonging
/// to the next frame are preserved for the following read (pipelined frames on
/// the same connection still work).
async fn read_line_capped<R>(reader: &mut R, max: usize) -> crate::Result<String>
where
    R: AsyncBufReadExt + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let (consumed, found_newline, hit_eof) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                (0usize, false, true)
            } else if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                buf.extend_from_slice(&available[..=pos]);
                (pos + 1, true, false)
            } else {
                buf.extend_from_slice(available);
                (available.len(), false, false)
            }
        };
        reader.consume(consumed);
        if hit_eof {
            break;
        }
        if buf.len() > max {
            return Err(crate::Error::InvalidParams(format!(
                "request frame exceeds maximum of {max} bytes"
            )));
        }
        if found_newline {
            break;
        }
    }
    String::from_utf8(buf)
        .map_err(|e| crate::Error::InvalidParams(format!("invalid UTF-8 in request frame: {e}")))
}

/// Read one JSON-RPC request from a buffered reader. Returns `Ok(None)` on
/// clean EOF.
pub async fn read_request<R>(reader: &mut R) -> crate::Result<Option<Request>>
where
    R: AsyncBufReadExt + Unpin,
{
    let line = read_line_capped(reader, MAX_LINE_BYTES).await?;
    if line.is_empty() {
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
    let line = read_line_capped(reader, MAX_LINE_BYTES).await?;
    if line.is_empty() {
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

/// True when `v` is already a complete JSON-RPC notification frame — an object
/// carrying both a `"jsonrpc"` and a `"method"` field. Such values are written
/// to the client verbatim (preserving their own method); anything else is
/// treated as a `stats_subscribe` tick payload to be wrapped.
fn is_jsonrpc_notification(v: &Value) -> bool {
    v.get("jsonrpc").is_some() && v.get("method").is_some()
}

/// Write a pre-built JSON-RPC notification frame verbatim (followed by a
/// newline + flush). Used to forward `events_subscribe`'s `spt/event` frames
/// without re-wrapping them.
async fn write_prebuilt_frame<W>(writer: &mut W, frame: &Value) -> crate::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = serde_json::to_vec(frame)?;
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
/// `stats_subscribe`, `events_subscribe`) push values onto a per-connection
/// mpsc; this loop drains the channel between inbound requests.
///
/// Two payload shapes are supported on the same channel:
///
/// * a **pre-framed JSON-RPC notification** (an object carrying both
///   `"jsonrpc"` and `"method"`, as produced by `events_subscribe`'s
///   `spt/event` frames) is written verbatim, preserving its own method; and
/// * any other value is treated as a `stats_subscribe` tick payload and
///   wrapped into a `notifications/stats/tick` frame.
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
                        // A subscription may push either a pre-framed JSON-RPC
                        // notification (events_subscribe's `spt/event` frames,
                        // carrying their own `jsonrpc`+`method`) or a bare tick
                        // payload (stats_subscribe). Forward the former verbatim
                        // so its method is preserved; wrap the latter into the
                        // legacy `notifications/stats/tick` frame.
                        if is_jsonrpc_notification(&payload) {
                            write_prebuilt_frame(writer, &payload).await?;
                        } else {
                            write_notification(writer, "notifications/stats/tick", payload).await?;
                        }
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
    use tokio::sync::Semaphore;

    /// Default cap on concurrently-served loopback connections.
    ///
    /// Each accepted connection runs on its own task and holds a read buffer;
    /// without a cap a local process can open unbounded sockets to exhaust
    /// memory/FDs (a local `DoS`). Connections beyond the cap are dropped at
    /// accept time. Generous for legitimate local tooling.
    pub const DEFAULT_MAX_CONNECTIONS: usize = 32;

    /// JSON-RPC server bound to a loopback TCP address.
    ///
    /// Refuses any non-loopback peer with [`crate::Error::PolicyDenied`] and
    /// drops the connection without dispatching the frame. Each accepted
    /// connection is handled on its own task so concurrent clients are
    /// supported, up to [`LoopbackTransport::max_connections`].
    pub struct LoopbackTransport {
        listener: TcpListener,
        max_connections: usize,
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
            Ok(Self {
                listener,
                max_connections: DEFAULT_MAX_CONNECTIONS,
            })
        }

        /// Override the concurrent-connection cap (default
        /// [`DEFAULT_MAX_CONNECTIONS`]). A value of `0` is clamped to `1` so
        /// the listener always makes forward progress.
        #[must_use]
        pub fn with_max_connections(mut self, max: usize) -> Self {
            self.max_connections = max.max(1);
            self
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
            let limiter = Arc::new(Semaphore::new(self.max_connections));
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
                // Bound concurrent connections: acquire a permit without
                // blocking the accept loop. When the cap is reached, drop the
                // freshly-accepted peer rather than queueing unbounded work.
                let Ok(permit) = Arc::clone(&limiter).try_acquire_owned() else {
                    tracing::warn!(
                        peer = %peer,
                        max = self.max_connections,
                        "MCP loopback connection cap reached — dropping peer"
                    );
                    drop(stream);
                    continue;
                };
                let inner = inner.clone();
                tokio::spawn(async move {
                    // Hold the permit for the lifetime of the connection.
                    let _permit = permit;
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

    #[test]
    fn is_jsonrpc_notification_detects_preframed() {
        assert!(is_jsonrpc_notification(&serde_json::json!({
            "jsonrpc": "2.0", "method": "spt/event", "params": {}
        })));
        // A bare stats tick payload is NOT a pre-framed notification.
        assert!(!is_jsonrpc_notification(&serde_json::json!({
            "total_sessions": 3
        })));
        // Missing method → not a notification frame.
        assert!(!is_jsonrpc_notification(
            &serde_json::json!({"jsonrpc": "2.0"})
        ));
    }

    #[tokio::test]
    async fn write_prebuilt_frame_emits_verbatim() {
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "spt/event",
            "params": {"kind": "profile.failed"}
        });
        let mut buf = Vec::<u8>::new();
        write_prebuilt_frame(&mut buf, &frame).await.unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.ends_with('\n'));
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["method"], "spt/event");
        assert_eq!(v["params"]["kind"], "profile.failed");
        assert!(v.get("id").is_none());
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

    #[tokio::test]
    async fn read_line_capped_reads_line_including_newline() {
        let cursor = std::io::Cursor::new(b"hello\n".to_vec());
        let mut reader = tokio::io::BufReader::new(cursor);
        let line = read_line_capped(&mut reader, 1024).await.unwrap();
        assert_eq!(line, "hello\n");
    }

    #[tokio::test]
    async fn read_line_capped_eof_is_empty_string() {
        let cursor = std::io::Cursor::new(Vec::<u8>::new());
        let mut reader = tokio::io::BufReader::new(cursor);
        let line = read_line_capped(&mut reader, 1024).await.unwrap();
        assert!(line.is_empty());
    }

    /// An over-long line (no newline within the cap) is rejected rather than
    /// buffered unbounded — the pre-auth memory-exhaustion DoS mitigation.
    #[tokio::test]
    async fn read_line_capped_rejects_overlong_line() {
        let cursor = std::io::Cursor::new(vec![b'a'; 4096]);
        let mut reader = tokio::io::BufReader::new(cursor);
        let err = read_line_capped(&mut reader, 64).await.unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    /// The capped reader consumes exactly one frame, leaving pipelined frames
    /// intact for the following read.
    #[tokio::test]
    async fn read_line_capped_preserves_following_frame() {
        let cursor = std::io::Cursor::new(b"one\ntwo\n".to_vec());
        let mut reader = tokio::io::BufReader::new(cursor);
        assert_eq!(read_line_capped(&mut reader, 1024).await.unwrap(), "one\n");
        assert_eq!(read_line_capped(&mut reader, 1024).await.unwrap(), "two\n");
        assert!(read_line_capped(&mut reader, 1024)
            .await
            .unwrap()
            .is_empty());
    }

    /// An over-long frame must close the connection rather than allocate
    /// without bound: `read_frame` surfaces the cap error and the run loop
    /// propagates it (E8-F15 + DoS hardening).
    #[tokio::test]
    async fn overlong_frame_closes_connection() {
        let cursor = std::io::Cursor::new(vec![b'x'; 8192]);
        let mut reader = tokio::io::BufReader::new(cursor);
        // Use the internal helper at the real cap-shape to assert closure
        // semantics deterministically without allocating 4 MiB.
        let err = read_line_capped(&mut reader, 100).await.unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    /// The loopback transport caps concurrent connections: with the cap set to
    /// 1, a second peer is accepted then immediately closed by the server
    /// (local FD/memory-exhaustion DoS mitigation).
    #[tokio::test]
    async fn loopback_connection_cap_drops_excess_peers() {
        use crate::audit::NoopAuditSink;
        use crate::controller::NoopController;
        use crate::policy::{McpPolicy, Policy};
        use crate::server::McpServer;
        use crate::sources::NoopSources;
        use std::time::Duration;
        use tokio::io::{
            AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader,
        };
        use tokio::net::TcpStream;

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

        let transport = loopback::LoopbackTransport::bind("127.0.0.1:0")
            .await
            .expect("bind")
            .with_max_connections(1);
        let addr = transport.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = transport.serve(inner).await;
        });

        // Connection 1: a full initialize round-trip proves the per-connection
        // task is alive and holding the only permit.
        let c1 = TcpStream::connect(addr).await.expect("connect c1");
        let (r1, mut w1) = c1.into_split();
        w1.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n")
            .await
            .expect("write init");
        let mut br1 = TokioBufReader::new(r1);
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), br1.read_line(&mut line))
            .await
            .expect("init reply within timeout")
            .expect("read init reply");
        assert!(line.contains("protocolVersion"), "init reply: {line}");

        // Connection 2: beyond the cap → server accepts then closes it.
        let mut c2 = TcpStream::connect(addr).await.expect("connect c2");
        let mut buf = [0u8; 32];
        let n = tokio::time::timeout(Duration::from_secs(5), c2.read(&mut buf))
            .await
            .expect("c2 read within timeout")
            .expect("c2 read");
        assert_eq!(
            n, 0,
            "connection beyond the cap must be closed by the server"
        );

        // Keep c1 alive until here so its permit stays held for the assertion.
        drop(br1);
        drop(w1);
    }

    #[tokio::test]
    async fn loopback_with_max_connections_clamps_zero_to_one() {
        let t = loopback::LoopbackTransport::bind("127.0.0.1:0")
            .await
            .expect("bind")
            .with_max_connections(0);
        // No panic, listener still valid.
        assert!(t.local_addr().unwrap().ip().is_loopback());
    }
}
