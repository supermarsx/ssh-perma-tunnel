//! Lightweight JSON-RPC 2.0 client to a running spt's MCP loopback transport.
//!
//! Used by CLI subcommands that need to invoke supervisor-side actions
//! (`tunnel failover`, `session close`, `session drain`, `stats live`, live
//! benchmark drivers) on the already-running process rather than spawning a
//! fresh supervisor.
//!
//! Discovery: [`McpClient::connect_from_state_dir`] reads
//! `<state_dir>/mcp-listen.json` (see [`crate::mcp_listen`]) and dials
//! `host:port` with the token. If the sidecar is missing, returns a clear
//! error pointing the user at `[mcp].listen` config.

use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;

use futures::stream::Stream;
use serde::Deserialize;
use serde_json::{json, Value};
use spt_core::{Error, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::mcp_listen;

/// `initialize` response shape we care about.
#[derive(Debug, Clone, Deserialize)]
pub struct InitializeResponse {
    /// Echoed protocol version.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Server identity block.
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

/// `serverInfo` block.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerInfo {
    /// Server name (`spt-mcp`).
    pub name: String,
    /// Server version.
    pub version: String,
}

/// JSON-RPC 2.0 client for the MCP loopback transport.
pub struct McpClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: i64,
    token: Option<String>,
}

impl McpClient {
    /// Connect to a loopback MCP listener at `addr`. No auth — caller may set
    /// a token via [`Self::with_token`] before [`Self::initialize`].
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| Error::RuntimeFailure(format!("connect {addr}: {e}")))?;
        let (r, w) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(r),
            writer: w,
            next_id: 1,
            token: None,
        })
    }

    /// Connect to the loopback listener recorded in
    /// `<state_dir>/mcp-listen.json`. Pre-loads the bearer token from the
    /// sidecar so [`Self::initialize`] succeeds.
    pub async fn connect_from_state_dir(state_dir: &Path) -> Result<Self> {
        let s = mcp_listen::read(state_dir).map_err(|e| {
            Error::RuntimeFailure(format!(
                "{e}\n\
                 hint: enable MCP loopback with `[mcp].listen = \"127.0.0.1:<port>\"` \
                 in your config and restart `spt tunnel run`"
            ))
        })?;
        let addr: SocketAddr = format!("{}:{}", s.host, s.port)
            .parse()
            .map_err(|e| Error::RuntimeFailure(format!("parse mcp-listen sidecar addr: {e}")))?;
        let mut c = Self::connect(addr).await?;
        c.token = Some(s.token);
        Ok(c)
    }

    /// Override or set the bearer token used in `initialize`.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Drive the MCP `initialize` handshake.
    pub async fn initialize(&mut self) -> Result<InitializeResponse> {
        let mut params = json!({
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "spt-cli", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {}
        });
        if let Some(t) = &self.token {
            params["token"] = Value::String(t.clone());
        }
        let resp = self.rpc("initialize", params).await?;
        let parsed: InitializeResponse = serde_json::from_value(resp)
            .map_err(|e| Error::RuntimeFailure(format!("parse initialize response: {e}")))?;
        Ok(parsed)
    }

    /// Call `tools/call` with the given tool name + arguments. Returns the
    /// already-unwrapped tool result `Value` (the `content[0].text` JSON
    /// payload), since every spt tool returns one structured object.
    pub async fn call_tool(&mut self, name: &str, args: Value) -> Result<Value> {
        let result = self
            .rpc(
                "tools/call",
                json!({
                    "name": name,
                    "arguments": args,
                }),
            )
            .await?;
        // Server wraps the payload as `{content: [{type:"text", text: "<json>"}], isError: false}`.
        // Try to unwrap; fall back to the raw value.
        if let Some(text) = result
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .and_then(|f| f.get("text"))
            .and_then(|t| t.as_str())
        {
            return serde_json::from_str(text)
                .map_err(|e| Error::RuntimeFailure(format!("parse tool result: {e}")));
        }
        Ok(result)
    }

    /// Read one resource via `resources/read`.
    pub async fn read_resource(&mut self, uri: &str) -> Result<Value> {
        self.rpc("resources/read", json!({"uri": uri})).await
    }

    /// Subscribe to a streaming tool. Calls `tools/call` for `tool_name`
    /// (typically `stats_subscribe`) and then drains
    /// `notifications/<...>` frames as they arrive. Returns a
    /// stream of params objects.
    ///
    /// The client takes ownership of the underlying connection because
    /// subsequent requests would interleave with the pushed notifications.
    /// Drop the stream to close the connection.
    pub async fn subscribe(
        mut self,
        tool_name: &str,
        args: Value,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Value>> + Send>>> {
        // Issue the subscribe call; the response is read first.
        let _ = self.call_tool(tool_name, args).await?;
        let (tx, rx) = mpsc::channel::<Result<Value>>(64);
        tokio::spawn(async move {
            loop {
                let mut line = String::new();
                let n = match self.reader.read_line(&mut line).await {
                    Ok(n) => n,
                    Err(e) => {
                        let _ = tx
                            .send(Err(Error::RuntimeFailure(format!("read: {e}"))))
                            .await;
                        break;
                    }
                };
                if n == 0 {
                    break; // EOF
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let v: Value = match serde_json::from_str(trimmed) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = tx
                            .send(Err(Error::RuntimeFailure(format!("parse: {e}"))))
                            .await;
                        break;
                    }
                };
                // Notifications carry `method` + `params`; responses carry `id` + (`result`|`error`).
                if v.get("method").is_some() {
                    let params = v.get("params").cloned().unwrap_or(Value::Null);
                    if tx.send(Ok(params)).await.is_err() {
                        break;
                    }
                }
            }
        });
        let stream = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        Ok(Box::pin(stream))
    }

    /// Issue one JSON-RPC request and return the unwrapped `result` value.
    async fn rpc(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let body = serde_json::to_vec(&req)
            .map_err(|e| Error::RuntimeFailure(format!("serialize: {e}")))?;
        self.writer
            .write_all(&body)
            .await
            .map_err(|e| Error::RuntimeFailure(format!("write: {e}")))?;
        self.writer
            .write_all(b"\n")
            .await
            .map_err(|e| Error::RuntimeFailure(format!("write: {e}")))?;
        self.writer
            .flush()
            .await
            .map_err(|e| Error::RuntimeFailure(format!("flush: {e}")))?;

        // Read until we see a frame whose `id` matches. Skip notification
        // frames (no `id`) — the simple sync RPC path doesn't surface them.
        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .await
                .map_err(|e| Error::RuntimeFailure(format!("read: {e}")))?;
            if n == 0 {
                return Err(Error::RuntimeFailure("server closed connection".into()));
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(trimmed)
                .map_err(|e| Error::RuntimeFailure(format!("parse: {e}")))?;
            // Skip server→client notifications.
            if v.get("id").is_none() {
                continue;
            }
            if let Some(err) = v.get("error") {
                let msg = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                return Err(Error::RuntimeFailure(format!(
                    "rpc error: {msg} ({})",
                    err.get("code")
                        .and_then(serde_json::Value::as_i64)
                        .unwrap_or(0)
                )));
            }
            let result = v.get("result").cloned().unwrap_or(Value::Null);
            return Ok(result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_and_initialize_against_loopback() {
        let policy = spt_mcp::McpPolicy {
            enabled: true,
            ..Default::default()
        };
        let server = crate::mcp_server::build_noop_server(policy);
        let transport = spt_mcp::LoopbackTransport::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = transport.local_addr().unwrap();
        let server_task = tokio::spawn(async move { server.run(transport).await });

        let mut client = McpClient::connect(addr).await.unwrap();
        let init = client.initialize().await.unwrap();
        assert_eq!(init.protocol_version, "2024-11-05");
        drop(client);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn connect_from_state_dir_errors_when_sidecar_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let err = McpClient::connect_from_state_dir(tmp.path()).await;
        assert!(err.is_err(), "expected error when sidecar absent");
    }

    #[tokio::test]
    async fn connect_to_unreachable_addr_errors() {
        // Bind a TCP listener, get its addr, then drop the listener so the
        // socket is closed before we connect.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        // On some kernels this returns "connection refused" immediately; on
        // others it may block. Allow either Err or transiently-Ok.
        let r = McpClient::connect(addr).await;
        match r {
            // Accept race-condition success, or expected RuntimeFailure.
            Ok(_) | Err(Error::RuntimeFailure(_)) => {}
            Err(other) => panic!("unexpected error type: {other:?}"),
        }
    }

    #[test]
    fn initialize_response_deserialises_required_fields() {
        let body = r#"{
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "spt-mcp", "version": "0.1.0"}
        }"#;
        let resp: InitializeResponse = serde_json::from_str(body).unwrap();
        assert_eq!(resp.protocol_version, "2024-11-05");
        assert_eq!(resp.server_info.name, "spt-mcp");
        assert_eq!(resp.server_info.version, "0.1.0");
    }

    #[test]
    fn initialize_response_rejects_missing_fields() {
        let body = r#"{"protocolVersion": "x"}"#;
        let r: std::result::Result<InitializeResponse, _> = serde_json::from_str(body);
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn with_token_attaches_token_for_initialize_payload() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        // Spin up an echo server that records the inbound initialize JSON.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured: std::sync::Arc<tokio::sync::Mutex<Option<String>>> =
            std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let captured_c = captured.clone();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let (r, mut w) = s.split();
            let mut br = BufReader::new(r);
            let mut line = String::new();
            br.read_line(&mut line).await.unwrap();
            *captured_c.lock().await = Some(line.clone());
            // Send a minimal response.
            let resp = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"spt-mcp","version":"0.0.0"}}}"#;
            w.write_all(resp.as_bytes()).await.unwrap();
            w.write_all(b"\n").await.unwrap();
            w.flush().await.unwrap();
        });

        let mut client = McpClient::connect(addr).await.unwrap().with_token("hunter2");
        let _ = client.initialize().await.unwrap();
        let _ = server.await;
        let body = captured.lock().await.clone().unwrap();
        assert!(body.contains("hunter2"), "expected token in payload: {body}");
    }
}
