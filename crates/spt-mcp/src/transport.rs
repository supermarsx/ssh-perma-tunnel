//! JSON-RPC transports for the MCP server.
//!
//! Two transports are defined; only `stdio` is implemented in this version.
//!
//! # Stdio framing
//!
//! Each line on stdin is exactly one JSON-RPC request, terminated by `\n`.
//! Each response written to stdout is one JSON object on its own line.
//! `stderr` is reserved for tracing logs — never write protocol bytes there.
//!
//! # Loopback (placeholder)
//!
//! [`loopback::bind`] is a deferred follow-up. It returns
//! [`crate::Error::NotImplemented`] in this version. The framing types in
//! this module already accept any `AsyncBufRead + AsyncWrite` so dropping the
//! TCP listener in later is mechanical.

use crate::protocol::{Request, Response};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Transport variant marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// Line-delimited JSON-RPC over stdin/stdout.
    Stdio,
    /// Loopback TCP — placeholder; not implemented.
    Loopback,
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

/// Stdio transport helpers.
pub mod stdio {
    use super::{BufReader, Request, Response};
    use tokio::io::{stdin, stdout, AsyncWriteExt, Stdin, Stdout};
    // AsyncWriteExt is used for `flush` below.

    /// Owned framed stdio handles used by the server's main loop.
    pub struct StdioFraming {
        /// Buffered stdin reader.
        pub reader: BufReader<Stdin>,
        /// Stdout writer (line-buffered explicitly with a trailing flush).
        pub writer: Stdout,
    }

    impl StdioFraming {
        /// Construct from process stdio handles.
        #[must_use]
        pub fn new() -> Self {
            Self {
                reader: BufReader::new(stdin()),
                writer: stdout(),
            }
        }

        /// Read one request.
        pub async fn read(&mut self) -> crate::Result<Option<Request>> {
            super::read_request(&mut self.reader).await
        }

        /// Write one response.
        pub async fn write(&mut self, response: &Response) -> crate::Result<()> {
            super::write_response(&mut self.writer, response).await
        }

        /// Flush stdout. Called on shutdown.
        pub async fn flush(&mut self) -> crate::Result<()> {
            self.writer.flush().await?;
            Ok(())
        }
    }

    impl Default for StdioFraming {
        fn default() -> Self {
            Self::new()
        }
    }
}

/// Loopback TCP transport — placeholder for the v2 follow-up.
pub mod loopback {
    /// Bind a loopback TCP listener. **Not implemented in v1.**
    ///
    /// Returns [`crate::Error::NotImplemented`] unconditionally. The follow-up
    /// task will replace this with a `tokio::net::TcpListener` accepting
    /// connections that share the same JSON-RPC framing as stdio.
    pub fn bind(_addr: &str) -> crate::Result<()> {
        Err(crate::Error::NotImplemented(
            "loopback TCP transport is deferred to a follow-up",
        ))
    }
}
