//! ssh-over-websocket transport.
//!
//! ## Wire summary
//!
//! Uses `tokio-tungstenite 0.24` to perform the RFC 6455 upgrade and
//! exchange binary frames. The advertised subprotocol is `ssh`. Caller
//! supplied headers (`headers` in `ObfsConfig::Websocket`) are merged
//! into the upgrade request verbatim.
//!
//! Only binary opcodes carry SSH bytes — incoming text frames cause the
//! reader to surface an `InvalidData` error so a misconfigured server
//! is detected immediately. Ping frames are handled transparently by
//! `tokio-tungstenite`; close frames propagate as EOF to the SSH layer.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use http::Request;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message, WebSocketConfig};
use tokio_tungstenite::{connect_async_with_config, MaybeTlsStream, WebSocketStream};

use spt_core::Result;

use crate::audit::AuditHook;
use crate::config::ObfsConfig;
use crate::error::ObfsError;
use crate::transport::{AsyncReadWrite, ObfsTransport};

/// The WebSocket subprotocol name required by every spt-over-WS server.
pub const SSH_SUBPROTOCOL: &str = "ssh";

/// ssh-over-websocket transport handle.
pub struct WebsocketTransport {
    cfg: ObfsConfig,
    audit: Arc<dyn AuditHook>,
    /// Test-only override for the dial target.
    url_override: Option<String>,
}

impl WebsocketTransport {
    /// Construct the transport.
    pub fn new(cfg: ObfsConfig, audit: Arc<dyn AuditHook>) -> Result<Self> {
        let ObfsConfig::Websocket { .. } = cfg else {
            return Err(ObfsError::InvalidConfig(
                "WebsocketTransport requires ObfsConfig::Websocket".into(),
            )
            .into());
        };
        cfg.validate().map_err(spt_core::Error::from)?;
        Ok(Self {
            cfg,
            audit,
            url_override: None,
        })
    }

    /// Override the dial URL (test hook for loopback fixtures).
    #[must_use]
    pub fn with_url_override(mut self, url: impl Into<String>) -> Self {
        self.url_override = Some(url.into());
        self
    }

    /// Borrow the configured target URL.
    #[must_use]
    pub fn url(&self) -> &str {
        match &self.cfg {
            ObfsConfig::Websocket { url, .. } => url.as_str(),
            _ => unreachable!("checked in new()"),
        }
    }

    /// Render the HTTP upgrade request the live backend emits.
    ///
    /// Returns the canonical headers (`Upgrade`, `Connection`,
    /// `Sec-WebSocket-Version`, `Sec-WebSocket-Protocol: ssh`) plus any
    /// caller-supplied extras. The unit test pins the subprotocol.
    #[must_use]
    pub fn build_upgrade_request(&self) -> Vec<(String, String)> {
        let mut hdrs = vec![
            ("Upgrade".into(), "websocket".into()),
            ("Connection".into(), "Upgrade".into()),
            ("Sec-WebSocket-Version".into(), "13".into()),
            ("Sec-WebSocket-Protocol".into(), SSH_SUBPROTOCOL.into()),
        ];
        match &self.cfg {
            ObfsConfig::Websocket { headers, .. } => {
                for (k, v) in headers {
                    hdrs.push((k.clone(), v.clone()));
                }
            }
            _ => unreachable!("checked in new()"),
        }
        hdrs
    }

    /// Build the `http::Request` handed to `tokio-tungstenite`.
    ///
    /// Exposed for unit testing of header propagation.
    pub fn build_http_request(&self) -> std::result::Result<Request<()>, ObfsError> {
        let url = self.url_override.as_deref().unwrap_or_else(|| self.url());
        // `tokio-tungstenite` requires Host, Upgrade, Connection,
        // Sec-WebSocket-Key, Sec-WebSocket-Version. Of those, our
        // explicit list provides everything except Host (which the
        // crate fills from the URL) and Sec-WebSocket-Key (random,
        // tungstenite-generated). We can pre-build those though to
        // make the request fully concrete for tests.
        let parsed =
            url::Url::parse(url).map_err(|e| ObfsError::InvalidConfig(format!("ws url: {e}")))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| ObfsError::InvalidConfig("ws url has no host".into()))?;
        let port = parsed.port_or_known_default().unwrap_or(443);
        let host_hdr = if (parsed.scheme() == "wss" && port == 443)
            || (parsed.scheme() == "ws" && port == 80)
        {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        };
        let key = ws_random_key();
        let mut builder = Request::builder()
            .method("GET")
            .uri(url)
            .header("Host", host_hdr)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", key)
            .header("Sec-WebSocket-Protocol", SSH_SUBPROTOCOL);
        if let ObfsConfig::Websocket { headers, .. } = &self.cfg {
            for (k, v) in headers {
                builder = builder.header(k.as_str(), v.as_str());
            }
        }
        builder
            .body(())
            .map_err(|e| ObfsError::InvalidConfig(format!("ws req: {e}")))
    }
}

fn ws_random_key() -> String {
    use base64::Engine;
    let mut buf = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// Minimal binary-frame encoder kept for backwards compatibility with the
/// t6-e13 contract tests. Encodes the payload with a fixed binary opcode.
#[must_use]
pub fn encode_binary_frame(payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(5 + payload.len());
    buf.put_u8(0x82); // FIN=1, opcode=binary
    buf.put_u32(payload.len() as u32);
    buf.put_slice(payload);
    buf.freeze()
}

/// Decode a frame produced by [`encode_binary_frame`].
pub fn decode_binary_frame(frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() < 5 {
        return Err(ObfsError::Handshake(format!("ws frame too short: {}", frame.len())).into());
    }
    if frame[0] != 0x82 {
        return Err(ObfsError::Handshake(format!(
            "ws frame opcode {:#x} != binary(0x82)",
            frame[0]
        ))
        .into());
    }
    let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    if frame.len() - 5 != len {
        return Err(ObfsError::Handshake(format!(
            "ws frame length mismatch: header={}, body={}",
            len,
            frame.len() - 5
        ))
        .into());
    }
    Ok(frame[5..].to_vec())
}

/// Duplex bridge translating WebSocket frames to/from `AsyncRead+Write`.
pub struct WebsocketStream {
    ws: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    rx: Vec<u8>,
    closed: bool,
    pending_write: Option<Vec<u8>>,
}

impl WebsocketStream {
    /// Construct from a live `tokio-tungstenite` stream.
    pub fn new(ws: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>) -> Self {
        Self {
            ws,
            rx: Vec::new(),
            closed: false,
            pending_write: None,
        }
    }
}

impl AsyncRead for WebsocketStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.rx.is_empty() {
                let n = buf.remaining().min(self.rx.len());
                let drained: Vec<u8> = self.rx.drain(..n).collect();
                buf.put_slice(&drained);
                return Poll::Ready(Ok(()));
            }
            if self.closed {
                return Poll::Ready(Ok(())); // EOF
            }
            match self.ws.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(b) => {
                        self.rx.extend_from_slice(&b);
                    }
                    Message::Close(_) => {
                        self.closed = true;
                    }
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                        // tungstenite auto-responds to Ping; raw frames
                        // are an artefact of low-level configurations
                        // we don't enable.
                    }
                    Message::Text(_) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "ws: text frame not allowed on ssh subprotocol",
                        )));
                    }
                },
                Poll::Ready(Some(Err(e))) => {
                    // 1.88 lint: io_other_error
                    return Poll::Ready(Err(std::io::Error::other(format!("ws: {e}"))));
                }
                Poll::Ready(None) => {
                    self.closed = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WebsocketStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // First, ensure the sink is ready.
        match self.ws.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                // 1.88 lint: io_other_error
                return Poll::Ready(Err(std::io::Error::other(format!("ws ready: {e}"))));
            }
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let owned = buf.to_vec();
        let n = owned.len();
        match self.ws.start_send_unpin(Message::Binary(owned)) {
            Ok(()) => Poll::Ready(Ok(n)),
            // 1.88 lint: io_other_error
            Err(e) => Poll::Ready(Err(std::io::Error::other(format!("ws send: {e}")))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.ws.poll_flush_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            // 1.88 lint: io_other_error
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::other(format!("ws flush: {e}"))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Issue a clean close frame on first call.
        if self.pending_write.is_none() {
            self.pending_write = Some(Vec::new()); // sentinel
            let close = Message::Close(Some(CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                reason: std::borrow::Cow::Borrowed("ssh-shutdown"),
            }));
            let _ = self.ws.start_send_unpin(close);
        }
        match self.ws.poll_close_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            // 1.88 lint: io_other_error
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::other(format!("ws close: {e}"))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[async_trait]
impl ObfsTransport for WebsocketTransport {
    async fn connect(&mut self, target: &str) -> Result<Box<dyn AsyncReadWrite>> {
        self.audit.on_connect(self.name(), target);
        let req = self.build_http_request().map_err(spt_core::Error::from)?;
        let cfg = WebSocketConfig::default();
        let (ws, _resp) = connect_async_with_config(req, Some(cfg), false)
            .await
            .map_err(|e| ObfsError::Handshake(format!("ws connect: {e}")))?;
        tracing::debug!(
            transport = self.name(),
            url = self.url_override.as_deref().unwrap_or_else(|| self.url()),
            "ws: upgrade complete"
        );
        Ok(Box::new(WebsocketStream::new(ws)))
    }

    fn name(&self) -> &'static str {
        "ssh-over-websocket"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NoopAuditHook;

    fn cfg() -> ObfsConfig {
        ObfsConfig::Websocket {
            url: "wss://example.test/ssh".into(),
            headers: vec![("X-Auth".into(), "tok".into())],
        }
    }

    #[test]
    fn subprotocol_present_in_upgrade_request() {
        let t = WebsocketTransport::new(cfg(), Arc::new(NoopAuditHook)).unwrap();
        let h = t.build_upgrade_request();
        assert!(h
            .iter()
            .any(|(k, v)| k == "Sec-WebSocket-Protocol" && v == "ssh"));
        assert!(h.iter().any(|(k, v)| k == "X-Auth" && v == "tok"));
    }

    #[test]
    fn http_request_contains_subprotocol_and_custom_headers() {
        let t = WebsocketTransport::new(cfg(), Arc::new(NoopAuditHook)).unwrap();
        let req = t.build_http_request().unwrap();
        let hdrs = req.headers();
        assert_eq!(
            hdrs.get("Sec-WebSocket-Protocol")
                .unwrap()
                .to_str()
                .unwrap(),
            "ssh"
        );
        assert_eq!(hdrs.get("X-Auth").unwrap().to_str().unwrap(), "tok");
        assert!(hdrs.get("Sec-WebSocket-Key").is_some());
    }

    #[test]
    fn binary_frame_round_trip() {
        let payload = b"SSH-2.0-spt\r\n".to_vec();
        let frame = encode_binary_frame(&payload);
        let out = decode_binary_frame(&frame).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn decode_rejects_text_opcode() {
        let mut bad = BytesMut::new();
        bad.put_u8(0x81); // text frame
        bad.put_u32(0);
        assert!(decode_binary_frame(&bad).is_err());
    }
}
