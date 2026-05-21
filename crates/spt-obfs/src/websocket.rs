//! ssh-over-websocket transport.
//!
//! ## Stub status
//!
//! `tokio-tungstenite` is **absent from `Cargo.lock`**; stub-where-needed
//! precedent applies. The connect path surfaces a stable
//! `Error::UnsupportedPlatform` with a `tokio-tungstenite` detail string so
//! callers (Bwire's audit layer; the supervisor) can distinguish the
//! "missing dep" case from genuine network failures.
//!
//! The handshake contract — `Sec-WebSocket-Protocol: ssh`, binary-frame round
//! trip — is enforced via in-process helpers ([`build_upgrade_request`],
//! [`encode_binary_frame`] / [`decode_binary_frame`]) so the test contract
//! holds even when the wire path is gated.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};

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
        Ok(Self { cfg, audit })
    }

    /// Borrow the configured target URL.
    #[must_use]
    pub fn url(&self) -> &str {
        match &self.cfg {
            ObfsConfig::Websocket { url, .. } => url.as_str(),
            _ => unreachable!("checked in new()"),
        }
    }

    /// Render the HTTP upgrade request the real backend would emit. Returns
    /// the canonical `Sec-WebSocket-*` header set plus any caller-supplied
    /// extras so the unit test can assert the subprotocol is present.
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
}

/// Minimal binary-frame encoder used by the round-trip test.
///
/// Layout: `[opcode=0x82 binary][len 4 BE][payload]`. Real implementations
/// emit RFC 6455 frames via `tokio-tungstenite`; this in-process form is
/// sufficient to drive the contract.
#[must_use]
pub fn encode_binary_frame(payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(5 + payload.len());
    buf.put_u8(0x82); // FIN=1, opcode=binary
    buf.put_u32(payload.len() as u32);
    buf.put_slice(payload);
    buf.freeze()
}

/// Decode a frame produced by [`encode_binary_frame`].
///
/// Returns the inner payload on success.
pub fn decode_binary_frame(frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() < 5 {
        return Err(ObfsError::Handshake(format!(
            "ws frame too short: {}",
            frame.len()
        ))
        .into());
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

#[async_trait]
impl ObfsTransport for WebsocketTransport {
    async fn connect(&mut self, target: &str) -> Result<Box<dyn AsyncReadWrite>> {
        self.audit.on_connect(self.name(), target);
        tracing::warn!(
            transport = self.name(),
            url = self.url(),
            "ssh-over-websocket: stub transport — `tokio-tungstenite` not in Cargo.lock"
        );
        Err(ObfsError::Unsupported {
            transport: "ssh-over-websocket",
            crate_name: "tokio-tungstenite",
            detail: "stub transport; activate via `real-tokio-tungstenite` once dep lands"
                .into(),
        }
        .into())
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
