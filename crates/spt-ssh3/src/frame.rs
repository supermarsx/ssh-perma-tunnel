//! SSH3 wire framing types.
//!
//! These mirror draft-michel-remote-terminal-http3-00 §5 (the "SSH3 framing
//! layer") used by the francoismichel/ssh3 reference. The types are kept
//! pure-data so unit tests cover encoding and decoding even when the runtime
//! transport is stubbed out.
//!
//! ## Frame layout
//!
//! Each frame on a QUIC stream is `[type: varint][length: varint][payload …]`.
//! The `Settings` frame is sent by both peers immediately after the Extended
//! CONNECT control stream is established and carries a map of capability →
//! value. We model the subset spt cares about explicitly; unknown keys are
//! preserved in `extras` for round-trip fidelity.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use spt_core::{Error, Result};

/// Stream classification used by SSH3 over HTTP/3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ssh3StreamKind {
    /// The control stream (Extended CONNECT response stream).
    Control,
    /// A `direct-tcp` forward stream (client-initiated TCP forward).
    DirectTcp,
    /// A `forwarded-tcp` stream (server-initiated remote forward back-channel).
    ForwardedTcp,
    /// A `tcpip-forward` request stream (client requests a remote listener).
    TcpipForward,
    /// A datagram-bearing UDP-flow association stream.
    UdpAssociation,
}

/// Numeric type tags for the framing layer.
///
/// Values are draft-michel-remote-terminal-http3-00 placeholders; the wire
/// values are intentionally small varints in the experimental range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Ssh3FrameKind {
    /// Capability advertisement, sent first on every stream.
    Settings = 0x01,
    /// Open a `direct-tcp` forward to `host:port`.
    DirectTcpRequest = 0x02,
    /// Server response to a forward open.
    ForwardOpenResponse = 0x03,
    /// Bytes of a forwarded TCP stream.
    Data = 0x04,
    /// Half-close (FIN) on a forwarded TCP stream.
    Close = 0x05,
    /// UDP datagram association request.
    UdpAssociate = 0x06,
    /// Application-level keepalive (in addition to QUIC PING).
    AppPing = 0x07,
}

impl Ssh3FrameKind {
    /// Convert from the wire varint.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Self::Settings,
            0x02 => Self::DirectTcpRequest,
            0x03 => Self::ForwardOpenResponse,
            0x04 => Self::Data,
            0x05 => Self::Close,
            0x06 => Self::UdpAssociate,
            0x07 => Self::AppPing,
            _ => return None,
        })
    }
}

/// One framed message on an SSH3 stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssh3Frame {
    /// Frame type.
    pub kind: Ssh3FrameKind,
    /// Opaque payload — meaning depends on `kind`.
    pub payload: Bytes,
}

impl Ssh3Frame {
    /// Construct a new frame.
    #[must_use]
    pub fn new(kind: Ssh3FrameKind, payload: impl Into<Bytes>) -> Self {
        Self {
            kind,
            payload: payload.into(),
        }
    }

    /// Encode `self` to its wire representation: `[kind:u8][len:u32_be][bytes]`.
    ///
    /// Note: the production wire format uses QUIC varints; this stub uses a
    /// fixed-size length prefix so unit tests can exercise round-trip without
    /// pulling a varint dependency. The framing-layer **types** are stable;
    /// only the encoding helper is stub-mode-specific.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(5 + self.payload.len());
        buf.put_u8(self.kind as u8);
        // Cap length at u32::MAX for the stub encoder.
        let len = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        buf.put_u32(len);
        buf.put_slice(&self.payload[..len as usize]);
        buf.freeze()
    }

    /// Decode one frame from `buf`. Advances `buf` past the consumed bytes.
    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 5 {
            return Err(Error::InvalidConfig(
                "ssh3 frame: short header".to_string(),
            ));
        }
        let kind_raw = buf.get_u8();
        let kind = Ssh3FrameKind::from_u8(kind_raw).ok_or_else(|| {
            Error::InvalidConfig(format!("ssh3 frame: unknown kind 0x{kind_raw:02x}"))
        })?;
        let len = buf.get_u32() as usize;
        if buf.remaining() < len {
            return Err(Error::InvalidConfig(
                "ssh3 frame: payload truncated".to_string(),
            ));
        }
        let payload = buf.copy_to_bytes(len);
        Ok(Self { kind, payload })
    }
}

/// Capability map exchanged in the very first `Settings` frame on the control
/// stream. The supervisor compares its required-cap set against `peer` in
/// [`crate::Ssh3Protocol::connect`]; missing required capabilities cause a
/// hard fail (`UnsupportedPlatform`).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ssh3Settings {
    /// Peer supports client-initiated TCP forwards.
    pub direct_tcp: bool,
    /// Peer supports server-initiated TCP forwards (`tcpip-forward`).
    pub remote_tcp: bool,
    /// Peer supports UDP datagrams over QUIC.
    pub udp_datagrams: bool,
    /// Peer supports SSH agent forwarding (rare in SSH3 reference).
    pub agent_forwarding: bool,
    /// Maximum concurrent forwards advertised by the peer.
    pub max_forwards: Option<u32>,
    /// Negotiated protocol revision string.
    pub version: Option<String>,
    /// Unrecognized-key passthrough for round-trip parsing fidelity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extras: Vec<(String, String)>,
}

impl Ssh3Settings {
    /// Check that this settings map satisfies a required capability set.
    ///
    /// `required` is whatever the supervisor needs for the configured forwards
    /// (e.g. `udp_datagrams = true` if any `[[profiles.forwards]]` has
    /// `transport = "udp"`).
    pub fn satisfies(&self, required: &Ssh3Settings) -> Result<()> {
        let mut missing: Vec<&str> = Vec::new();
        if required.direct_tcp && !self.direct_tcp {
            missing.push("direct_tcp");
        }
        if required.remote_tcp && !self.remote_tcp {
            missing.push("remote_tcp");
        }
        if required.udp_datagrams && !self.udp_datagrams {
            missing.push("udp_datagrams");
        }
        if required.agent_forwarding && !self.agent_forwarding {
            missing.push("agent_forwarding");
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(Error::UnsupportedPlatform(format!(
                "ssh3 peer is missing required capabilities: {}",
                missing.join(", ")
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let f = Ssh3Frame::new(Ssh3FrameKind::Data, Bytes::from_static(b"hello"));
        let mut bytes = f.encode();
        let de = Ssh3Frame::decode(&mut bytes).unwrap();
        assert_eq!(de, f);
    }

    #[test]
    fn frame_decode_unknown_kind() {
        let mut buf = Bytes::from_static(&[0xFE, 0, 0, 0, 0]);
        let err = Ssh3Frame::decode(&mut buf).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn frame_decode_truncated() {
        let mut buf = Bytes::from_static(&[0x04, 0, 0, 0, 0xFF, b'x']);
        let err = Ssh3Frame::decode(&mut buf).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn settings_satisfies_ok() {
        let peer = Ssh3Settings {
            direct_tcp: true,
            remote_tcp: true,
            udp_datagrams: true,
            ..Default::default()
        };
        let req = Ssh3Settings {
            direct_tcp: true,
            udp_datagrams: true,
            ..Default::default()
        };
        peer.satisfies(&req).unwrap();
    }

    #[test]
    fn settings_satisfies_missing() {
        let peer = Ssh3Settings {
            direct_tcp: true,
            ..Default::default()
        };
        let req = Ssh3Settings {
            direct_tcp: true,
            udp_datagrams: true,
            ..Default::default()
        };
        let err = peer.satisfies(&req).unwrap_err();
        assert!(matches!(err, Error::UnsupportedPlatform(_)));
    }

    #[test]
    fn frame_kind_from_u8() {
        assert_eq!(Ssh3FrameKind::from_u8(0x04), Some(Ssh3FrameKind::Data));
        assert_eq!(Ssh3FrameKind::from_u8(0xAA), None);
    }
}
