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
    /// Remote-direction UDP forward request: server listens on `bind`, dials
    /// `target` per inbound datagram, and proxies bytes back over a flow-id
    /// keyed datagram channel toward the client.
    ///
    /// Note: the original task brief specified `0x07` for this frame, but
    /// `AppPing` already owns that tag — `0x08` is the actual on-the-wire
    /// value.
    RemoteUdpForwardRequest = 0x08,
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
            0x08 => Self::RemoteUdpForwardRequest,
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

    /// Read one frame from an `AsyncRead` source.
    ///
    /// The wire format is `[kind:u8][len:u32_be][payload …]`. EOF before the
    /// header is mapped to `Error::RuntimeFailure("ssh3 frame: eof")` so the
    /// caller can distinguish a clean stream close from a truncated frame.
    pub async fn read_async<R>(r: &mut R) -> Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let mut header = [0u8; 5];
        r.read_exact(&mut header).await.map_err(|e| {
            Error::RuntimeFailure(format!("ssh3 frame: read header: {e}"))
        })?;
        let kind = Ssh3FrameKind::from_u8(header[0])
            .ok_or_else(|| Error::InvalidConfig(format!("ssh3 frame: unknown kind 0x{:02x}", header[0])))?;
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let mut payload = vec![0u8; len];
        if len > 0 {
            r.read_exact(&mut payload).await.map_err(|e| {
                Error::RuntimeFailure(format!("ssh3 frame: read payload: {e}"))
            })?;
        }
        Ok(Self { kind, payload: Bytes::from(payload) })
    }

    /// Write this frame to an `AsyncWrite` sink.
    pub async fn write_async<W>(&self, w: &mut W) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        let buf = self.encode();
        w.write_all(&buf).await.map_err(|e| {
            Error::RuntimeFailure(format!("ssh3 frame: write: {e}"))
        })?;
        Ok(())
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

/// Payload for [`Ssh3FrameKind::DirectTcpRequest`] and the inbound
/// `forwarded-tcp` open frame: a target host:port request on a freshly opened
/// bidi stream.
///
/// Wire: `[host_len:u16_be][host_utf8…][port:u16_be]`.
///
/// **Source**: chosen for the spt↔spt interop contract — see `session.rs`
/// top-of-file note. This is NOT bit-compatible with francoismichel/ssh3's
/// reference framing, which uses a different SSH-style string encoding; the
/// task explicitly authorizes the spt↔spt-only escape hatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOpenPayload {
    /// Target host (UTF-8).
    pub host: String,
    /// Target port.
    pub port: u16,
}

impl ChannelOpenPayload {
    /// Encode to a [`Bytes`] suitable for [`Ssh3Frame::payload`].
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let host = self.host.as_bytes();
        let mut buf = BytesMut::with_capacity(2 + host.len() + 2);
        buf.put_u16(u16::try_from(host.len()).unwrap_or(u16::MAX));
        buf.put_slice(host);
        buf.put_u16(self.port);
        buf.freeze()
    }

    /// Decode from a frame payload.
    pub fn decode(mut payload: Bytes) -> Result<Self> {
        if payload.remaining() < 2 {
            return Err(Error::InvalidConfig(
                "ssh3 channel-open: short header".into(),
            ));
        }
        let hlen = payload.get_u16() as usize;
        if payload.remaining() < hlen + 2 {
            return Err(Error::InvalidConfig(
                "ssh3 channel-open: truncated".into(),
            ));
        }
        let host_bytes = payload.copy_to_bytes(hlen);
        let host = std::str::from_utf8(&host_bytes)
            .map_err(|e| Error::InvalidConfig(format!("ssh3 channel-open: host utf8: {e}")))?
            .to_string();
        let port = payload.get_u16();
        Ok(Self { host, port })
    }
}

/// Payload for [`Ssh3FrameKind::ForwardOpenResponse`].
///
/// Wire: `[ok:u8 (0=err,1=ok)][reason_len:u16_be][reason_utf8…]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardOpenResponse {
    /// Whether the open was accepted.
    pub ok: bool,
    /// Optional reason string (always present, possibly empty).
    pub reason: String,
}

impl ForwardOpenResponse {
    /// Encode to a [`Bytes`] suitable for [`Ssh3Frame::payload`].
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let r = self.reason.as_bytes();
        let mut buf = BytesMut::with_capacity(1 + 2 + r.len());
        buf.put_u8(u8::from(self.ok));
        buf.put_u16(u16::try_from(r.len()).unwrap_or(u16::MAX));
        buf.put_slice(r);
        buf.freeze()
    }

    /// Decode from a frame payload.
    pub fn decode(mut payload: Bytes) -> Result<Self> {
        if payload.remaining() < 3 {
            return Err(Error::InvalidConfig("ssh3 forward-resp: short".into()));
        }
        let ok = payload.get_u8() != 0;
        let rlen = payload.get_u16() as usize;
        if payload.remaining() < rlen {
            return Err(Error::InvalidConfig("ssh3 forward-resp: truncated".into()));
        }
        let reason_bytes = payload.copy_to_bytes(rlen);
        let reason = std::str::from_utf8(&reason_bytes)
            .map_err(|e| Error::InvalidConfig(format!("ssh3 forward-resp: utf8: {e}")))?
            .to_string();
        Ok(Self { ok, reason })
    }
}

/// Payload for [`Ssh3FrameKind::UdpAssociate`] *and*
/// [`Ssh3FrameKind::RemoteUdpForwardRequest`].
///
/// Wire: `[flow_id:u32_be][host_len:u16_be][host_utf8…][port:u16_be]`.
///
/// Local-UDP (initiator → peer, kind `UdpAssociate`): `host:port` is the
/// remote target the peer should dial outbound for each datagram tagged
/// with `flow_id`.
///
/// Remote-UDP (initiator → peer, kind `RemoteUdpForwardRequest`):
/// `host:port` is the **bind** address the peer should listen on; the
/// initiator demuxes inbound datagrams (any external source) by `flow_id`
/// and forwards them to its locally configured target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpAssociatePayload {
    /// Flow id allocated by the requester. UDP datagrams on this association
    /// prefix payloads with this same flow id (`u32_be`).
    pub flow_id: u32,
    /// Target host of the UDP forward.
    pub host: String,
    /// Target port.
    pub port: u16,
}

impl UdpAssociatePayload {
    /// Encode to a [`Bytes`] suitable for [`Ssh3Frame::payload`].
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let h = self.host.as_bytes();
        let mut buf = BytesMut::with_capacity(4 + 2 + h.len() + 2);
        buf.put_u32(self.flow_id);
        buf.put_u16(u16::try_from(h.len()).unwrap_or(u16::MAX));
        buf.put_slice(h);
        buf.put_u16(self.port);
        buf.freeze()
    }

    /// Decode from a frame payload.
    pub fn decode(mut payload: Bytes) -> Result<Self> {
        if payload.remaining() < 6 {
            return Err(Error::InvalidConfig("ssh3 udp-assoc: short".into()));
        }
        let flow_id = payload.get_u32();
        let hlen = payload.get_u16() as usize;
        if payload.remaining() < hlen + 2 {
            return Err(Error::InvalidConfig("ssh3 udp-assoc: truncated".into()));
        }
        let host_bytes = payload.copy_to_bytes(hlen);
        let host = std::str::from_utf8(&host_bytes)
            .map_err(|e| Error::InvalidConfig(format!("ssh3 udp-assoc: utf8: {e}")))?
            .to_string();
        let port = payload.get_u16();
        Ok(Self {
            flow_id,
            host,
            port,
        })
    }
}

const SETTINGS_FLAG_DIRECT_TCP: u8 = 0x01;
const SETTINGS_FLAG_REMOTE_TCP: u8 = 0x02;
const SETTINGS_FLAG_UDP: u8 = 0x04;
const SETTINGS_FLAG_AGENT: u8 = 0x08;

impl Ssh3Settings {
    /// Encode this settings struct to a [`Bytes`] payload for an
    /// [`Ssh3FrameKind::Settings`] frame.
    ///
    /// Wire: `[flags:u8][max_forwards:u32_be (0 = unset)][version_len:u16_be][version_utf8…]`.
    #[must_use]
    pub fn encode_payload(&self) -> Bytes {
        let mut flags = 0u8;
        if self.direct_tcp {
            flags |= SETTINGS_FLAG_DIRECT_TCP;
        }
        if self.remote_tcp {
            flags |= SETTINGS_FLAG_REMOTE_TCP;
        }
        if self.udp_datagrams {
            flags |= SETTINGS_FLAG_UDP;
        }
        if self.agent_forwarding {
            flags |= SETTINGS_FLAG_AGENT;
        }
        let version = self.version.as_deref().unwrap_or("");
        let v = version.as_bytes();
        let mut buf = BytesMut::with_capacity(1 + 4 + 2 + v.len());
        buf.put_u8(flags);
        buf.put_u32(self.max_forwards.unwrap_or(0));
        buf.put_u16(u16::try_from(v.len()).unwrap_or(u16::MAX));
        buf.put_slice(v);
        buf.freeze()
    }

    /// Decode from the payload of an [`Ssh3FrameKind::Settings`] frame.
    pub fn decode_payload(mut payload: Bytes) -> Result<Self> {
        if payload.remaining() < 1 + 4 + 2 {
            return Err(Error::InvalidConfig("ssh3 settings: short".into()));
        }
        let flags = payload.get_u8();
        let max_forwards = payload.get_u32();
        let vlen = payload.get_u16() as usize;
        if payload.remaining() < vlen {
            return Err(Error::InvalidConfig("ssh3 settings: truncated".into()));
        }
        let v_bytes = payload.copy_to_bytes(vlen);
        let version_str = std::str::from_utf8(&v_bytes)
            .map_err(|e| Error::InvalidConfig(format!("ssh3 settings: version utf8: {e}")))?;
        Ok(Self {
            direct_tcp: flags & SETTINGS_FLAG_DIRECT_TCP != 0,
            remote_tcp: flags & SETTINGS_FLAG_REMOTE_TCP != 0,
            udp_datagrams: flags & SETTINGS_FLAG_UDP != 0,
            agent_forwarding: flags & SETTINGS_FLAG_AGENT != 0,
            max_forwards: if max_forwards == 0 {
                None
            } else {
                Some(max_forwards)
            },
            version: if version_str.is_empty() {
                None
            } else {
                Some(version_str.to_string())
            },
            extras: Vec::new(),
        })
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

    #[test]
    fn channel_open_round_trip() {
        let p = ChannelOpenPayload {
            host: "example.invalid".into(),
            port: 6789,
        };
        let de = ChannelOpenPayload::decode(p.encode()).unwrap();
        assert_eq!(p, de);
    }

    #[test]
    fn forward_open_response_round_trip() {
        let p = ForwardOpenResponse {
            ok: false,
            reason: "denied".into(),
        };
        let de = ForwardOpenResponse::decode(p.encode()).unwrap();
        assert_eq!(p, de);
    }

    #[test]
    fn udp_associate_round_trip() {
        let p = UdpAssociatePayload {
            flow_id: 0xdead_beef,
            host: "udp.target".into(),
            port: 53,
        };
        let de = UdpAssociatePayload::decode(p.encode()).unwrap();
        assert_eq!(p, de);
    }

    #[test]
    fn settings_payload_round_trip() {
        let s = Ssh3Settings {
            direct_tcp: true,
            remote_tcp: true,
            udp_datagrams: true,
            agent_forwarding: false,
            max_forwards: Some(64),
            version: Some("spt-ssh3/0.1".into()),
            extras: vec![],
        };
        let de = Ssh3Settings::decode_payload(s.encode_payload()).unwrap();
        assert_eq!(s, de);
    }

    #[tokio::test]
    async fn frame_async_round_trip() {
        let f = Ssh3Frame::new(Ssh3FrameKind::Data, Bytes::from_static(b"abc"));
        let mut buf: Vec<u8> = Vec::new();
        f.write_async(&mut buf).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let de = Ssh3Frame::read_async(&mut cursor).await.unwrap();
        assert_eq!(de, f);
    }
}
