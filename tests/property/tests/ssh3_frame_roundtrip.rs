//! Property: every typed SSH3 frame and payload survives `encode → decode`
//! as the identity transformation.

use arbitrary::Unstructured;
use bytes::Bytes;
use spt_property_tests::run_property;
use spt_ssh3::frame::{
    ChannelOpenPayload, ForwardOpenResponse, Ssh3Frame, Ssh3FrameKind, Ssh3Settings,
    UdpAssociatePayload,
};

fn arb_kind(u: &mut Unstructured<'_>) -> arbitrary::Result<Ssh3FrameKind> {
    Ok(match u.int_in_range(0u8..=7)? {
        0 => Ssh3FrameKind::Settings,
        1 => Ssh3FrameKind::DirectTcpRequest,
        2 => Ssh3FrameKind::ForwardOpenResponse,
        3 => Ssh3FrameKind::Data,
        4 => Ssh3FrameKind::Close,
        5 => Ssh3FrameKind::UdpAssociate,
        6 => Ssh3FrameKind::AppPing,
        _ => Ssh3FrameKind::RemoteUdpForwardRequest,
    })
}

fn arb_string(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let len = u.int_in_range(0u16..=64)? as usize;
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        // Printable ASCII keeps the property focused on framing — UTF-8
        // decoding is exercised separately via the fuzz target.
        let c: u8 = u.int_in_range(32u8..=126)?;
        s.push(c as char);
    }
    Ok(s)
}

// ---- Properties (10 invariants) -------------------------------------------

#[test]
fn frame_envelope_roundtrip() {
    run_property("frame_envelope_roundtrip", |u| {
        let kind = arb_kind(u)?;
        let len = u.int_in_range(0u16..=256)? as usize;
        let mut payload = vec![0u8; len];
        u.fill_buffer(&mut payload)?;
        let f = Ssh3Frame::new(kind, Bytes::from(payload));
        let mut buf = f.encode();
        let de = Ssh3Frame::decode(&mut buf).expect("decode round-trip");
        assert_eq!(de, f);
        assert!(buf.is_empty(), "decoder did not consume entire frame");
        Ok(())
    });
}

#[test]
fn frame_envelope_concat_roundtrip() {
    run_property("frame_envelope_concat_roundtrip", |u| {
        let n = u.int_in_range(2u8..=4)?;
        let mut frames = Vec::new();
        let mut concat = Vec::new();
        for _ in 0..n {
            let kind = arb_kind(u)?;
            let len = u.int_in_range(0u8..=32)? as usize;
            let mut payload = vec![0u8; len];
            u.fill_buffer(&mut payload)?;
            let f = Ssh3Frame::new(kind, Bytes::from(payload));
            concat.extend_from_slice(&f.encode());
            frames.push(f);
        }
        let mut buf = Bytes::from(concat);
        for expected in frames {
            let de = Ssh3Frame::decode(&mut buf).expect("decode chained frame");
            assert_eq!(de, expected);
        }
        assert!(buf.is_empty());
        Ok(())
    });
}

#[test]
fn channel_open_payload_roundtrip() {
    run_property("channel_open_payload_roundtrip", |u| {
        let host = arb_string(u)?;
        let port = u.int_in_range(0u16..=65_535)?;
        let p = ChannelOpenPayload { host, port };
        let de = ChannelOpenPayload::decode(p.encode()).expect("decode");
        assert_eq!(p, de);
        Ok(())
    });
}

#[test]
fn forward_open_response_roundtrip() {
    run_property("forward_open_response_roundtrip", |u| {
        let ok: bool = u.arbitrary()?;
        let reason = arb_string(u)?;
        let p = ForwardOpenResponse { ok, reason };
        let de = ForwardOpenResponse::decode(p.encode()).expect("decode");
        assert_eq!(p, de);
        Ok(())
    });
}

#[test]
fn udp_associate_payload_roundtrip() {
    run_property("udp_associate_payload_roundtrip", |u| {
        let flow_id = u.arbitrary::<u32>()?;
        let host = arb_string(u)?;
        let port = u.int_in_range(0u16..=65_535)?;
        let p = UdpAssociatePayload {
            flow_id,
            host,
            port,
        };
        let de = UdpAssociatePayload::decode(p.encode()).expect("decode");
        assert_eq!(p, de);
        Ok(())
    });
}

#[test]
fn settings_payload_roundtrip() {
    run_property("settings_payload_roundtrip", |u| {
        let s = Ssh3Settings {
            direct_tcp: u.arbitrary()?,
            remote_tcp: u.arbitrary()?,
            udp_datagrams: u.arbitrary()?,
            agent_forwarding: u.arbitrary()?,
            max_forwards: if u.arbitrary()? {
                Some(u.int_in_range(1u32..=4096)?)
            } else {
                None
            },
            version: if u.arbitrary()? {
                // Encoder collapses Some("") → None on decode (empty
                // version string is wire-indistinguishable from absent),
                // so we ensure non-empty before declaring Some.
                let mut s = arb_string(u)?;
                if s.is_empty() {
                    s.push('v');
                }
                Some(s)
            } else {
                None
            },
            extras: vec![],
        };
        let de = Ssh3Settings::decode_payload(s.encode_payload()).expect("decode");
        assert_eq!(s, de);
        Ok(())
    });
}

#[test]
fn frame_kind_from_u8_roundtrip() {
    run_property("frame_kind_from_u8_roundtrip", |u| {
        let kind = arb_kind(u)?;
        let raw = kind as u8;
        let back = Ssh3FrameKind::from_u8(raw).expect("kind round-trip");
        assert_eq!(kind, back);
        Ok(())
    });
}

#[test]
fn empty_payload_frame_roundtrip() {
    run_property("empty_payload_frame_roundtrip", |u| {
        let kind = arb_kind(u)?;
        let f = Ssh3Frame::new(kind, Bytes::new());
        let mut buf = f.encode();
        let de = Ssh3Frame::decode(&mut buf).expect("decode");
        assert_eq!(de, f);
        Ok(())
    });
}

#[test]
fn channel_open_empty_host_roundtrip() {
    run_property("channel_open_empty_host_roundtrip", |u| {
        let p = ChannelOpenPayload {
            host: String::new(),
            port: u.int_in_range(0u16..=65_535)?,
        };
        let de = ChannelOpenPayload::decode(p.encode()).expect("decode");
        assert_eq!(p, de);
        Ok(())
    });
}

#[test]
fn settings_with_all_flags_set() {
    run_property("settings_with_all_flags_set", |_u| {
        let s = Ssh3Settings {
            direct_tcp: true,
            remote_tcp: true,
            udp_datagrams: true,
            agent_forwarding: true,
            max_forwards: Some(4096),
            version: Some("spt/1".into()),
            extras: vec![],
        };
        let de = Ssh3Settings::decode_payload(s.encode_payload()).expect("decode");
        assert_eq!(s, de);
        Ok(())
    });
}
