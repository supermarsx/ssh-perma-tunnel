//! Emit valid SSH3 frames of every kind plus boundary cases.

use bytes::{Bytes, BytesMut, BufMut};
use spt_fuzz_generators::{out_dir_from_args, write_file};
use spt_ssh3::frame::{
    ChannelOpenPayload, ForwardOpenResponse, Ssh3Frame, Ssh3FrameKind, Ssh3Settings,
    UdpAssociatePayload,
};

fn frame(kind: Ssh3FrameKind, payload: Bytes) -> Vec<u8> {
    let bytes = Ssh3Frame::new(kind, payload).encode();
    // Round-trip sanity.
    let mut b = bytes.clone();
    let _ = Ssh3Frame::decode(&mut b).expect("frame round-trip");
    bytes.to_vec()
}

fn main() {
    let dir = out_dir_from_args();

    // Settings frame: empty, all-flags, typical, with version, max_forwards.
    {
        let s = Ssh3Settings::default();
        write_file(&dir, "valid_settings_empty.bin",
            &frame(Ssh3FrameKind::Settings, s.encode_payload()));
    }
    {
        let s = Ssh3Settings {
            direct_tcp: true,
            remote_tcp: true,
            udp_datagrams: true,
            agent_forwarding: true,
            max_forwards: Some(64),
            version: Some("spt-fuzz/0.1".to_string()),
            extras: Vec::new(),
        };
        write_file(&dir, "valid_settings_full.bin",
            &frame(Ssh3FrameKind::Settings, s.encode_payload()));
    }
    {
        let s = Ssh3Settings {
            direct_tcp: true,
            remote_tcp: false,
            udp_datagrams: false,
            agent_forwarding: false,
            max_forwards: None,
            version: None,
            extras: Vec::new(),
        };
        write_file(&dir, "valid_settings_only_direct.bin",
            &frame(Ssh3FrameKind::Settings, s.encode_payload()));
    }
    {
        let s = Ssh3Settings {
            udp_datagrams: true,
            max_forwards: Some(u32::MAX),
            version: Some("a".repeat(512)),
            ..Default::default()
        };
        write_file(&dir, "valid_settings_long_version.bin",
            &frame(Ssh3FrameKind::Settings, s.encode_payload()));
    }

    // ChannelOpen / DirectTcpRequest: ipv4, ipv6 literal, hostname, ports.
    for (name, host, port) in [
        ("valid_chopen_ipv4.bin", "127.0.0.1", 22u16),
        ("valid_chopen_ipv6.bin", "::1", 8443),
        ("valid_chopen_hostname.bin", "svc.internal.example.com", 80),
        ("valid_chopen_unicode.bin", "ホスト.example", 443),
        ("valid_chopen_port_zero.bin", "h", 0),
        ("valid_chopen_port_max.bin", "h", u16::MAX),
        ("valid_chopen_long_host.bin", &"x".repeat(253), 443),
    ] {
        let p = ChannelOpenPayload { host: host.to_string(), port };
        write_file(&dir, name, &frame(Ssh3FrameKind::DirectTcpRequest, p.encode()));
    }

    // ForwardOpenResponse: ok / err / long reason / empty reason.
    for (name, ok, reason) in [
        ("valid_fwdresp_ok.bin", true, ""),
        ("valid_fwdresp_err.bin", false, "connection refused"),
        ("valid_fwdresp_long_reason.bin", false, &"r".repeat(2048) as &str),
        ("valid_fwdresp_unicode.bin", false, "拒否されました"),
    ] {
        let p = ForwardOpenResponse { ok, reason: reason.to_string() };
        write_file(&dir, name, &frame(Ssh3FrameKind::ForwardOpenResponse, p.encode()));
    }

    // UdpAssociate.
    for (name, flow_id, host, port) in [
        ("valid_udp_minimal.bin", 1u32, "h", 53u16),
        ("valid_udp_max_flow.bin", u32::MAX, "1.1.1.1", 53),
        ("valid_udp_ipv6.bin", 7, "[::1]", 53),
        ("valid_udp_long_host.bin", 42, &"u".repeat(255) as &str, 65535),
    ] {
        let p = UdpAssociatePayload { flow_id, host: host.to_string(), port };
        write_file(&dir, name, &frame(Ssh3FrameKind::UdpAssociate, p.encode()));
    }

    // Data, Close, AppPing.
    write_file(&dir, "valid_data_empty.bin",
        &frame(Ssh3FrameKind::Data, Bytes::new()));
    write_file(&dir, "valid_data_hello.bin",
        &frame(Ssh3FrameKind::Data, Bytes::from_static(b"hello")));
    write_file(&dir, "valid_data_8k.bin",
        &frame(Ssh3FrameKind::Data, Bytes::from(vec![0x42u8; 8192])));
    write_file(&dir, "valid_close.bin",
        &frame(Ssh3FrameKind::Close, Bytes::new()));
    write_file(&dir, "valid_appping.bin",
        &frame(Ssh3FrameKind::AppPing, Bytes::from_static(b"ping")));

    // Multi-frame concatenations (the harness loops decode up to 16 times).
    {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&Ssh3Frame::new(Ssh3FrameKind::Settings, Ssh3Settings::default().encode_payload()).encode());
        buf.extend_from_slice(&Ssh3Frame::new(Ssh3FrameKind::Data, Bytes::from_static(b"hi")).encode());
        buf.extend_from_slice(&Ssh3Frame::new(Ssh3FrameKind::AppPing, Bytes::new()).encode());
        write_file(&dir, "valid_multi_frame.bin", &buf);
    }

    // Boundaries --------------------------------------------------------
    write_file(&dir, "boundary_empty.bin", b"");
    write_file(&dir, "boundary_one_byte.bin", &[0x01]);
    write_file(&dir, "boundary_short_header_4.bin", &[0x01, 0x00, 0x00, 0x00]);
    write_file(&dir, "boundary_unknown_kind.bin",
        &[0xFF, 0x00, 0x00, 0x00, 0x00]);
    write_file(&dir, "boundary_huge_len.bin",
        &[0x04, 0xFF, 0xFF, 0xFF, 0xFF]);
    write_file(&dir, "boundary_truncated_payload.bin",
        &[0x04, 0x00, 0x00, 0x00, 0x10, b'a', b'b']);
    write_file(&dir, "boundary_zero_len_data.bin",
        &[0x04, 0x00, 0x00, 0x00, 0x00]);
    {
        // ChannelOpenPayload with hlen pointing past end of payload.
        let mut p = BytesMut::new();
        p.put_u16(0xFFFF);
        p.put_u8(0xAA); // partial host
        write_file(&dir, "boundary_chopen_hlen_overflow.bin",
            &frame(Ssh3FrameKind::DirectTcpRequest, p.freeze()));
    }
    {
        // Settings payload truncated mid-version.
        let mut p = BytesMut::new();
        p.put_u8(0x0F);
        p.put_u32(1);
        p.put_u16(64); // claims 64 bytes of version
        p.put_slice(b"abc"); // only 3
        write_file(&dir, "boundary_settings_truncated_version.bin",
            &frame(Ssh3FrameKind::Settings, p.freeze()));
    }

    println!("ssh3_frame: corpus generated under {}", dir.display());
}
