//! Integration tests for the SSH3 control-stream handshake against an
//! injected duplex transport.
//!
//! `crate::transport::open_control_stream` and `accept_control_stream` are
//! coupled to `quinn::Connection`, but the handshake logic on top is just
//! `Ssh3Frame::write_async` / `read_async` over a bidirectional byte pipe.
//! These tests mirror that logic on top of a `tokio::io::duplex` pair —
//! the public frame layer is the unit under test, the duplex stand-in
//! validates that the framing has no implicit dependency on QUIC stream
//! semantics.
//!
//! Real `quinn::Connection` coverage is exercised by `two_endpoints.rs`
//! when ring TLS is available; this file complements that with a
//! transport-free path that runs in every environment.

#![allow(clippy::missing_assert_message)]

use bytes::Bytes;
use spt_core::Error;
use spt_ssh3::frame::{
    ChannelOpenPayload, ForwardOpenResponse, Ssh3Frame, Ssh3FrameKind, Ssh3Settings,
    UdpAssociatePayload,
};
use tokio::io::duplex;

/// Helper mirroring `open_control_stream`'s body for an `AsyncRead+Write`
/// pair (no quinn dependency).
async fn open_control_pair<S>(stream: &mut S, local: Ssh3Settings) -> Result<Ssh3Settings, Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let our = Ssh3Frame::new(Ssh3FrameKind::Settings, local.encode_payload());
    our.write_async(stream).await?;
    let frame = Ssh3Frame::read_async(stream).await?;
    if frame.kind != Ssh3FrameKind::Settings {
        return Err(Error::RuntimeFailure(format!(
            "expected Settings, got {:?}",
            frame.kind
        )));
    }
    Ssh3Settings::decode_payload(frame.payload)
}

/// Server-side counterpart.
async fn accept_control_pair<S>(stream: &mut S, local: Ssh3Settings) -> Result<Ssh3Settings, Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let frame = Ssh3Frame::read_async(stream).await?;
    if frame.kind != Ssh3FrameKind::Settings {
        return Err(Error::RuntimeFailure(format!(
            "expected Settings, got {:?}",
            frame.kind
        )));
    }
    let peer = Ssh3Settings::decode_payload(frame.payload)?;
    let ours = Ssh3Frame::new(Ssh3FrameKind::Settings, local.encode_payload());
    ours.write_async(stream).await?;
    Ok(peer)
}

#[tokio::test]
async fn control_handshake_over_duplex_roundtrips_settings() {
    let (mut client, mut server) = duplex(8192);

    let client_local = Ssh3Settings {
        direct_tcp: true,
        remote_tcp: true,
        udp_datagrams: true,
        agent_forwarding: false,
        max_forwards: Some(8),
        version: Some("client/0.1".into()),
        extras: vec![],
    };
    let server_local = Ssh3Settings {
        direct_tcp: true,
        remote_tcp: false,
        udp_datagrams: true,
        agent_forwarding: false,
        max_forwards: Some(32),
        version: Some("server/0.1".into()),
        extras: vec![],
    };

    let (client_seen, server_seen) = tokio::join!(
        open_control_pair(&mut client, client_local.clone()),
        accept_control_pair(&mut server, server_local.clone()),
    );
    let client_seen = client_seen.unwrap();
    let server_seen = server_seen.unwrap();

    // Each side sees the other's advertised settings (sans `extras`
    // which the wire encoder drops).
    assert_eq!(client_seen.direct_tcp, server_local.direct_tcp);
    assert_eq!(client_seen.remote_tcp, server_local.remote_tcp);
    assert_eq!(client_seen.udp_datagrams, server_local.udp_datagrams);
    assert_eq!(client_seen.max_forwards, server_local.max_forwards);
    assert_eq!(client_seen.version, server_local.version);

    assert_eq!(server_seen.direct_tcp, client_local.direct_tcp);
    assert_eq!(server_seen.remote_tcp, client_local.remote_tcp);
    assert_eq!(server_seen.version, client_local.version);
}

#[tokio::test]
async fn handshake_rejects_non_settings_first_frame() {
    let (mut client, mut server) = duplex(4096);
    let client_local = Ssh3Settings {
        direct_tcp: true,
        ..Default::default()
    };

    // The server sends a Data frame instead of Settings.
    let server_task = tokio::spawn(async move {
        let f = Ssh3Frame::new(Ssh3FrameKind::Data, Bytes::from_static(b"nope"));
        f.write_async(&mut server).await.unwrap();
    });

    let err = open_control_pair(&mut client, client_local).await.unwrap_err();
    match err {
        Error::RuntimeFailure(msg) => assert!(msg.contains("Settings")),
        _ => panic!("wrong variant: {err:?}"),
    }
    server_task.await.unwrap();
}

#[tokio::test]
async fn handshake_propagates_eof_as_runtime_failure() {
    let (mut client, server) = duplex(2048);
    drop(server); // EOF immediately.

    let client_local = Ssh3Settings::default();
    let err = open_control_pair(&mut client, client_local).await.unwrap_err();
    assert!(matches!(err, Error::RuntimeFailure(_)));
}

#[tokio::test]
async fn channel_open_request_response_roundtrip_over_duplex() {
    let (mut client, mut server) = duplex(8192);

    let target_host = "target.invalid";
    let target_port = 9090u16;

    // Server task: read open frame, send OK response.
    let server_task = tokio::spawn(async move {
        let frame = Ssh3Frame::read_async(&mut server).await.unwrap();
        assert_eq!(frame.kind, Ssh3FrameKind::DirectTcpRequest);
        let open = ChannelOpenPayload::decode(frame.payload).unwrap();
        assert_eq!(open.host, target_host);
        assert_eq!(open.port, target_port);

        let resp = Ssh3Frame::new(
            Ssh3FrameKind::ForwardOpenResponse,
            ForwardOpenResponse {
                ok: true,
                reason: String::new(),
            }
            .encode(),
        );
        resp.write_async(&mut server).await.unwrap();
    });

    // Client: send open, read response.
    let req = Ssh3Frame::new(
        Ssh3FrameKind::DirectTcpRequest,
        ChannelOpenPayload {
            host: target_host.into(),
            port: target_port,
        }
        .encode(),
    );
    req.write_async(&mut client).await.unwrap();
    let resp = Ssh3Frame::read_async(&mut client).await.unwrap();
    assert_eq!(resp.kind, Ssh3FrameKind::ForwardOpenResponse);
    let parsed = ForwardOpenResponse::decode(resp.payload).unwrap();
    assert!(parsed.ok);
    assert!(parsed.reason.is_empty());

    server_task.await.unwrap();
}

#[tokio::test]
async fn channel_open_rejection_carries_reason_over_duplex() {
    let (mut client, mut server) = duplex(8192);

    let server_task = tokio::spawn(async move {
        let _ = Ssh3Frame::read_async(&mut server).await.unwrap();
        let resp = Ssh3Frame::new(
            Ssh3FrameKind::ForwardOpenResponse,
            ForwardOpenResponse {
                ok: false,
                reason: "policy denial".into(),
            }
            .encode(),
        );
        resp.write_async(&mut server).await.unwrap();
    });

    let req = Ssh3Frame::new(
        Ssh3FrameKind::DirectTcpRequest,
        ChannelOpenPayload {
            host: "h".into(),
            port: 1,
        }
        .encode(),
    );
    req.write_async(&mut client).await.unwrap();
    let resp = Ssh3Frame::read_async(&mut client).await.unwrap();
    let parsed = ForwardOpenResponse::decode(resp.payload).unwrap();
    assert!(!parsed.ok);
    assert_eq!(parsed.reason, "policy denial");

    server_task.await.unwrap();
}

#[tokio::test]
async fn udp_associate_payload_roundtrips_via_frame_over_duplex() {
    let (mut a, mut b) = duplex(4096);

    let assoc = UdpAssociatePayload {
        flow_id: 0xdead_beef,
        host: "udp.example".into(),
        port: 5300,
    };
    let frame = Ssh3Frame::new(Ssh3FrameKind::UdpAssociate, assoc.encode());

    let writer = tokio::spawn(async move {
        frame.write_async(&mut a).await.unwrap();
    });

    let received = Ssh3Frame::read_async(&mut b).await.unwrap();
    writer.await.unwrap();

    assert_eq!(received.kind, Ssh3FrameKind::UdpAssociate);
    let parsed = UdpAssociatePayload::decode(received.payload).unwrap();
    assert_eq!(parsed.flow_id, 0xdead_beef);
    assert_eq!(parsed.host, "udp.example");
    assert_eq!(parsed.port, 5300);
}

#[tokio::test]
async fn multiple_frames_back_to_back_over_duplex() {
    // Pipe several distinct frame kinds through the same byte stream and
    // confirm they decode in order. Exercises the read_async/write_async
    // contract that frames don't bleed across boundaries.
    let (mut a, mut b) = duplex(8192);
    let frames = vec![
        Ssh3Frame::new(Ssh3FrameKind::AppPing, Bytes::new()),
        Ssh3Frame::new(Ssh3FrameKind::Data, Bytes::from_static(b"hello")),
        Ssh3Frame::new(Ssh3FrameKind::Close, Bytes::new()),
    ];
    let frames_clone = frames.clone();

    let writer = tokio::spawn(async move {
        for f in frames_clone {
            f.write_async(&mut a).await.unwrap();
        }
    });

    for expected in frames {
        let got = Ssh3Frame::read_async(&mut b).await.unwrap();
        assert_eq!(got, expected);
    }
    writer.await.unwrap();
}

#[tokio::test]
async fn handshake_rejects_settings_payload_corruption() {
    // Server sends a Settings frame whose payload is too short to decode.
    let (mut client, mut server) = duplex(2048);

    let server_task = tokio::spawn(async move {
        let bad = Ssh3Frame::new(Ssh3FrameKind::Settings, Bytes::from_static(&[0u8; 3]));
        bad.write_async(&mut server).await.unwrap();
    });

    let err = open_control_pair(&mut client, Ssh3Settings::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidConfig(_)));
    server_task.await.unwrap();
}
