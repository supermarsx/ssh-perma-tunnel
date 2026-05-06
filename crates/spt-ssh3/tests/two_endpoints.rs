//! End-to-end tests for the SSH3 channel framing layer.
//!
//! These tests stand up two `quinn::Endpoint`s on localhost (one client, one
//! server) over TLS 1.3 with a self-signed cert, then drive both ends of an
//! [`Ssh3Session`] without going through HTTP/3 at all (using
//! [`Ssh3Session::from_parts`] + [`open_control_stream`] /
//! [`accept_control_stream`]). This isolates the channel framing layer.
//!
//! Wire-compat caveat: these tests verify spt↔spt interop only. Real-server
//! interop is gated on the `SPT_SSH3_TEST_SERVER` integration test, which is
//! not provided here.

#![cfg(not(miri))]
#![allow(
    clippy::manual_let_else,
    clippy::let_unit_value,
    clippy::ignored_unit_patterns,
    clippy::while_let_loop
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use spt_core::BindAddr;
use spt_protocol::endpoint::TargetAddr;
use spt_protocol::forward::{
    ForwardDirection, LocalForwardSpec, RemoteForwardSpec, UdpForwardSpec,
};
use spt_protocol::session::{SessionInfo, TunnelSession};
use spt_ssh3::forward::serve_local_tcp_acceptor;
use spt_ssh3::frame::Ssh3Settings;
use spt_ssh3::{accept_control_stream, open_control_stream, Ssh3Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn install_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a (server-config, client-config) pair sharing a self-signed cert.
fn make_quic_pair() -> (ServerConfig, ClientConfig) {
    install_ring();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let mut server = ServerConfig::with_single_cert(vec![cert_der.clone()], key_der).unwrap();
    let mut tcfg = TransportConfig::default();
    tcfg.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    server.transport_config(Arc::new(tcfg));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let rustls_client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let quic_client_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client).unwrap();
    let mut client = ClientConfig::new(Arc::new(quic_client_crypto));
    let mut tcfg2 = TransportConfig::default();
    tcfg2.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    client.transport_config(Arc::new(tcfg2));

    (server, client)
}

/// Create a connected client/server pair of `quinn::Connection`s on localhost.
async fn connected_pair() -> (quinn::Connection, quinn::Connection) {
    let (server_cfg, client_cfg) = make_quic_pair();

    let server_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server_endpoint = Endpoint::server(server_cfg, server_addr).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let mut client_endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    client_endpoint.set_default_client_config(client_cfg);

    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        incoming.await.unwrap()
    });

    let client_conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let server_conn = server_handle.await.unwrap();
    (client_conn, server_conn)
}

fn local_settings() -> Ssh3Settings {
    Ssh3Settings {
        direct_tcp: true,
        remote_tcp: true,
        udp_datagrams: true,
        agent_forwarding: false,
        max_forwards: Some(8),
        version: Some("test/0.1".into()),
        extras: vec![],
    }
}

fn dummy_info(side: &str) -> SessionInfo {
    SessionInfo {
        backend: "ssh3".into(),
        peer_version: Some(side.to_string()),
        negotiated: Some("test".into()),
        established_at: 0,
    }
}

#[tokio::test]
async fn local_tcp_forward_round_trips_payload() {
    let (client_conn, server_conn) = connected_pair().await;

    // Set up the SSH3 control streams (client opens, server accepts).
    let (c_send, c_recv, c_peer) = {
        let client = open_control_stream(&client_conn, local_settings());
        let server = accept_control_stream(&server_conn, local_settings());
        let (c, _s) = tokio::join!(client, server);
        let (s, r, p) = c.unwrap();
        (s, r, p)
    };

    // The client side becomes an Ssh3Session.
    let mut session: Box<dyn TunnelSession> = Box::new(Ssh3Session::from_parts(
        client_conn.clone(),
        c_send,
        c_recv,
        c_peer,
        dummy_info("client"),
        None,
    ));

    // On the server side: spawn a "fake server" acceptor that bridges every
    // incoming bidi stream to a real TCP echo server.
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match echo_listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let echo_addr_resolved = echo_addr;
    let server_conn_a = server_conn.clone();
    let acceptor = tokio::spawn(async move {
        serve_local_tcp_acceptor(server_conn_a, move |_open| {
            Some(TargetAddr::new(
                echo_addr_resolved.ip().to_string(),
                echo_addr_resolved.port(),
            ))
        })
        .await;
    });

    // Open a local forward bound to a random local port, target = the echo
    // server (the server side resolves it via the resolver closure).
    let listen = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listen_addr = listen.local_addr().unwrap();
    drop(listen);
    let spec = LocalForwardSpec {
        name: "test-tcp".into(),
        listen: BindAddr::Tcp(listen_addr),
        target: TargetAddr::new("localhost", 9999), // ignored — resolver
        max_connections: None,
    };
    let _handle = session.open_local_forward(&spec).await.unwrap();

    // Connect to the local listener; write payload; expect echo.
    let mut client_sock = TcpStream::connect(listen_addr).await.unwrap();
    let payload: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
    client_sock.write_all(&payload).await.unwrap();
    client_sock.shutdown().await.unwrap();
    let mut got = Vec::with_capacity(payload.len());
    client_sock.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, payload);

    acceptor.abort();
    let _ = client_conn.close(0u32.into(), b"done");
    let _ = server_conn.close(0u32.into(), b"done");
}

#[tokio::test]
async fn local_tcp_forward_random_payload_round_trip() {
    // Property-style: random sizes, payload integrity assertion each.
    let (client_conn, server_conn) = connected_pair().await;

    let (c_send, c_recv, c_peer) = {
        let c = open_control_stream(&client_conn, local_settings());
        let s = accept_control_stream(&server_conn, local_settings());
        let (cl, _sv) = tokio::join!(c, s);
        cl.unwrap()
    };
    let mut session: Box<dyn TunnelSession> = Box::new(Ssh3Session::from_parts(
        client_conn.clone(),
        c_send,
        c_recv,
        c_peer,
        dummy_info("client"),
        None,
    ));

    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match echo_listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let acceptor = tokio::spawn(async move {
        serve_local_tcp_acceptor(server_conn, move |_| {
            Some(TargetAddr::new(echo_addr.ip().to_string(), echo_addr.port()))
        })
        .await;
    });

    let listen_probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listen_addr = listen_probe.local_addr().unwrap();
    drop(listen_probe);
    let _h = session
        .open_local_forward(&LocalForwardSpec {
            name: "rand".into(),
            listen: BindAddr::Tcp(listen_addr),
            target: TargetAddr::new("localhost", 1),
            max_connections: None,
        })
        .await
        .unwrap();

    // Deterministic xorshift64* PRNG (no extra crate needed).
    let mut state: u64 = 0xC0FF_EEBA_BEDE_ADF0;
    let mut next_byte = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D) as u8
    };
    for _ in 0..16 {
        let len = (usize::from(next_byte()) << 4) + 1;
        let payload: Vec<u8> = (0..len).map(|_| next_byte()).collect();
        let mut sock = TcpStream::connect(listen_addr).await.unwrap();
        sock.write_all(&payload).await.unwrap();
        sock.shutdown().await.unwrap();
        let mut got = Vec::new();
        sock.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, payload, "round-trip mismatch at len={len}");
    }
    acceptor.abort();
}

#[tokio::test]
async fn udp_forward_demuxes_by_flow_id() {
    let (client_conn, server_conn) = connected_pair().await;

    let (c_send, c_recv, c_peer) = {
        let c = open_control_stream(&client_conn, local_settings());
        let s = accept_control_stream(&server_conn, local_settings());
        let (cl, _) = tokio::join!(c, s);
        cl.unwrap()
    };
    let mut session: Box<dyn TunnelSession> = Box::new(Ssh3Session::from_parts(
        client_conn.clone(),
        c_send,
        c_recv,
        c_peer,
        dummy_info("client"),
        None,
    ));

    // Bind a local UDP socket that we will send packets *to* (acting as the
    // local app). The forward will relay to QUIC datagrams with flow-id prefix.
    let local_listen = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    let local_listen_addr = local_listen.local_addr().unwrap();
    drop(local_listen);

    let spec = UdpForwardSpec {
        name: "udp1".into(),
        direction: ForwardDirection::Local,
        listen: BindAddr::Tcp(local_listen_addr),
        target: TargetAddr::new("127.0.0.1", 1234),
        idle_timeout_secs: 30,
        max_flows: None,
    };
    let _h = session.open_udp_forward(&spec).await.unwrap();

    // Server side: read all incoming datagrams, echo them back (preserving the
    // flow-id prefix). For demux verification we just check that bytes after
    // the prefix round-trip.
    let server_conn_e = server_conn.clone();
    let echo = tokio::spawn(async move {
        loop {
            match server_conn_e.read_datagram().await {
                Ok(p) => {
                    let _ = server_conn_e.send_datagram(p);
                }
                Err(_) => break,
            }
        }
    });

    // Send three datagrams from a fake "local app" through the local UDP
    // socket the forward bound. The forward will tx them over QUIC; the echo
    // bounces them back; the forward delivers them to the original peer addr.
    let app = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    app.connect(local_listen_addr).await.unwrap();
    let payloads: Vec<Vec<u8>> = vec![b"ping-1".to_vec(), b"two".to_vec(), b"third".to_vec()];
    for p in &payloads {
        app.send(p).await.unwrap();
    }

    // Receive the echoes.
    let mut buf = [0u8; 2048];
    for expected in &payloads {
        let n = tokio::time::timeout(Duration::from_secs(5), app.recv(&mut buf))
            .await
            .expect("udp echo timeout")
            .unwrap();
        assert_eq!(&buf[..n], expected.as_slice());
    }

    echo.abort();
    let _ = client_conn.close(0u32.into(), b"done");
    let _ = server_conn.close(0u32.into(), b"done");
}

#[tokio::test]
async fn udp_forward_unsupported_when_peer_lacks_capability() {
    let (client_conn, server_conn) = connected_pair().await;

    // Server advertises NO udp_datagrams.
    let server_settings = Ssh3Settings {
        udp_datagrams: false,
        ..local_settings()
    };
    let (c_send, c_recv, c_peer) = {
        let c = open_control_stream(&client_conn, local_settings());
        let s = accept_control_stream(&server_conn, server_settings);
        let (cl, _) = tokio::join!(c, s);
        cl.unwrap()
    };
    assert!(!c_peer.udp_datagrams);

    let mut session: Box<dyn TunnelSession> = Box::new(Ssh3Session::from_parts(
        client_conn,
        c_send,
        c_recv,
        c_peer,
        dummy_info("client"),
        None,
    ));

    let listen_probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    let addr = listen_probe.local_addr().unwrap();
    drop(listen_probe);
    let err = session
        .open_udp_forward(&UdpForwardSpec {
            name: "no-udp".into(),
            direction: ForwardDirection::Local,
            listen: BindAddr::Tcp(addr),
            target: TargetAddr::new("127.0.0.1", 1),
            idle_timeout_secs: 30,
            max_flows: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, spt_core::Error::UnsupportedPlatform(_)));
}

#[tokio::test]
async fn remote_forward_round_trip() {
    use spt_ssh3::frame::{
        ChannelOpenPayload, ForwardOpenResponse, Ssh3Frame, Ssh3FrameKind,
    };
    let (client_conn, server_conn) = connected_pair().await;

    // Drive control-stream handshake; retain the server's halves so we can
    // hand-roll the tcpip-forward request handler.
    let (cs, sv) = tokio::join!(
        open_control_stream(&client_conn, local_settings()),
        accept_control_stream(&server_conn, local_settings()),
    );
    let (c_send, c_recv, c_peer) = cs.unwrap();
    let (mut s_send, mut s_recv, _s_peer) = sv.unwrap();

    let mut client_session: Box<dyn TunnelSession> = Box::new(Ssh3Session::from_parts(
        client_conn.clone(),
        c_send,
        c_recv,
        c_peer,
        dummy_info("client"),
        None,
    ));

    // Echo server the client's local end will connect to (target of the
    // remote forward).
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match echo_listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    // Server side: read the tcpip-forward request from the client; ack OK;
    // then open a fresh bidi stream toward the client carrying a
    // DirectTcpRequest with the client's bound (host, port). The client
    // dispatcher will look it up in remote_forwards and bridge to echo.
    let server_conn_back = server_conn.clone();
    let server_drive = tokio::spawn(async move {
        let req = Ssh3Frame::read_async(&mut s_recv).await.unwrap();
        assert_eq!(req.kind, Ssh3FrameKind::DirectTcpRequest);
        let parsed = ChannelOpenPayload::decode(req.payload).unwrap();
        // Accept it.
        Ssh3Frame::new(
            Ssh3FrameKind::ForwardOpenResponse,
            ForwardOpenResponse {
                ok: true,
                reason: String::new(),
            }
            .encode(),
        )
        .write_async(&mut s_send)
        .await
        .unwrap();

        // For each "inbound connection" we open a bidi from server → client
        // and replay the DirectTcpRequest.
        let (mut send, mut recv) = server_conn_back.open_bi().await.unwrap();
        Ssh3Frame::new(
            Ssh3FrameKind::DirectTcpRequest,
            ChannelOpenPayload {
                host: parsed.host.clone(),
                port: parsed.port,
            }
            .encode(),
        )
        .write_async(&mut send)
        .await
        .unwrap();
        // Read OK from client.
        let resp = Ssh3Frame::read_async(&mut recv).await.unwrap();
        assert_eq!(resp.kind, Ssh3FrameKind::ForwardOpenResponse);
        let r = ForwardOpenResponse::decode(resp.payload).unwrap();
        assert!(r.ok, "client rejected: {}", r.reason);

        // Server-side simulates "inbound TCP connection arrived on the
        // listener". It writes a payload onto the bidi (client will bridge it
        // to the echo target), then reads back the echo, then closes.
        let payload: &[u8] = b"remote-forward-payload";
        send.write_all(payload).await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(64 * 1024).await.unwrap();
        assert_eq!(echoed, payload);
    });

    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 7777));
    let _h = client_session
        .open_remote_forward(&RemoteForwardSpec {
            name: "remote".into(),
            listen: BindAddr::Tcp(bind),
            target: TargetAddr::new(echo_addr.ip().to_string(), echo_addr.port()),
            max_connections: None,
        })
        .await
        .unwrap();

    // Now wait for the server task to set up the inbound stream and bridge it
    // to the echo. The client doesn't actively trigger a connection — in our
    // simulated wire, the server itself decides when to forward. Let the
    // server task complete one full bridge.
    tokio::time::timeout(Duration::from_secs(5), server_drive)
        .await
        .unwrap()
        .unwrap();
}
