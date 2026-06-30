//! Integration test for the SSH3 remote-UDP forward path (spt↔spt).
//!
//! Brings up two `quinn::Endpoint`s on localhost. The "client" side opens a
//! [`UdpForwardSpec`] with `direction = Remote`, which sends a
//! [`Ssh3FrameKind::RemoteUdpForwardRequest`] frame on the control stream.
//! The "server" side runs [`spt_ssh3::forward::serve_remote_udp_forwards`]
//! which binds a UDP listener on the requested address and proxies inbound
//! datagrams as `[u32_be flow_id][bytes]` QUIC datagrams toward the client.
//! The client's local target is an in-test echo socket whose replies the
//! client-side forward bounces back over the QUIC datagram channel; the
//! server reflects the reply to the most recent external sender.
//!
//! Wire-compat caveat: spt↔spt only — the
//! [`Ssh3FrameKind::RemoteUdpForwardRequest`] tag (0x08) and payload
//! shape are the spt-internal contract, not bit-compatible with
//! francoismichel/ssh3's reference framing.

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
use spt_protocol::forward::{ForwardDirection, ForwardRateLimits, UdpForwardSpec};
use spt_protocol::session::{SessionInfo, TunnelSession};
use spt_ssh3::forward::{serve_datagram_demux, serve_remote_udp_forwards, SessionState};
use spt_ssh3::frame::Ssh3Settings;
use spt_ssh3::{accept_control_stream, open_control_stream, Ssh3Session};
use tokio::net::UdpSocket;
use tokio::sync::Mutex as AsyncMutex;

fn install_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

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
async fn remote_udp_forward_round_trips_payload() {
    let (client_conn, server_conn) = connected_pair().await;

    // Drive the SSH3 control-stream handshake on both sides.
    let (cs_res, sv_res) = tokio::join!(
        open_control_stream(&client_conn, local_settings()),
        accept_control_stream(&server_conn, local_settings()),
    );
    let (c_send, c_recv, c_peer) = cs_res.unwrap();
    let (s_send, s_recv, _s_peer) = sv_res.unwrap();

    // Server side: spawn the remote-UDP acceptor against its control-stream
    // recv half. We need its own SessionState so the inbound datagram demux
    // (replies from client → server) can deliver via flow_id; but since
    // we're not running a real Ssh3Session on the server side here, we also
    // need to drive the read_datagram loop ourselves. For this echo test
    // the server doesn't need to receive replies — the client-side forward
    // just sends one datagram, the local target echoes, and the client
    // reflects via the QUIC datagram channel.
    let server_state = Arc::new(SessionState::default());
    let server_send = Arc::new(AsyncMutex::new(s_send));
    let acceptor = tokio::spawn(serve_remote_udp_forwards(
        server_conn.clone(),
        s_recv,
        server_send,
        server_state.clone(),
    ));
    let demux = tokio::spawn(serve_datagram_demux(
        server_conn.clone(),
        server_state.clone(),
    ));

    // Client side: stand up a proper Ssh3Session so that inbound datagrams
    // get demuxed by flow_id into our state.udp_flows map.
    let mut client_session: Box<dyn TunnelSession> = Box::new(Ssh3Session::from_parts(
        client_conn.clone(),
        c_send,
        c_recv,
        c_peer,
        dummy_info("client"),
        None,
    ));

    // Local "target" UDP echo socket — the client-side forward will dial
    // here for each datagram it receives over QUIC.
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match echo.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let _ = echo.send_to(&buf[..n], peer).await;
                }
                Err(_) => break,
            }
        }
    });

    // Pick a free port for the server-side bind. Bind+drop to claim a port
    // the OS won't immediately reassign.
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    let bind_addr = probe.local_addr().unwrap();
    drop(probe);

    // Open the remote UDP forward: server listens on `bind_addr`, dialing
    // back into the client-side handler which forwards to `echo_addr`.
    let spec = UdpForwardSpec {
        name: "rudp1".into(),
        direction: ForwardDirection::Remote,
        listen: BindAddr::Tcp(bind_addr),
        target: TargetAddr::new(echo_addr.ip().to_string(), echo_addr.port()),
        idle_timeout_secs: 30,
        max_flows: None,
        limits: ForwardRateLimits::default(),
    };
    let _h = client_session.open_udp_forward(&spec).await.unwrap();

    // Give the server a moment to process the request and bind the listener.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // External UDP "client" sends a packet to the server-bound listener.
    let external = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    external.connect(bind_addr).await.unwrap();
    let payload = b"hello-remote-udp";
    external.send(payload).await.unwrap();

    // Wait for the echo round-trip: server → QUIC → client → echo socket
    // → client → QUIC → server → external.
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), external.recv(&mut buf))
        .await
        .expect("remote-udp echo timeout")
        .unwrap();
    assert_eq!(&buf[..n], payload);

    // Cleanup.
    echo_task.abort();
    acceptor.abort();
    demux.abort();
    let _ = client_conn.close(0u32.into(), b"done");
    let _ = server_conn.close(0u32.into(), b"done");
}

/// M5: a peer flooding `RemoteUdpForwardRequest` frames must be bounded by the
/// `inbound_forward_limit` semaphore. With `max_forwards = 1` the server binds
/// the first requested listener (which holds the only permit for its lifetime)
/// and silently drops every later request — so only the first forward works.
#[tokio::test]
async fn remote_udp_forward_flood_bounded_by_semaphore() {
    let (client_conn, server_conn) = connected_pair().await;

    let (cs_res, sv_res) = tokio::join!(
        open_control_stream(&client_conn, local_settings()),
        accept_control_stream(&server_conn, local_settings()),
    );
    let (c_send, c_recv, c_peer) = cs_res.unwrap();
    let (s_send, s_recv, _s_peer) = sv_res.unwrap();

    // Server caps inbound forwards at ONE.
    let server_state = Arc::new(SessionState::with_max_forwards(Some(1)));
    let server_send = Arc::new(AsyncMutex::new(s_send));
    let acceptor = tokio::spawn(serve_remote_udp_forwards(
        server_conn.clone(),
        s_recv,
        server_send,
        server_state.clone(),
    ));
    let demux = tokio::spawn(serve_datagram_demux(
        server_conn.clone(),
        server_state.clone(),
    ));

    let mut client_session: Box<dyn TunnelSession> = Box::new(Ssh3Session::from_parts(
        client_conn.clone(),
        c_send,
        c_recv,
        c_peer,
        dummy_info("client"),
        None,
    ));

    // One local echo socket; both forwards point their client-side target at it.
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match echo.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let _ = echo.send_to(&buf[..n], peer).await;
                }
                Err(_) => break,
            }
        }
    });

    // Claim two distinct server-bind ports.
    let probe_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    let bind_a = probe_a.local_addr().unwrap();
    drop(probe_a);
    let probe_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    let bind_b = probe_b.local_addr().unwrap();
    drop(probe_b);

    let mk_spec = |name: &str, bind: SocketAddr| UdpForwardSpec {
        name: name.into(),
        direction: ForwardDirection::Remote,
        listen: BindAddr::Tcp(bind),
        target: TargetAddr::new(echo_addr.ip().to_string(), echo_addr.port()),
        idle_timeout_secs: 30,
        max_flows: None,
        limits: ForwardRateLimits::default(),
    };

    // Forward A is requested first → acquires the single permit and binds.
    let _ha = client_session
        .open_udp_forward(&mk_spec("rudp-a", bind_a))
        .await
        .unwrap();
    // Forward B is requested second → semaphore is exhausted → dropped server-side.
    let _hb = client_session
        .open_udp_forward(&mk_spec("rudp-b", bind_b))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(250)).await;

    // A must round-trip (its listener bound).
    let ext_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    ext_a.connect(bind_a).await.unwrap();
    ext_a.send(b"to-a").await.unwrap();
    let mut buf = [0u8; 64];
    let got_a = tokio::time::timeout(Duration::from_secs(5), ext_a.recv(&mut buf))
        .await
        .expect("forward A (within cap) must echo")
        .unwrap();
    assert_eq!(&buf[..got_a], b"to-a");

    // B must NOT round-trip — no listener was bound for it (over the cap), so
    // the datagram goes nowhere and the recv times out.
    let ext_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    ext_b.connect(bind_b).await.unwrap();
    ext_b.send(b"to-b").await.unwrap();
    let mut buf_b = [0u8; 64];
    let res_b = tokio::time::timeout(Duration::from_millis(800), ext_b.recv(&mut buf_b)).await;
    // B must NOT echo: acceptable outcomes are a timeout (no listener bound) or
    // a recv error (e.g. ICMP port-unreachable / WSAECONNRESET on Windows). The
    // only failure is a *successful* echo of the payload, which would mean the
    // over-cap forward bound a listener.
    let b_echoed = matches!(res_b, Ok(Ok(n)) if &buf_b[..n] == b"to-b");
    assert!(
        !b_echoed,
        "forward B (over cap) must NOT bind/echo — semaphore should have dropped it (got {res_b:?})"
    );

    echo_task.abort();
    acceptor.abort();
    demux.abort();
    let _ = client_conn.close(0u32.into(), b"done");
    let _ = server_conn.close(0u32.into(), b"done");
}

/// M5 (UDS path): a peer flooding `RemoteUdsForwardRequest` frames is bounded
/// by the same `inbound_forward_limit` semaphore. With `max_forwards = 1` one
/// request is ACKed `ok:true` (binds the listener, holds the permit) and the
/// over-cap request is rejected `ok:false` — so across two requests we observe
/// exactly one accept and one rejection (ACK order races, but content does
/// not).
#[cfg(unix)]
#[tokio::test]
async fn remote_uds_forward_flood_bounded_by_semaphore() {
    use spt_ssh3::frame::{ForwardOpenResponse, Ssh3Frame, Ssh3FrameKind, UdsChannelOpenPayload};

    let (client_conn, server_conn) = connected_pair().await;

    let (cs_res, sv_res) = tokio::join!(
        open_control_stream(&client_conn, local_settings()),
        accept_control_stream(&server_conn, local_settings()),
    );
    let (mut c_send, mut c_recv, _c_peer) = cs_res.unwrap();
    let (s_send, s_recv, _s_peer) = sv_res.unwrap();

    let server_state = Arc::new(SessionState::with_max_forwards(Some(1)));
    let server_send = Arc::new(AsyncMutex::new(s_send));
    let acceptor = tokio::spawn(serve_remote_udp_forwards(
        server_conn.clone(),
        s_recv,
        server_send,
        server_state.clone(),
    ));

    // Two distinct remote bind paths in the temp dir.
    let uniq = std::process::id();
    let path_a = std::env::temp_dir().join(format!("spt-ssh3-uds-flood-a-{uniq}.sock"));
    let path_b = std::env::temp_dir().join(format!("spt-ssh3-uds-flood-b-{uniq}.sock"));
    let _ = std::fs::remove_file(&path_a);
    let _ = std::fs::remove_file(&path_b);

    for p in [&path_a, &path_b] {
        let frame = Ssh3Frame::new(
            Ssh3FrameKind::RemoteUdsForwardRequest,
            UdsChannelOpenPayload {
                path: p.to_string_lossy().into_owned(),
            }
            .encode(),
        );
        frame.write_async(&mut c_send).await.unwrap();
    }

    // Read both ACKs (order between the accept task and the cap-reject path is
    // not deterministic, so collect and assert on the multiset).
    let mut oks = Vec::new();
    for _ in 0..2 {
        let frame =
            tokio::time::timeout(Duration::from_secs(5), Ssh3Frame::read_async(&mut c_recv))
                .await
                .expect("ack within deadline")
                .expect("ack frame");
        assert_eq!(frame.kind, Ssh3FrameKind::ForwardOpenResponse);
        oks.push(ForwardOpenResponse::decode(frame.payload).unwrap().ok);
    }
    let accepted = oks.iter().filter(|&&ok| ok).count();
    let rejected = oks.iter().filter(|&&ok| !ok).count();
    assert_eq!(
        accepted, 1,
        "exactly one remote-uds forward accepted under cap=1"
    );
    assert_eq!(
        rejected, 1,
        "the over-cap remote-uds forward must be rejected"
    );

    acceptor.abort();
    let _ = std::fs::remove_file(&path_a);
    let _ = std::fs::remove_file(&path_b);
    let _ = client_conn.close(0u32.into(), b"done");
    let _ = server_conn.close(0u32.into(), b"done");
}
