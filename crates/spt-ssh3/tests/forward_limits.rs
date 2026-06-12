//! Integration tests for SSH3 remote-forward dispatch safety properties:
//!
//! * **E3-F8** — the inbound-bidi dispatcher dials the local target *before*
//!   acking, so a peer never sees `ok:true` for a forward whose downstream is
//!   unreachable.
//! * **E3-F3** — the dispatcher enforces the negotiated `max_forwards` cap:
//!   inbound opens past the cap are rejected with `ok:false` rather than
//!   spawning unbounded bridge tasks.
//!
//! Both drive a real client [`Ssh3Session`] over a loopback QUIC pair and
//! hand-roll the *server* side (opening `forwarded-tcp` bidi streams toward the
//! client) so we can observe exactly what `ForwardOpenResponse` the client's
//! dispatcher returns.

#![cfg(not(miri))]
#![allow(clippy::manual_let_else, clippy::ignored_unit_patterns)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use spt_core::BindAddr;
use spt_protocol::endpoint::TargetAddr;
use spt_protocol::forward::RemoteForwardSpec;
use spt_protocol::handle::ForwardHandle;
use spt_protocol::session::{SessionInfo, TunnelSession};
use spt_ssh3::frame::{ChannelOpenPayload, ForwardOpenResponse, Ssh3Frame, Ssh3FrameKind, Ssh3Settings};
use spt_ssh3::{accept_control_stream, open_control_stream, Ssh3Session};
use tokio::net::TcpListener;

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

fn settings(max_forwards: Option<u32>) -> Ssh3Settings {
    Ssh3Settings {
        direct_tcp: true,
        remote_tcp: true,
        udp_datagrams: true,
        agent_forwarding: false,
        max_forwards,
        version: Some("test/0.1".into()),
        extras: vec![],
    }
}

fn dummy_info() -> SessionInfo {
    SessionInfo {
        backend: "ssh3".into(),
        peer_version: Some("client".into()),
        negotiated: Some("test".into()),
        established_at: 0,
    }
}

/// Drive the control-stream handshake and hand back the client session plus the
/// server-side control halves and connection. The client advertises
/// `client_max_forwards`; that value is what the *server*'s peer-settings see,
/// and it is what the client session uses to size its own inbound cap.
async fn setup(
    client_max_forwards: Option<u32>,
) -> (
    Box<dyn TunnelSession>,
    quinn::Connection,
    quinn::SendStream,
    quinn::RecvStream,
) {
    let (client_conn, server_conn) = connected_pair().await;
    let (cs, sv) = tokio::join!(
        open_control_stream(&client_conn, settings(client_max_forwards)),
        accept_control_stream(&server_conn, settings(client_max_forwards)),
    );
    let (c_send, c_recv, c_peer) = cs.unwrap();
    let (s_send, s_recv, _s_peer) = sv.unwrap();
    let session: Box<dyn TunnelSession> = Box::new(Ssh3Session::from_parts(
        client_conn.clone(),
        c_send,
        c_recv,
        c_peer,
        dummy_info(),
        None,
    ));
    (session, server_conn, s_send, s_recv)
}

/// Register a remote forward on the client side. Reads the `tcpip-forward`
/// request the client sends on the control stream and acks it. Returns the
/// [`ForwardHandle`]; the caller must keep it alive (dropping it closes the
/// forward and unregisters it).
async fn register_remote_forward(
    session: &mut Box<dyn TunnelSession>,
    s_send: &mut quinn::SendStream,
    s_recv: &mut quinn::RecvStream,
    target: TargetAddr,
    bind: SocketAddr,
) -> ForwardHandle {
    // The control-stream request handler must run concurrently with the
    // client's `open_remote_forward` (which blocks on the ACK).
    let server_ack = async {
        let req = Ssh3Frame::read_async(s_recv).await.unwrap();
        assert_eq!(req.kind, Ssh3FrameKind::DirectTcpRequest);
        let _parsed = ChannelOpenPayload::decode(req.payload).unwrap();
        Ssh3Frame::new(
            Ssh3FrameKind::ForwardOpenResponse,
            ForwardOpenResponse {
                ok: true,
                reason: String::new(),
            }
            .encode(),
        )
        .write_async(s_send)
        .await
        .unwrap();
    };
    let open = async {
        session
            .open_remote_forward(&RemoteForwardSpec {
                name: "rf".into(),
                listen: BindAddr::Tcp(bind),
                target,
                max_connections: None,
            })
            .await
            .unwrap()
    };
    let (_, handle) = tokio::join!(server_ack, open);
    handle
}

/// Open one inbound `forwarded-tcp` bidi stream toward the client for `(host,
/// port)` and return the `ForwardOpenResponse` the client's dispatcher sends,
/// **along with the stream halves**. The caller must keep the returned halves
/// alive to keep the accepted forward (and its `max_forwards` permit) live —
/// dropping them half-closes the QUIC stream, which tears the bridge (and the
/// permit) down.
async fn open_inbound(
    server_conn: &quinn::Connection,
    host: &str,
    port: u16,
) -> (ForwardOpenResponse, quinn::SendStream, quinn::RecvStream) {
    let (mut send, mut recv) = server_conn.open_bi().await.unwrap();
    Ssh3Frame::new(
        Ssh3FrameKind::DirectTcpRequest,
        ChannelOpenPayload {
            host: host.to_string(),
            port,
        }
        .encode(),
    )
    .write_async(&mut send)
    .await
    .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), Ssh3Frame::read_async(&mut recv))
        .await
        .expect("dispatcher response timed out")
        .unwrap();
    assert_eq!(resp.kind, Ssh3FrameKind::ForwardOpenResponse);
    let parsed = ForwardOpenResponse::decode(resp.payload).unwrap();
    (parsed, send, recv)
}

/// E3-F8: a remote forward whose local target is unreachable must be rejected —
/// the dispatcher dials *before* acking, so the peer gets `ok:false` instead of
/// a success followed by an abrupt reset.
#[tokio::test]
async fn remote_forward_ok_false_when_local_dial_fails() {
    let (mut session, server_conn, mut s_send, mut s_recv) = setup(Some(8)).await;

    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 7001));
    // Target is a port nothing listens on → dial fails.
    let dead_target = TargetAddr::new("127.0.0.1", 1);
    let _h =
        register_remote_forward(&mut session, &mut s_send, &mut s_recv, dead_target, bind).await;

    let (resp, _s, _r) = open_inbound(&server_conn, "127.0.0.1", 7001).await;
    assert!(
        !resp.ok,
        "dispatcher ACKed a forward whose local dial must have failed"
    );
    assert!(
        resp.reason.contains("local dial failed"),
        "unexpected reason: {}",
        resp.reason
    );
}

/// E3-F8 (happy path): when the local target *is* reachable the dispatcher acks
/// with `ok:true` — confirming the dial-before-ack reordering didn't break the
/// success case.
#[tokio::test]
async fn remote_forward_ok_true_when_local_dial_succeeds() {
    let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let (mut session, server_conn, mut s_send, mut s_recv) = setup(Some(8)).await;
    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 7002));
    let target = TargetAddr::new(echo_addr.ip().to_string(), echo_addr.port());
    let _h = register_remote_forward(&mut session, &mut s_send, &mut s_recv, target, bind).await;

    let (resp, _s, _r) = open_inbound(&server_conn, "127.0.0.1", 7002).await;
    assert!(resp.ok, "reachable target was rejected: {}", resp.reason);
}

/// E3-F3: with a `max_forwards` cap of 1, the first inbound open (to a live
/// target, so it occupies a permit) succeeds, and a second concurrent open must
/// be rejected with `ok:false` "max_forwards reached" — proving the cap is
/// enforced rather than cosmetic.
#[tokio::test]
async fn max_forwards_cap_rejects_inbound_past_limit() {
    // A live echo target so accepted opens hold their permits open (the bridge
    // task keeps running, holding the OwnedSemaphorePermit).
    let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                // Hold the connection open (do not close) so the permit stays
                // held for the duration of the test.
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    // Client advertises max_forwards = 1 → the client session caps inbound
    // forwards at 1 permit.
    let (mut session, server_conn, mut s_send, mut s_recv) = setup(Some(1)).await;
    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 7003));
    let target = TargetAddr::new(echo_addr.ip().to_string(), echo_addr.port());
    let _h = register_remote_forward(&mut session, &mut s_send, &mut s_recv, target, bind).await;

    // First inbound open consumes the single permit. Hold the stream halves so
    // the bridge — and therefore the permit — stays live for the second open.
    let (first, _s1, _r1) = open_inbound(&server_conn, "127.0.0.1", 7003).await;
    assert!(first.ok, "first inbound open rejected: {}", first.reason);

    // Give the bridge task a moment to actually be holding the permit.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second inbound open must be rejected — the permit is still held.
    let (second, _s2, _r2) = open_inbound(&server_conn, "127.0.0.1", 7003).await;
    assert!(
        !second.ok,
        "second inbound open should have been rejected by max_forwards cap"
    );
    assert!(
        second.reason.contains("max_forwards"),
        "unexpected reason: {}",
        second.reason
    );
}
