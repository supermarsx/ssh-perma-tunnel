//! Data-plane regression tests through the **real** ssh3 (QUIC) transport.
//!
//! These lock in the Wave-11 data-plane fixes as *class* coverage (see
//! `.orchestration/logs/cov-dataplane.md`, P3/P5/P6) so a future partial-write /
//! half-close / throttle+idle / demux / cap regression can't slip through the
//! ssh3 backend:
//!
//! * **byte-integrity** of a real ssh3 local-TCP forward for {0 B, tiny,
//!   64 KiB, ≥4 MiB} payloads, round-tripped BYTE-EXACT over the QUIC byte-pipe.
//! * **half-close / EOF** propagation in *both* directions through the forward.
//! * **throttle + idle** (P3): a rate-limited forward transfers a large payload
//!   to completion without being idle-closed mid-flight (MED-3).
//! * **concurrent-client TCP** (P6): N simultaneous forwards never cross-talk;
//!   each is byte-exact.
//! * **`max_connections`** (LOW-6, CAS gate): under a heavy concurrent-accept
//!   burst the cap is never overshot and admitted transfers are byte-exact.
//! * **local-UDP concurrent-client demux** (MEDIUM-4): ≥3 concurrent local UDP
//!   apps each receive ONLY their own replies (no cross-talk), datagram
//!   boundaries preserved across many rounds, and an oversized datagram is
//!   dropped (not split/corrupted) without wedging the flow.
//!
//! Reuses the `two_endpoints.rs` harness (quinn `connected_pair` +
//! `serve_local_tcp_acceptor` echo). Wire-compat caveat: spt↔spt only.

#![cfg(not(miri))]
#![allow(
    clippy::manual_let_else,
    clippy::let_unit_value,
    clippy::ignored_unit_patterns,
    clippy::while_let_loop,
    clippy::too_many_lines
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use spt_core::BindAddr;
use spt_protocol::endpoint::TargetAddr;
use spt_protocol::forward::{
    BindConflictPolicy, ForwardDirection, ForwardRateLimits, LocalForwardSpec, UdpForwardSpec,
};
use spt_protocol::handle::ForwardHandle;
use spt_protocol::session::{SessionInfo, TunnelSession};
use spt_ssh3::forward::serve_local_tcp_acceptor;
use spt_ssh3::frame::Ssh3Settings;
use spt_ssh3::{accept_control_stream, open_control_stream, Ssh3Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

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
        max_forwards: Some(64),
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

/// Everything a forward-based test needs to keep alive; dropping it closes the
/// QUIC connections and the acceptor. The `_session` and `_handle` fields are
/// load-bearing: dropping either tears the forward down (the handle's close
/// oneshot fires, and the session owns the client connection), so they are held
/// for the rig's lifetime even though never read.
struct ForwardRig {
    _session: Box<dyn TunnelSession>,
    _handle: ForwardHandle,
    listen_addr: SocketAddr,
    client_conn: quinn::Connection,
    server_conn: quinn::Connection,
    acceptor: tokio::task::JoinHandle<()>,
}

impl Drop for ForwardRig {
    fn drop(&mut self) {
        self.acceptor.abort();
        let _ = self.client_conn.close(0u32.into(), b"done");
        let _ = self.server_conn.close(0u32.into(), b"done");
    }
}

/// Bring up a client `Ssh3Session`, a server-side `serve_local_tcp_acceptor`
/// bridging every inbound stream to `target`, and one local TCP forward with
/// the given limits. Returns the rig; connect to `rig.listen_addr` to drive it.
async fn setup_local_tcp_forward(
    target: SocketAddr,
    max_connections: Option<u32>,
    limits: ForwardRateLimits,
    idle_timeout: Option<Duration>,
) -> ForwardRig {
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

    let server_conn_a = server_conn.clone();
    let acceptor = tokio::spawn(async move {
        serve_local_tcp_acceptor(server_conn_a, move |_open| {
            Some(TargetAddr::new(target.ip().to_string(), target.port()))
        })
        .await;
    });

    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listen_addr = probe.local_addr().unwrap();
    drop(probe);

    let spec = LocalForwardSpec {
        name: "regr-tcp".into(),
        listen: BindAddr::Tcp(listen_addr),
        target: TargetAddr::new("localhost", 1), // ignored — resolver used
        max_connections,
        limits,
        idle_timeout,
        on_bind_conflict: BindConflictPolicy::default(),
        required: false,
    };
    let handle = session.open_local_forward(&spec).await.unwrap();

    ForwardRig {
        _session: session,
        _handle: handle,
        listen_addr,
        client_conn,
        server_conn,
        acceptor,
    }
}

/// Spawn a loopback TCP echo server; returns its bound address.
async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Deterministic byte pattern.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Write `payload` on a fresh forward connection (concurrently with reading so a
/// large echo can't deadlock on flow control), half-close the write side, and
/// return everything read back to EOF.
async fn echo_round_trip(listen_addr: SocketAddr, payload: Vec<u8>) -> Vec<u8> {
    let sock = TcpStream::connect(listen_addr).await.unwrap();
    let (mut r, mut w) = sock.into_split();
    let to_write = payload;
    let writer = tokio::spawn(async move {
        w.write_all(&to_write).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), r.read_to_end(&mut got))
        .await
        .expect("read_to_end timed out")
        .unwrap();
    writer.await.unwrap();
    got
}

// ---------------------------------------------------------------------------
// 1. Byte-integrity: {0 B, tiny, 64 KiB, 4 MiB} exact round-trip.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_forward_byte_exact_across_sizes() {
    let echo = spawn_tcp_echo().await;
    let rig = setup_local_tcp_forward(echo, None, ForwardRateLimits::default(), None).await;

    for &size in &[0usize, 1, 100, 64 * 1024, 4 * 1024 * 1024] {
        let payload = pattern(size);
        let got = echo_round_trip(rig.listen_addr, payload.clone()).await;
        assert_eq!(got.len(), payload.len(), "length mismatch at size={size}");
        assert_eq!(got, payload, "byte mismatch at size={size}");
    }
}

// ---------------------------------------------------------------------------
// 2. Half-close / EOF propagation, both directions.
// ---------------------------------------------------------------------------

/// Client half-closes its write half first; the server target reads to EOF and
/// only *then* replies. Proves the client→server FIN propagates through the
/// forward AND the server→client half stays open to deliver the late reply.
#[tokio::test]
async fn tcp_forward_half_close_client_first_server_replies_after_eof() {
    // Target: read everything to EOF, then echo it back with a suffix marker.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = sock.split();
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap(); // completes only on client FIN
        w.write_all(&got).await.unwrap();
        w.write_all(b"|POST-EOF").await.unwrap();
        w.shutdown().await.unwrap();
    });

    let rig = setup_local_tcp_forward(target, None, ForwardRateLimits::default(), None).await;

    let sock = TcpStream::connect(rig.listen_addr).await.unwrap();
    let (mut r, mut w) = sock.into_split();
    w.write_all(b"REQUEST").await.unwrap();
    w.shutdown().await.unwrap(); // half-close: client is done sending
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), r.read_to_end(&mut got))
        .await
        .expect("late reply never arrived — half-close broke the read half")
        .unwrap();
    assert_eq!(
        got, b"REQUEST|POST-EOF",
        "server reply after client half-close was lost/truncated"
    );
}

/// Server half-closes its write half first; the client keeps sending afterward.
/// Proves the server→client FIN does not tear down the still-open client→server
/// half (the server receives the client's post-FIN bytes).
#[tokio::test]
async fn tcp_forward_half_close_server_first_client_keeps_sending() {
    let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = sock.split();
        // Greet, then half-close our write half immediately.
        w.write_all(b"GREETING").await.unwrap();
        w.shutdown().await.unwrap();
        // Keep reading: the client sends more AFTER seeing our EOF.
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        let _ = tx.send(got);
    });

    let rig = setup_local_tcp_forward(target, None, ForwardRateLimits::default(), None).await;

    let sock = TcpStream::connect(rig.listen_addr).await.unwrap();
    let (mut r, mut w) = sock.into_split();

    // Read the greeting and observe the read-half EOF.
    let mut greeting = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), r.read_to_end(&mut greeting))
        .await
        .expect("greeting/EOF timed out")
        .unwrap();
    assert_eq!(greeting, b"GREETING", "server greeting not delivered");

    // Now send more — the server's half-close must NOT have killed this half.
    w.write_all(b"LATE-DATA").await.unwrap();
    w.shutdown().await.unwrap();

    let server_got = tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .expect("server never received post-half-close bytes")
        .unwrap();
    assert_eq!(
        server_got, b"LATE-DATA",
        "client→server half was severed by the server's half-close"
    );
}

// ---------------------------------------------------------------------------
// 3. Throttle + idle through real ssh3 (P3 / MED-3).
// ---------------------------------------------------------------------------

/// A rate-limited forward whose idle timeout is far shorter than the transfer's
/// wall-clock duration must NOT idle-close a still-draining connection: the full
/// payload arrives byte-exact. Guards the throttle-vs-idle interaction (a slow
/// but active transfer being mis-read as idle and truncated).
#[tokio::test]
async fn tcp_forward_throttled_large_transfer_not_idle_closed() {
    let echo = spawn_tcp_echo().await;
    // 400 KB/s each way; idle window 400 ms. 1 MB payload ⇒ ~1.5 s of active
    // transfer past the free burst, crossing several idle windows.
    let limits = ForwardRateLimits {
        rate_bps_up: 400_000,
        rate_bps_down: 400_000,
        ..ForwardRateLimits::default()
    };
    let rig = setup_local_tcp_forward(echo, None, limits, Some(Duration::from_millis(400))).await;

    let payload = pattern(1_000_000);
    let got = echo_round_trip(rig.listen_addr, payload.clone()).await;
    assert_eq!(
        got.len(),
        payload.len(),
        "throttled transfer was truncated (idle-closed mid-flight?)"
    );
    assert_eq!(got, payload, "throttled transfer corrupted");
}

// ---------------------------------------------------------------------------
// 4. Concurrent-client TCP (P6): no cross-talk, each byte-exact.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_forward_concurrent_clients_no_cross_talk() {
    const CLIENTS: u8 = 6;

    let echo = spawn_tcp_echo().await;
    let rig = setup_local_tcp_forward(echo, None, ForwardRateLimits::default(), None).await;

    let mut handles = Vec::new();
    for id in 0..CLIENTS {
        let addr = rig.listen_addr;
        handles.push(tokio::spawn(async move {
            // Payload tagged by client id so a mis-demux surfaces as a byte
            // mismatch rather than a silent pass.
            let payload: Vec<u8> = (0..8192)
                .map(|i| id.wrapping_mul(37).wrapping_add((i % 251) as u8))
                .collect();
            let got = echo_round_trip(addr, payload.clone()).await;
            assert_eq!(got, payload, "client {id} saw corrupted/cross-talk bytes");
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// 5. max_connections cap (LOW-6, CAS gate): never overshoot under a burst.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_forward_max_connections_never_overshoots() {
    const CAP: u32 = 4;
    const BURST: usize = 24;

    // Counting/holding target: tracks concurrent bridged connections and the
    // max ever observed. Each connection is held (echo copy) until the client
    // drops, so the cap is measured while transfers are live.
    let current = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let cur_t = current.clone();
    let max_t = max_seen.clone();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let cur = cur_t.clone();
            let mx = max_t.clone();
            tokio::spawn(async move {
                let now = cur.fetch_add(1, Ordering::SeqCst) + 1;
                mx.fetch_max(now, Ordering::SeqCst);
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                cur.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });

    let rig = setup_local_tcp_forward(target, Some(CAP), ForwardRateLimits::default(), None).await;

    let successes = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..BURST {
        let addr = rig.listen_addr;
        let succ = successes.clone();
        handles.push(tokio::spawn(async move {
            let payload = pattern(64);
            let Ok(mut sock) = TcpStream::connect(addr).await else {
                return;
            };
            if sock.write_all(&payload).await.is_err() {
                return;
            }
            let mut got = vec![0u8; payload.len()];
            match sock.read_exact(&mut got).await {
                Ok(_) => {
                    // Hold the connection so admitted transfers stay concurrent
                    // long enough for the whole burst to be processed by the
                    // accept loop (over-cap accepts are dropped immediately).
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if got == payload {
                        succ.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Err(_) => { /* dropped by the cap gate — expected for the surplus */ }
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let observed = max_seen.load(Ordering::SeqCst);
    let ok = successes.load(Ordering::SeqCst);
    assert!(
        observed <= CAP as usize,
        "max_connections overshoot: observed {observed} concurrent bridges > cap {CAP}"
    );
    assert!(observed >= 1, "no connection was ever bridged");
    assert!(
        ok >= 1 && ok <= CAP as usize,
        "admitted-transfer count {ok} outside 1..={CAP} (cap not honoured / transfers disrupted)"
    );
}

// ---------------------------------------------------------------------------
// 6. Local-UDP concurrent-client demux (MEDIUM-4).
// ---------------------------------------------------------------------------

/// Bring up a local UDP forward plus a server that raw-echoes every QUIC
/// datagram (flow-id prefix preserved). Returns (rig-ish tuple). The server
/// echo bounces `[flow_id][payload]` unchanged, so the *client-side* per-source
/// flow-id demux is what routes each reply back to the originating app socket —
/// a mis-demux delivers app A's bytes to app B and fails the assertions.
async fn setup_local_udp_echo_forward() -> (
    Box<dyn TunnelSession>,
    ForwardHandle,
    SocketAddr,
    quinn::Connection,
    quinn::Connection,
    tokio::task::JoinHandle<()>,
) {
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

    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    let listen_addr = probe.local_addr().unwrap();
    drop(probe);

    let spec = UdpForwardSpec {
        name: "regr-udp".into(),
        direction: ForwardDirection::Local,
        listen: BindAddr::Tcp(listen_addr),
        target: TargetAddr::new("127.0.0.1", 1234),
        idle_timeout_secs: 30,
        max_flows: None,
        limits: ForwardRateLimits::default(),
    };
    let handle = session.open_udp_forward(&spec).await.unwrap();

    // Server: echo every inbound QUIC datagram verbatim (flow-id + payload).
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

    (session, handle, listen_addr, client_conn, server_conn, echo)
}

#[tokio::test]
async fn udp_forward_concurrent_clients_no_cross_talk() {
    const APPS: u8 = 4;
    const ROUNDS: usize = 8;

    let (_session, _handle, listen_addr, client_conn, server_conn, echo) =
        setup_local_udp_echo_forward().await;

    let mut handles = Vec::new();
    for app_id in 0..APPS {
        handles.push(tokio::spawn(async move {
            let app = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
            app.connect(listen_addr).await.unwrap();
            for round in 0..ROUNDS {
                // Distinct length + content per (app, round): a coalesced or
                // split datagram changes the length; a cross-talk delivers the
                // wrong tag byte.
                let len = 50 + usize::from(app_id) * 97 + round * 5;
                let tag = app_id
                    .wrapping_mul(53)
                    .wrapping_add((round as u8).wrapping_mul(7));
                let payload: Vec<u8> = (0..len)
                    .map(|i| tag.wrapping_add((i % 251) as u8))
                    .collect();

                app.send(&payload).await.unwrap();
                let mut buf = [0u8; 2048];
                let n = tokio::time::timeout(Duration::from_secs(5), app.recv(&mut buf))
                    .await
                    .unwrap_or_else(|_| panic!("app {app_id} round {round}: reply timeout"))
                    .unwrap();
                assert_eq!(
                    n, len,
                    "app {app_id} round {round}: datagram boundary not preserved"
                );
                assert_eq!(
                    &buf[..n],
                    payload.as_slice(),
                    "app {app_id} round {round}: wrong bytes (cross-talk/mis-demux)"
                );
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    echo.abort();
    let _ = client_conn.close(0u32.into(), b"done");
    let _ = server_conn.close(0u32.into(), b"done");
}

/// An oversized datagram (larger than the negotiated QUIC datagram limit) is
/// dropped rather than split/corrupted, and does not wedge the flow — a normal
/// datagram on the same client still round-trips afterwards.
#[tokio::test]
async fn udp_forward_oversized_datagram_dropped_flow_survives() {
    let (_session, _handle, listen_addr, client_conn, server_conn, echo) =
        setup_local_udp_echo_forward().await;

    let app = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    app.connect(listen_addr).await.unwrap();

    // On loopback quinn negotiates a small (~1200 B) per-datagram limit; a
    // payload larger than that (plus the 4 B flow prefix) cannot be sent as one
    // QUIC datagram, so the local UDP pump drops it. Only exercise the drop when
    // the resulting UDP datagram still fits a single OS UDP send.
    let max = client_conn
        .max_datagram_size()
        .expect("quic datagrams negotiated");
    if max + 4 < 60_000 {
        let over = vec![0xABu8; max + 200];
        app.send(&over).await.unwrap();
        let mut buf = [0u8; 4096];
        let res = tokio::time::timeout(Duration::from_millis(700), app.recv(&mut buf)).await;
        assert!(
            res.is_err(),
            "oversized-for-QUIC datagram must be dropped, not relayed (got {res:?})"
        );
    }

    // A normal datagram on the same client flow still works.
    app.send(b"still-alive").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), app.recv(&mut buf))
        .await
        .expect("normal datagram after an oversized drop: reply timeout")
        .unwrap();
    assert_eq!(
        &buf[..n],
        b"still-alive",
        "flow wedged after dropping an oversized datagram"
    );

    echo.abort();
    let _ = client_conn.close(0u32.into(), b"done");
    let _ = server_conn.close(0u32.into(), b"done");
}
