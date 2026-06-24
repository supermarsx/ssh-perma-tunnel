//! e2e (Wave C): ssh3 (QUIC) through the **supervisor** + serve-end forward
//! coverage gaps, built entirely on the `spt_ssh3::testing` harness so the
//! `spt-e2e-tests` crate needs no direct `quinn` / `rustls` / `rcgen` /
//! `spt-trust` dependency (the manifest only enables `spt-ssh3/testing`).
//!
//! ## What's new here vs the existing ssh3 e2e
//!
//! The shipped `crates/spt-ssh3/tests/{e2e_forward,serve_endpoint,uds_forward,
//! remote_udp,two_endpoints}.rs` all drive an [`spt_ssh3::Ssh3Session`]
//! **directly** — none go through the [`spt_supervisor`] `Orchestrator`. This
//! file fills two gaps:
//!
//! * **Supervised ssh3** — a real ssh3 session is driven through
//!   [`OrchestratorBuilder`] / [`wait_for_state`] (the same harness the ssh2
//!   mock variants use): the supervisor brings the profile to `Active` and opens
//!   the profile's declared local-TCP forward over the supervised ssh3 session;
//!   a byte payload round-trips through that supervisor-managed forward. A
//!   sibling test asserts the supervisor reports failure (never reaches
//!   `Active`) when the connect/auth is rejected.
//! * **Serve-end gaps** — a local-TCP forward, a **remote-UDP** forward, and an
//!   **ACL-deny** path are exercised through the spt-ssh3 server-side forward
//!   serving helpers (`serve_inbound_opens` / `serve_remote_udp_forwards` /
//!   `serve_datagram_demux`) running on the [`Ssh3TestServer`] server halves.
//!
//! ## Why the `Ssh3TestServer` harness (and not `serve()` / `Ssh3Server::run`)
//!
//! Driving the full `Ssh3Protocol::connect` bootstrap (QUIC + TLS + HTTP/3
//! Extended-CONNECT) against the real `serve()` accept loop requires a
//! self-signed server config + SPKI pin, which only `spt_ssh3::tls::
//! self_signed_server_config` provides — and that is gated behind the
//! `server-selfsigned` feature, which the e2e manifest does NOT enable (it only
//! turns on `spt-ssh3/testing` → `server`). Standing up a `quinn` server config
//! by hand would need direct `quinn`/`rustls`/`rcgen`/`spt-trust` deps, also not
//! in the manifest. The `Ssh3TestServer::start_pair()` fixture gives a real,
//! already-bootstrapped client [`Ssh3Session`] (full QUIC forward I/O) plus the
//! raw server-side QUIC halves, which we pair with the public server-side
//! forward serving helpers — fully hermetic, no extra deps.
//!
//! COORDINATOR / Linux-gate note: the `Ssh3ServerAcl` HTTP-401 CONNECT-reject
//! path (a true bootstrap-time auth deny through `Ssh3Server::run`) and the
//! `serve()` accept loop are NOT covered here for the dependency reason above;
//! they remain covered inside `crates/spt-ssh3/tests/serve_endpoint.rs` /
//! `e2e_forward.rs`. If the e2e manifest later gains `spt-ssh3/server-selfsigned`
//! (or direct quinn deps), these supervised tests can be retargeted at the real
//! `serve()` loop. The auth-deny intent is covered here at the supervisor level
//! (connect rejected → never `Active`) and at the serve level (ACL resolver
//! denies the channel open → no byte round-trip).
//!
//! Hermetic: loopback QUIC on ephemeral ports; bounded waits via `wait_for_state`
//! and timed reads (QUIC/ssh3 timing is sensitive, so liveness is observed via
//! the supervisor state watcher and bounded retry loops — no fixed sleeps as a
//! readiness signal).

// NOTE: unlike the in-crate `crates/spt-ssh3/tests/*.rs`, this file lives in the
// `spt-e2e-tests` crate, which has no `testing` feature of its own — the
// `spt-ssh3/testing` fixtures are pulled in via the dev-dependency's feature in
// `tests/Cargo.toml`. So we gate only on `not(miri)`, not on a local feature
// (gating on `feature = "testing"` here would compile the whole file away).
#![cfg(not(miri))]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use spt_auth::AuthConfig;
use spt_config::testing::{ForwardBuilder, ProfileBuilder};
use spt_core::{BindAddr, Error, Result};
use spt_protocol::endpoint::TargetAddr;
use spt_protocol::forward::{
    BindConflictPolicy, ForwardDirection, ForwardRateLimits, LocalForwardSpec, UdpForwardSpec,
};
use spt_protocol::{Endpoint, ProtocolCapabilities, TunnelProtocol, TunnelSession};
use spt_ssh3::forward::{
    serve_datagram_demux, serve_inbound_opens, serve_remote_udp_forwards, SessionState,
};
use spt_ssh3::frame::Ssh3Settings;
use spt_ssh3::testing::test_support::connected_pair_public;
use spt_ssh3::testing::Ssh3TestServer;
use spt_ssh3::{accept_control_stream, open_control_stream, Ssh3Session};
use spt_supervisor::testing::{
    wait_for_state, OrchestratorBuilder, ProfileStateName, ProfileSupervisorConfig,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;

// -----------------------------------------------------------------------------
// Loopback echo helpers
// -----------------------------------------------------------------------------

/// Spawn a TCP echo server, returning its address.
async fn start_tcp_echo() -> SocketAddr {
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

/// Spawn a UDP echo server, returning its address.
async fn start_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let _ = socket.send_to(&buf[..n], peer).await;
                }
                Err(_) => break,
            }
        }
    });
    addr
}

/// Reserve a free ephemeral TCP port (bind + drop).
async fn free_tcp_port() -> u16 {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// Reserve a free ephemeral UDP port (bind + drop).
async fn free_udp_port() -> u16 {
    let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    let p = s.local_addr().unwrap().port();
    drop(s);
    p
}

// -----------------------------------------------------------------------------
// Supervisor adapter protocols
// -----------------------------------------------------------------------------

/// A [`TunnelProtocol`] whose `connect()` brings up a fresh
/// [`Ssh3TestServer::start_pair`], spawns a server-side local-TCP open acceptor
/// (resolving every open to `echo_target`), and returns the real client
/// [`Ssh3Session`]. This lets the supervisor drive a genuine ssh3 session +
/// forward I/O without the HTTP/3-CONNECT bootstrap (unavailable to this crate
/// — see the module docs). Each `connect()` (incl. supervisor reconnects)
/// stands up an independent pair.
struct Ssh3HarnessProtocol {
    echo_target: TargetAddr,
    /// Server handles kept alive for the lifetime of the orchestrator so the
    /// server side of each connection is not dropped underneath the session.
    keepalive: Arc<Mutex<Vec<spt_ssh3::testing::ServerHandle>>>,
}

impl Ssh3HarnessProtocol {
    fn new(echo_target: TargetAddr) -> Self {
        Self {
            echo_target,
            keepalive: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl TunnelProtocol for Ssh3HarnessProtocol {
    async fn connect(
        &self,
        _endpoint: &Endpoint,
        _auth: &AuthConfig,
    ) -> Result<Box<dyn TunnelSession>> {
        let (client, server) = Ssh3TestServer::new()
            .start_pair()
            .await
            .map_err(|e| Error::RuntimeFailure(format!("ssh3 start_pair: {e}")))?;
        // Server side: resolve every inbound local-TCP open to the echo target.
        let target = self.echo_target.clone();
        tokio::spawn(serve_inbound_opens(server.conn.clone(), move |_open| {
            Some(target.clone())
        }));
        // Retain the server handle so its QUIC connection is not closed on drop.
        self.keepalive.lock().push(server);
        Ok(client.session)
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::ssh3()
    }

    fn name(&self) -> &'static str {
        "ssh3-harness"
    }
}

/// A [`TunnelProtocol`] whose `connect()` always fails with an auth error —
/// models a bootstrap-time CONNECT rejection (HTTP 401 ACL deny) at the
/// supervisor boundary. The supervisor must report failure and never reach
/// `Active`.
struct Ssh3DenyProtocol;

#[async_trait]
impl TunnelProtocol for Ssh3DenyProtocol {
    async fn connect(
        &self,
        _endpoint: &Endpoint,
        _auth: &AuthConfig,
    ) -> Result<Box<dyn TunnelSession>> {
        Err(Error::AuthFailed(
            "ssh3 CONNECT rejected by server ACL (HTTP 401)".into(),
        ))
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::ssh3()
    }

    fn name(&self) -> &'static str {
        "ssh3-deny"
    }
}

// =============================================================================
// Wave C — ssh3 through the SUPERVISOR
// =============================================================================

/// The supervisor brings an `ssh3` profile to `Active` and opens its declared
/// local-TCP forward over the supervised ssh3 session; a byte payload
/// round-trips through that supervisor-managed forward. Covers the supervisor
/// path (connect → auth → open forwards → run_active) for the ssh3 backend,
/// which the direct-session ssh3 e2e never exercises.
#[tokio::test]
async fn ssh3_supervised_local_tcp_round_trips() {
    let echo = start_tcp_echo().await;
    let echo_target = TargetAddr::new(echo.ip().to_string(), echo.port());

    let listen_port = free_tcp_port().await;
    let listen_bind = format!("127.0.0.1:{listen_port}");
    let profile = ProfileBuilder::new("ssh3-sup")
        .protocol("ssh3")
        .endpoint("127.0.0.1", 443)
        .user("alice")
        .add_forward(
            ForwardBuilder::local_tcp("ssh3-echo", &listen_bind, "ignored-by-resolver:1")
                .required(true)
                .build(),
        )
        .build();

    let proto = Arc::new(Ssh3HarnessProtocol::new(echo_target));
    let endpoints = vec![Endpoint::new("127.0.0.1", 443)];

    let orch = OrchestratorBuilder::new()
        .with_profile(
            profile,
            proto as Arc<dyn TunnelProtocol>,
            AuthConfig::new("alice", vec![]),
            endpoints,
            ProfileSupervisorConfig::default(),
        )
        .build();

    wait_for_state(
        &orch,
        "ssh3-sup",
        ProfileStateName::Active,
        Duration::from_secs(20),
    )
    .await
    .expect("supervisor brings the ssh3 profile to Active");

    // The supervisor opened the forward listener; round-trip bytes through it:
    // client → forward listener → supervised ssh3 session → server → echo → back.
    let payload: Vec<u8> = (0..16 * 1024u32).map(|i| (i % 251) as u8).collect();
    let mut sock = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .expect("connect supervisor-managed forward listener");
    sock.write_all(&payload).await.expect("write payload");
    sock.shutdown().await.expect("shutdown write half");
    let mut got = Vec::with_capacity(payload.len());
    tokio::time::timeout(Duration::from_secs(10), sock.read_to_end(&mut got))
        .await
        .expect("read_to_end timed out")
        .expect("read echo");
    assert_eq!(
        got, payload,
        "bytes must round-trip through the supervised ssh3 forward"
    );

    orch.shutdown().await;
}

/// Lifecycle-only sibling: the supervisor reaches `Active` for an ssh3 profile
/// declaring no forwards (proves connect+auth alone bring the profile up).
#[tokio::test]
async fn ssh3_supervised_reaches_active_no_forwards() {
    let echo = start_tcp_echo().await;
    let echo_target = TargetAddr::new(echo.ip().to_string(), echo.port());

    let profile = ProfileBuilder::new("ssh3-bare")
        .protocol("ssh3")
        .endpoint("127.0.0.1", 443)
        .user("alice")
        .build();

    let proto = Arc::new(Ssh3HarnessProtocol::new(echo_target));
    let endpoints = vec![Endpoint::new("127.0.0.1", 443)];

    let orch = OrchestratorBuilder::new()
        .with_profile(
            profile,
            proto as Arc<dyn TunnelProtocol>,
            AuthConfig::new("alice", vec![]),
            endpoints,
            ProfileSupervisorConfig::default(),
        )
        .build();

    wait_for_state(
        &orch,
        "ssh3-bare",
        ProfileStateName::Active,
        Duration::from_secs(20),
    )
    .await
    .expect("supervisor brings the forward-less ssh3 profile to Active");

    orch.shutdown().await;
}

/// Auth-deny at the supervisor boundary: the ssh3 `connect` is rejected on every
/// attempt (modelling an `Ssh3ServerAcl` HTTP-401 CONNECT reject). The profile
/// must NOT reach `Active` within the window — a bounded wait that *fails* is
/// the assertion. `retry_auth_failures` is left at its default (`false`), so the
/// auth failure is terminal.
#[tokio::test]
async fn ssh3_supervised_connect_rejected_never_active() {
    let profile = ProfileBuilder::new("ssh3-deny")
        .protocol("ssh3")
        .endpoint("127.0.0.1", 443)
        .user("alice")
        .build();

    let proto = Arc::new(Ssh3DenyProtocol);
    let endpoints = vec![Endpoint::new("127.0.0.1", 443)];

    let orch = OrchestratorBuilder::new()
        .with_profile(
            profile,
            proto as Arc<dyn TunnelProtocol>,
            AuthConfig::new("alice", vec![]),
            endpoints,
            ProfileSupervisorConfig::default(),
        )
        .build();

    let res = wait_for_state(
        &orch,
        "ssh3-deny",
        ProfileStateName::Active,
        Duration::from_secs(3),
    )
    .await;
    assert!(
        res.is_err(),
        "an ssh3 profile whose CONNECT is auth-denied must not reach Active; got {res:?}"
    );

    orch.shutdown().await;
}

// =============================================================================
// Wave C — serve-end forward gaps (direct client + server-side helpers)
// =============================================================================

/// Local-TCP forward through the server-side `serve_inbound_opens` acceptor:
/// the client opens a local-TCP forward; the server resolves every open to the
/// echo target and bridges; a byte payload round-trips.
#[tokio::test]
async fn serve_local_tcp_round_trips() {
    let echo = start_tcp_echo().await;
    let echo_target = TargetAddr::new(echo.ip().to_string(), echo.port());

    let (mut client, server) = Ssh3TestServer::new().start_pair().await.unwrap();
    assert_eq!(client.session.session_info().backend, "ssh3");

    // Server side: resolve every inbound open to the echo target.
    let resolve_target = echo_target.clone();
    let _server_task = tokio::spawn(serve_inbound_opens(server.conn.clone(), move |_open| {
        Some(resolve_target.clone())
    }));

    let listen_port = free_tcp_port().await;
    let listen_addr: SocketAddr = ([127, 0, 0, 1], listen_port).into();
    let spec = LocalForwardSpec {
        name: "serve-local-tcp".into(),
        listen: BindAddr::Tcp(listen_addr),
        target: TargetAddr::new("ignored-by-resolver", 1),
        max_connections: None,
        limits: ForwardRateLimits::default(),
        idle_timeout: None,
        on_bind_conflict: BindConflictPolicy::default(),
        required: false,
    };
    let _handle = client
        .session
        .open_local_forward(&spec)
        .await
        .expect("open local-tcp forward");

    let payload: Vec<u8> = (0..16 * 1024u32).map(|i| (i % 251) as u8).collect();
    let mut sock = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .expect("connect forward listener");
    sock.write_all(&payload).await.unwrap();
    sock.shutdown().await.unwrap();
    let mut got = Vec::with_capacity(payload.len());
    tokio::time::timeout(Duration::from_secs(10), sock.read_to_end(&mut got))
        .await
        .expect("read_to_end timed out")
        .unwrap();
    assert_eq!(got, payload, "serve local-tcp round-trip mismatch");

    let _ = Box::new(client.session).close().await;
    server.shutdown();
}

/// Remote-UDP forward through the server-side `serve_remote_udp_forwards` +
/// `serve_datagram_demux` pair: the client opens a `UdpForwardSpec { direction:
/// Remote }`; the server binds a UDP listener; an external datagram round-trips
/// server → QUIC → client → echo → back → external. Covers BOTH the remote and
/// UDP serve-end gaps (the spt-ssh3 server loop wires remote-UDP, not remote-TCP).
///
/// Uses the lower-level `connected_pair_public()` + handshake seam (the same
/// shape as the shipped `crates/spt-ssh3/tests/remote_udp.rs`) rather than
/// `start_pair()`, because the remote-UDP server side needs the control-stream
/// `send`/`recv` halves *by value* and `ServerHandle` is a `Drop` type whose
/// fields cannot be moved out.
#[tokio::test]
async fn serve_remote_udp_round_trips() {
    let echo_addr = start_udp_echo().await;

    let (client_conn, server_conn) = connected_pair_public().await;

    // Drive the SSH3 control-stream handshake on both sides; both advertise the
    // same settings so peer-settings are symmetric.
    let settings = Ssh3Settings {
        direct_tcp: true,
        remote_tcp: true,
        udp_datagrams: true,
        agent_forwarding: false,
        max_forwards: Some(8),
        version: Some("e2e-serve/0.1".into()),
        extras: vec![],
    };
    let (cs, sv) = tokio::join!(
        open_control_stream(&client_conn, settings.clone()),
        accept_control_stream(&server_conn, settings.clone()),
    );
    let (c_send, c_recv, c_peer) = cs.expect("client handshake");
    let (s_send, s_recv, _s_peer) = sv.expect("server handshake");

    // Client side: a real `Ssh3Session` so inbound datagrams get demuxed by
    // flow-id into the client state.
    let mut client_session: Box<dyn TunnelSession> = Box::new(Ssh3Session::from_parts(
        client_conn.clone(),
        c_send,
        c_recv,
        c_peer,
        spt_protocol::SessionInfo {
            backend: "ssh3".into(),
            peer_version: Some("client".into()),
            negotiated: Some("e2e".into()),
            established_at: 0,
        },
        None,
    ));

    // Server side: drive the remote-UDP control acceptor + datagram demux.
    let server_state = Arc::new(SessionState::default());
    let server_send = Arc::new(AsyncMutex::new(s_send));
    let _acceptor = tokio::spawn(serve_remote_udp_forwards(
        server_conn.clone(),
        s_recv,
        server_send,
        server_state.clone(),
    ));
    let _demux = tokio::spawn(serve_datagram_demux(
        server_conn.clone(),
        server_state.clone(),
    ));

    let bind_port = free_udp_port().await;
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, bind_port));
    let spec = UdpForwardSpec {
        name: "serve-rudp".into(),
        direction: ForwardDirection::Remote,
        listen: BindAddr::Tcp(bind_addr),
        target: TargetAddr::new(echo_addr.ip().to_string(), echo_addr.port()),
        idle_timeout_secs: 30,
        max_flows: None,
        limits: ForwardRateLimits::default(),
    };
    let _handle = client_session
        .open_udp_forward(&spec)
        .await
        .expect("open remote-udp forward");

    // External UDP client hits the server-bound listener; assert the echo
    // round-trips within a bounded window (the server-side bind completes
    // asynchronously after the control frame, so retry the send).
    let external = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
    external.connect(bind_addr).await.unwrap();
    let payload = b"serve-remote-udp";

    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut buf = [0u8; 2048];
    let mut got: Option<Vec<u8>> = None;
    while tokio::time::Instant::now() < deadline {
        external.send(payload).await.unwrap();
        match tokio::time::timeout(Duration::from_millis(400), external.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                got = Some(buf[..n].to_vec());
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert_eq!(
        got.as_deref(),
        Some(&payload[..]),
        "remote-udp datagram must round-trip through the serve helpers"
    );

    let _ = client_session.close().await;
    client_conn.close(0u32.into(), b"test done");
    server_conn.close(0u32.into(), b"test done");
}

/// ACL-deny at the serve level: the server-side resolver returns `None` for
/// every open (ACL deny). The client's local listener still binds, but a
/// connection driven through it must NOT receive an echo — the channel open is
/// rejected server-side, so no bytes traverse the tunnel.
#[tokio::test]
async fn serve_acl_deny_blocks_bridge() {
    let (mut client, server) = Ssh3TestServer::new().start_pair().await.unwrap();

    // Server side: deny every inbound open (resolver yields None → reject).
    let _server_task = tokio::spawn(serve_inbound_opens(server.conn.clone(), |_open| {
        Option::<TargetAddr>::None
    }));

    let listen_port = free_tcp_port().await;
    let listen_addr: SocketAddr = ([127, 0, 0, 1], listen_port).into();
    let spec = LocalForwardSpec {
        name: "serve-deny".into(),
        listen: BindAddr::Tcp(listen_addr),
        target: TargetAddr::new("denied", 1),
        max_connections: None,
        limits: ForwardRateLimits::default(),
        idle_timeout: None,
        on_bind_conflict: BindConflictPolicy::default(),
        required: false,
    };
    // The local listener binds fine (the channel open is lazy / per-connection).
    let _handle = client
        .session
        .open_local_forward(&spec)
        .await
        .expect("open local forward (listener binds even if the ACL will deny)");

    let mut sock = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .expect("connect denied forward listener");
    sock.write_all(b"should-not-echo").await.unwrap();
    let _ = sock.shutdown().await;

    // The ACL-denied channel never bridges, so the read must NOT return the
    // payload: we expect EOF (0 bytes) or a connection error, never an echo.
    let mut got = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(3), sock.read_to_end(&mut got)).await;
    match read {
        Ok(Ok(_)) => assert!(
            got.is_empty(),
            "ACL-denied open must not echo any bytes, got {} bytes",
            got.len()
        ),
        Ok(Err(_)) => { /* connection reset / error — acceptable: no echo */ }
        Err(_) => { /* timed out with no echo — acceptable: deny held */ }
    }

    let _ = Box::new(client.session).close().await;
    server.shutdown();
}
