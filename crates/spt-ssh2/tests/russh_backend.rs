#![allow(clippy::missing_panics_doc)]

use std::time::Duration;

use spt_auth::{AuthConfig, AuthMethod};
use spt_core::BindAddr;
use spt_protocol::{
    BindConflictPolicy, DynamicForwardSpec, Endpoint, ForwardRateLimits, LocalForwardSpec,
    RemoteForwardSpec, TargetAddr, TunnelProtocol,
};
use spt_ssh2::testing::RusshTestServer;
use spt_ssh2::Ssh2Protocol;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

async fn connect_russh_session() -> (
    spt_ssh2::testing::RunningRusshServer,
    Box<dyn spt_protocol::TunnelSession>,
) {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");

    std::env::set_var("SPT_TEST_RUSSH_BACKEND_PW", "anything");
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_RUSSH_BACKEND_PW".into()),
        }],
    );
    let session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("russh backend connects");
    (server, session)
}

async fn free_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

#[tokio::test]
async fn russh_backend_connects_with_password_auth() {
    let (server, session) = connect_russh_session().await;
    assert_eq!(session.session_info().backend, "ssh2-russh");
    server.shutdown().await;
}

#[tokio::test]
async fn russh_backend_local_forward_bridges_to_direct_tcpip() {
    let (server, mut session) = connect_russh_session().await;
    let port = free_loopback_port().await;

    let handle = session
        .open_local_forward(&LocalForwardSpec {
            name: "local-echo".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            target: TargetAddr::new("server-side-echo", 7),
            max_connections: Some(4),
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open local forward");

    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect local forward");
    sock.write_all(b"ping")
        .await
        .expect("write through forward");
    let mut buf = [0u8; 4];
    sock.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, b"ping");

    handle.close().await;
    server.shutdown().await;
}

#[tokio::test]
async fn russh_backend_dynamic_forward_bridges_socks5_to_direct_tcpip() {
    let (server, mut session) = connect_russh_session().await;
    let port = free_loopback_port().await;

    let handle = session
        .open_dynamic_forward(&DynamicForwardSpec {
            name: "dynamic-proxy".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            max_connections: Some(4),
            allow_socks4: true,
            allow_socks4a: true,
            allow_socks5: true,
            allow_http_connect: true,
            allow_targets: Vec::new(),
            deny_targets: Vec::new(),
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open dynamic forward");

    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect dynamic forward");
    sock.write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write SOCKS greeting");
    let mut method = [0_u8; 2];
    sock.read_exact(&mut method)
        .await
        .expect("read SOCKS method");
    assert_eq!(method, [0x05, 0x00]);

    let host = b"server-side-echo";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&7_u16.to_be_bytes());
    sock.write_all(&request).await.expect("write SOCKS connect");
    let mut reply = [0_u8; 10];
    sock.read_exact(&mut reply).await.expect("read SOCKS reply");
    assert_eq!(&reply[..2], &[0x05, 0x00]);

    sock.write_all(b"dyn!").await.expect("write payload");
    let mut echoed = [0_u8; 4];
    sock.read_exact(&mut echoed).await.expect("read echo");
    assert_eq!(&echoed, b"dyn!");

    handle.close().await;
    server.shutdown().await;
}

#[tokio::test]
async fn russh_backend_dynamic_forward_bridges_socks4_to_direct_tcpip() {
    let (server, mut session) = connect_russh_session().await;
    let port = free_loopback_port().await;

    let handle = session
        .open_dynamic_forward(&DynamicForwardSpec {
            name: "dynamic-socks4-proxy".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            max_connections: Some(4),
            allow_socks4: true,
            allow_socks4a: true,
            allow_socks5: true,
            allow_http_connect: true,
            allow_targets: Vec::new(),
            deny_targets: Vec::new(),
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open dynamic forward");

    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect dynamic forward");
    sock.write_all(&[
        0x04, 0x01, 0x00, 0x07, 192, 0, 2, 10, b'u', b's', b'e', b'r', 0x00,
    ])
    .await
    .expect("write SOCKS4 connect");

    let mut reply = [0_u8; 8];
    sock.read_exact(&mut reply)
        .await
        .expect("read SOCKS4 reply");
    assert_eq!(&reply[..2], &[0x00, 0x5a]);

    sock.write_all(b"s4!!").await.expect("write payload");
    let mut echoed = [0_u8; 4];
    sock.read_exact(&mut echoed).await.expect("read echo");
    assert_eq!(&echoed, b"s4!!");

    handle.close().await;
    server.shutdown().await;
}

#[tokio::test]
async fn russh_backend_dynamic_forward_bridges_socks4a_to_direct_tcpip() {
    let (server, mut session) = connect_russh_session().await;
    let port = free_loopback_port().await;

    let handle = session
        .open_dynamic_forward(&DynamicForwardSpec {
            name: "dynamic-socks4a-proxy".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            max_connections: Some(4),
            allow_socks4: true,
            allow_socks4a: true,
            allow_socks5: true,
            allow_http_connect: true,
            allow_targets: Vec::new(),
            deny_targets: Vec::new(),
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open dynamic forward");

    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect dynamic forward");
    sock.write_all(&[
        0x04, 0x01, 0x00, 0x07, 0, 0, 0, 1, 0x00, b's', b'e', b'r', b'v', b'e', b'r', b'-', b's',
        b'i', b'd', b'e', b'-', b'e', b'c', b'h', b'o', 0x00,
    ])
    .await
    .expect("write SOCKS4A connect");

    let mut reply = [0_u8; 8];
    sock.read_exact(&mut reply)
        .await
        .expect("read SOCKS4A reply");
    assert_eq!(&reply[..2], &[0x00, 0x5a]);

    sock.write_all(b"s4a!").await.expect("write payload");
    let mut echoed = [0_u8; 4];
    sock.read_exact(&mut echoed).await.expect("read echo");
    assert_eq!(&echoed, b"s4a!");

    handle.close().await;
    server.shutdown().await;
}

#[tokio::test]
async fn russh_backend_dynamic_forward_bridges_http_connect_to_direct_tcpip() {
    let (server, mut session) = connect_russh_session().await;
    let port = free_loopback_port().await;

    let handle = session
        .open_dynamic_forward(&DynamicForwardSpec {
            name: "dynamic-http-proxy".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            max_connections: Some(4),
            allow_socks4: true,
            allow_socks4a: true,
            allow_socks5: true,
            allow_http_connect: true,
            allow_targets: Vec::new(),
            deny_targets: Vec::new(),
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open dynamic forward");

    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect dynamic forward");
    sock.write_all(b"CONNECT server-side-echo:7 HTTP/1.1\r\nHost: server-side-echo:7\r\n\r\n")
        .await
        .expect("write HTTP CONNECT request");

    let mut response = [0_u8; 39];
    sock.read_exact(&mut response)
        .await
        .expect("read HTTP CONNECT response");
    assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");

    sock.write_all(b"http").await.expect("write payload");
    let mut echoed = [0_u8; 4];
    sock.read_exact(&mut echoed).await.expect("read echo");
    assert_eq!(&echoed, b"http");

    handle.close().await;
    server.shutdown().await;
}

/// SSRF-mitigation ACL: a SOCKS5 target on the deny-list is rejected at the
/// SOCKS layer with reply code 0x02 ("connection not allowed by ruleset")
/// before any channel is opened.
#[tokio::test]
async fn russh_backend_dynamic_forward_acl_denies_target_with_socks5_code_02() {
    let (server, mut session) = connect_russh_session().await;
    let port = free_loopback_port().await;

    let handle = session
        .open_dynamic_forward(&DynamicForwardSpec {
            name: "dynamic-acl-deny".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            max_connections: Some(4),
            allow_socks4: true,
            allow_socks4a: true,
            allow_socks5: true,
            allow_http_connect: true,
            allow_targets: Vec::new(),
            deny_targets: vec!["server-side-echo".to_string()],
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open dynamic forward");

    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect dynamic forward");
    sock.write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write SOCKS greeting");
    let mut method = [0_u8; 2];
    sock.read_exact(&mut method)
        .await
        .expect("read SOCKS method");
    assert_eq!(method, [0x05, 0x00]);

    let host = b"server-side-echo";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&7_u16.to_be_bytes());
    sock.write_all(&request).await.expect("write SOCKS connect");
    let mut reply = [0_u8; 10];
    sock.read_exact(&mut reply).await.expect("read SOCKS reply");
    // 0x02 == connection not allowed by ruleset.
    assert_eq!(&reply[..2], &[0x05, 0x02], "denied target must reply 0x02");

    handle.close().await;
    server.shutdown().await;
}

/// SSRF-mitigation ACL: a SOCKS5 target matching the allow-list is bridged
/// normally (positive-match path preserved when an allow-list is configured).
#[tokio::test]
async fn russh_backend_dynamic_forward_acl_allows_listed_target() {
    let (server, mut session) = connect_russh_session().await;
    let port = free_loopback_port().await;

    let handle = session
        .open_dynamic_forward(&DynamicForwardSpec {
            name: "dynamic-acl-allow".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            max_connections: Some(4),
            allow_socks4: true,
            allow_socks4a: true,
            allow_socks5: true,
            allow_http_connect: true,
            allow_targets: vec!["server-*".to_string()],
            deny_targets: Vec::new(),
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open dynamic forward");

    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect dynamic forward");
    sock.write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write SOCKS greeting");
    let mut method = [0_u8; 2];
    sock.read_exact(&mut method)
        .await
        .expect("read SOCKS method");
    assert_eq!(method, [0x05, 0x00]);

    let host = b"server-side-echo";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&7_u16.to_be_bytes());
    sock.write_all(&request).await.expect("write SOCKS connect");
    let mut reply = [0_u8; 10];
    sock.read_exact(&mut reply).await.expect("read SOCKS reply");
    assert_eq!(&reply[..2], &[0x05, 0x00], "allowed target must succeed");

    sock.write_all(b"acl!").await.expect("write payload");
    let mut echoed = [0_u8; 4];
    sock.read_exact(&mut echoed).await.expect("read echo");
    assert_eq!(&echoed, b"acl!");

    handle.close().await;
    server.shutdown().await;
}

#[tokio::test]
async fn russh_backend_remote_forward_bridges_server_to_client() {
    let (server, mut session) = connect_russh_session().await;

    let local_target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local target");
    let local_target_port = local_target.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        let (mut sock, _) = local_target.accept().await.expect("accept local target");
        let mut buf = [0u8; 4];
        sock.read_exact(&mut buf)
            .await
            .expect("read server-originated bytes");
        let _ = seen_tx.send(buf.to_vec());
    });

    let remote_port = free_loopback_port().await;
    let handle = session
        .open_remote_forward(&RemoteForwardSpec {
            name: "remote-to-local".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{remote_port}")).unwrap(),
            target: TargetAddr::new("127.0.0.1", local_target_port),
            max_connections: Some(4),
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open remote forward");

    let mut remote_sock = connect_with_retry(remote_port).await;
    remote_sock
        .write_all(b"pong")
        .await
        .expect("write to remote listener");
    drop(remote_sock);

    let seen = tokio::time::timeout(Duration::from_secs(5), seen_rx)
        .await
        .expect("timely server-to-client delivery")
        .expect("local target receives bytes");
    assert_eq!(seen, b"pong");

    handle.close().await;
    server.shutdown().await;
}

/// Regression guard for the reverse-forward DoS (`remote_loop` ignored
/// `max_connections`). With `max_connections = 2`, driving 5 concurrent inbound
/// connections to the server-bound remote port must land at most 2 concurrent
/// bridges at the local target; the surplus inbound channels are closed by the
/// gate and never reach the target. A permit is then released when a bridge
/// ends, so a later inbound connection is admitted.
///
/// Against the pre-fix unbounded code every inbound channel spawned a bridge, so
/// all 5 would connect to the target and the `<= 2` assertion below fails.
#[tokio::test]
async fn russh_backend_remote_forward_enforces_max_connections() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let (server, mut session) = connect_russh_session().await;

    // Local target: track concurrent + total accepted connections. Each accepted
    // stream is held open (read until EOF) so an admitted bridge stays alive and
    // keeps its concurrency slot occupied.
    let local_target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local target");
    let local_target_port = local_target.local_addr().unwrap().port();
    let active = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    {
        let active = Arc::clone(&active);
        let total = Arc::clone(&total);
        let peak = Arc::clone(&peak);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = local_target.accept().await else {
                    break;
                };
                total.fetch_add(1, Ordering::SeqCst);
                let cur = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(cur, Ordering::SeqCst);
                let active = Arc::clone(&active);
                tokio::spawn(async move {
                    // Drain until the bridge closes (EOF), then free the slot.
                    let mut buf = [0u8; 256];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
    }

    let remote_port = free_loopback_port().await;
    let handle = session
        .open_remote_forward(&RemoteForwardSpec {
            name: "remote-capped".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{remote_port}")).unwrap(),
            target: TargetAddr::new("127.0.0.1", local_target_port),
            max_connections: Some(2),
            // Default limits => max_new_conns_per_sec = 0 (unlimited rate), so
            // only the concurrency cap is under test.
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open remote forward");

    // Drive 5 concurrent inbound connections; hold them open so their bridges
    // (the admitted ones) stay alive and occupy slots.
    let mut inbound = Vec::new();
    for _ in 0..5 {
        let mut sock = connect_with_retry(remote_port).await;
        // A byte of traffic ensures the forwarded-tcpip channel is live.
        let _ = sock.write_all(b"x").await;
        inbound.push(sock);
    }

    // Wait for the admitted bridges to reach the target.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while active.load(Ordering::SeqCst) < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // Let any (erroneously) surplus bridges settle, then assert the cap held.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        active.load(Ordering::SeqCst),
        2,
        "reverse forward must hold exactly max_connections=2 concurrent bridges"
    );
    assert_eq!(
        peak.load(Ordering::SeqCst),
        2,
        "concurrent bridge count must never exceed max_connections"
    );
    assert_eq!(
        total.load(Ordering::SeqCst),
        2,
        "surplus inbound channels must be closed by the gate, not bridged to the target"
    );

    // Release a slot: dropping all inbound connections ends the live bridges.
    inbound.clear();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while active.load(Ordering::SeqCst) > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        active.load(Ordering::SeqCst),
        0,
        "bridges must release their slots when the inbound connections close"
    );

    // A fresh inbound connection is now admitted (the limiter did not wedge).
    let mut sock = connect_with_retry(remote_port).await;
    let _ = sock.write_all(b"y").await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while active.load(Ordering::SeqCst) < 1 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        active.load(Ordering::SeqCst),
        1,
        "a freed slot must admit a new inbound connection"
    );
    assert_eq!(
        total.load(Ordering::SeqCst),
        3,
        "exactly one further bridge should have been admitted after release"
    );

    drop(sock);
    handle.close().await;
    server.shutdown().await;
}

async fn connect_with_retry(port: u16) -> TcpStream {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(sock) => return sock,
            Err(e) if tokio::time::Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => panic!("connect remote listener on {port}: {e}"),
        }
    }
}

// ──────── E3-F1: real keepalive liveness probe ────────────────────────

/// A live SSH2 session's `keepalive()` is a real probe and succeeds while the
/// session is healthy (previously it was an unconditional `Ok(())` no-op, so
/// success carried no signal). The companion test below proves it returns
/// `Err` once the session is dead.
#[tokio::test]
async fn russh_backend_keepalive_probe_succeeds_on_live_session() {
    let (server, mut session) = connect_russh_session().await;
    session
        .keepalive()
        .await
        .expect("keepalive probe must succeed on a live session");
    server.shutdown().await;
}

/// The core E3-F1 regression: after the transport is black-holed (NAT/idle
/// drop, network partition, server crash), the SSH2 `keepalive()` probe must
/// return `Err` so the supervisor's `run_active` loop can trigger session
/// replacement (spec §11.3). Before the fix `keepalive()` always returned
/// `Ok(())`, so a dead SSH2 session was detected only when real forward
/// traffic happened to hit an I/O error.
///
/// We interpose a tiny TCP relay between the client and the russh test server
/// so we can sever the established connection deterministically (the test
/// server's `shutdown()` only stops its accept loop — already-established
/// per-connection tasks survive, which does not model a dead link).
#[tokio::test]
async fn russh_backend_keepalive_probe_detects_dead_session() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    let server_port = server.addr.port();

    // Killable TCP relay: client → relay → server. `kill_rx` drops every
    // proxied connection, black-holing the SSH transport.
    let relay = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay listener");
    let relay_port = relay.local_addr().unwrap().port();
    let (kill_tx, kill_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            let Ok((mut client_side, _)) = relay.accept().await else {
                break;
            };
            let mut kill_rx = kill_rx.clone();
            tokio::spawn(async move {
                let Ok(mut server_side) = TcpStream::connect(("127.0.0.1", server_port)).await
                else {
                    return;
                };
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut client_side, &mut server_side) => {}
                    _ = kill_rx.changed() => {
                        // Drop both halves → RST/EOF on the client transport.
                    }
                }
            });
        }
    });

    std::env::set_var("SPT_TEST_RUSSH_BACKEND_PW", "anything");
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .build();
    let endpoint = Endpoint::new("127.0.0.1", relay_port);
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_RUSSH_BACKEND_PW".into()),
        }],
    );
    let mut session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("connect through relay");

    // Sanity: probe is healthy while the link is up.
    session
        .keepalive()
        .await
        .expect("keepalive healthy before the link is severed");

    // Black-hole the transport.
    kill_tx.send(true).expect("signal relay kill");

    // Poll the probe until it reports the session is dead. The russh event
    // loop may take a moment to notice the dropped socket, so retry within a
    // bounded window rather than asserting on the first call.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match session.keepalive().await {
            Err(_) => break, // detected the dead session — success.
            Ok(()) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Ok(()) => panic!(
                "keepalive() still reported Ok after the link was severed — \
                 dead SSH2 session went undetected (E3-F1 regression)"
            ),
        }
    }

    server.shutdown().await;
}

/// The transport-keepalive policy set via the builder reaches a real connect
/// without breaking the handshake (E3-F1 config plumbing, end-to-end). With a
/// short interval russh emits `keepalive@openssh.com` global requests; the
/// session must still establish and probe healthy.
#[tokio::test]
async fn russh_backend_connects_with_transport_keepalive_policy() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");

    std::env::set_var("SPT_TEST_RUSSH_BACKEND_PW", "anything");
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .keepalive(Some(Duration::from_secs(1)), Some(3))
        .build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_RUSSH_BACKEND_PW".into()),
        }],
    );
    let mut session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("connect with transport keepalive policy");
    session
        .keepalive()
        .await
        .expect("probe healthy with transport keepalive enabled");
    server.shutdown().await;
}

/// E3-F9: a profile configured with `gssapi`/`sspi` must fail fast at connect
/// (and `Ssh2Protocol::validate_auth` rejects it up-front) rather than after a
/// wasted TCP connect + backoff cycle.
#[tokio::test]
async fn russh_backend_rejects_gssapi_before_connect() {
    // No server needed — validation must fire before any socket is opened.
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .build();
    let endpoint = Endpoint::new("127.0.0.1", 1);
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Gssapi {
            service: None,
            principal: None,
            delegate: false,
        }],
    );

    // Up-front validation surface used by config/profile build.
    let pre = Ssh2Protocol::validate_auth(&auth);
    assert!(
        matches!(pre, Err(spt_core::Error::InvalidConfig(_))),
        "validate_auth must reject gssapi: {pre:?}"
    );

    // The connect path enforces it too (fail fast, no connect attempt).
    match proto.connect(&endpoint, &auth).await {
        Err(spt_core::Error::InvalidConfig(_)) => {}
        Err(other) => panic!("connect rejected gssapi with the wrong error: {other:?}"),
        Ok(_) => panic!("connect must reject gssapi before dialing, but it succeeded"),
    }
}

// -----------------------------------------------------------------------------
// t7-Bwire: end-to-end multi-hop dispatch through `Ssh2Protocol::connect`.
// Phase 0 left the russh backend rejecting `has_hops`; Bwire wires
// `multi_hop::open_chained_session` into the connect path so a profile with a
// non-empty `[[profiles.hops]]` table now walks the chain end-to-end.
// -----------------------------------------------------------------------------

#[tokio::test]
async fn ssh2_protocol_connect_walks_two_hop_chain() {
    // Bastion (hops[0]) -> endpoint. The endpoint server hosts the final
    // SSH session that the supervisor talks to.
    let bastion = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("bastion start");
    let endpoint_server = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("endpoint start");

    std::env::set_var("SPT_TEST_HOP_PW", "pw");
    let auth = AuthConfig::new(
        "u",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_HOP_PW".into()),
        }],
    );
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .hop(bastion.addr.ip().to_string(), bastion.addr.port())
        .build();
    let endpoint = Endpoint::new("127.0.0.1", endpoint_server.addr.port());
    let session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("connect through 2-hop chain");

    assert_eq!(session.session_info().backend, "ssh2-russh");
    assert!(
        session
            .session_info()
            .negotiated
            .as_deref()
            .unwrap_or("")
            .contains("multi-hop"),
        "session_info should mark multi-hop"
    );
    assert!(bastion.connection_count() >= 1);
    assert!(endpoint_server.connection_count() >= 1);
    assert!(
        bastion.channel_opens_direct_tcpip() >= 1,
        "bastion should host the direct-tcpip channel to the endpoint"
    );

    session.close().await.expect("close");
    bastion.shutdown().await;
    endpoint_server.shutdown().await;
}

// -----------------------------------------------------------------------------
// tw-authtrust — P0/P1 auth-reject + per-hop trust security regressions.
//
// These tests drive BAD credentials / an UNTRUSTED hop key through the real
// `Ssh2Protocol::connect` path and assert the connection is REFUSED. Each one
// fails if the corresponding control silently regressed (auth accepts wrong
// creds, or a mid-chain / final host key is trusted without verification).
// -----------------------------------------------------------------------------

/// P0: a WRONG password must be rejected by `connect` with an auth failure and
/// no session; the CORRECT password (same server) must authenticate. This is
/// the anti-bypass guard: if the `.success()` handling in `run_auth` regressed
/// (e.g. collapsed to always-accept), the wrong-password half would connect and
/// this test would fail.
#[tokio::test]
async fn russh_backend_rejects_wrong_password_accepts_correct() {
    let server = RusshTestServer::new()
        .with_password("tester", "correct-horse")
        .start()
        .await
        .expect("start russh server");
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .build();

    // WRONG password → AuthFailed, no session established.
    std::env::set_var("SPT_TEST_TW_WRONGPW", "definitely-not-it");
    let bad_auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_TW_WRONGPW".into()),
        }],
    );
    let err = proto
        .connect(&endpoint, &bad_auth)
        .await
        .map(|_| ())
        .expect_err("a wrong password must be rejected, not authenticated");
    assert_eq!(
        err.exit_code(),
        spt_core::ExitCode::AuthFailed,
        "wrong password must map to an auth failure, got: {err:?}"
    );
    assert!(
        server.auth_attempts() >= 1,
        "the server must have actually seen and rejected the credential attempt"
    );

    // CORRECT password → success. Proves the server WOULD accept valid creds,
    // so the rejection above is a genuine credential check (not the server
    // refusing everything).
    std::env::set_var("SPT_TEST_TW_RIGHTPW", "correct-horse");
    let ok_auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_TW_RIGHTPW".into()),
        }],
    );
    let session = proto
        .connect(&endpoint, &ok_auth)
        .await
        .expect("the correct password must authenticate");
    session.close().await.expect("close");

    std::env::remove_var("SPT_TEST_TW_WRONGPW");
    std::env::remove_var("SPT_TEST_TW_RIGHTPW");
    server.shutdown().await;
}

/// Write a fresh ephemeral Ed25519 private key in OpenSSH format to `dir/name`
/// and return `(path, public_key)`. The public half is handed to the test
/// server's `with_authorized_pubkey` allow-list; the private path is fed to
/// `AuthMethod::PublicKey`.
fn write_ephemeral_openssh_key(
    dir: &std::path::Path,
    name: &str,
) -> (std::path::PathBuf, russh::keys::ssh_key::PublicKey) {
    use russh::keys::ssh_key::{Algorithm, LineEnding, PrivateKey};
    let key = PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519).expect("ed25519 keygen");
    let pem = key
        .to_openssh(LineEnding::LF)
        .expect("encode openssh private key");
    let path = dir.join(name);
    std::fs::write(&path, pem.as_bytes()).expect("write private key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 key");
    }
    (path, key.public_key().clone())
}

/// P1: file-based public-key auth. The server authorises exactly ONE key; the
/// matching private key authenticates, a DIFFERENT (unauthorised) key is
/// rejected with an auth failure. Fails if the `AuthMethod::PublicKey` arm ever
/// regressed to accepting any key.
#[tokio::test]
async fn russh_backend_pubkey_authorized_accepts_unauthorized_rejects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (authorized_key_path, authorized_pub) = write_ephemeral_openssh_key(dir.path(), "id_ok");
    let (unauthorized_key_path, _unauth_pub) = write_ephemeral_openssh_key(dir.path(), "id_bad");

    let server = RusshTestServer::new()
        .with_authorized_pubkey(authorized_pub)
        .start()
        .await
        .expect("start russh server");
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .build();

    // Authorized key → success.
    let ok_auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::PublicKey {
            identity_file: authorized_key_path.clone(),
            passphrase: None,
            allow_ssh_rsa_sha1: false,
        }],
    );
    let session = proto
        .connect(&endpoint, &ok_auth)
        .await
        .expect("an authorized public key must authenticate");
    session.close().await.expect("close");

    // Unauthorized key → AuthFailed.
    let bad_auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::PublicKey {
            identity_file: unauthorized_key_path.clone(),
            passphrase: None,
            allow_ssh_rsa_sha1: false,
        }],
    );
    let err = proto
        .connect(&endpoint, &bad_auth)
        .await
        .map(|_| ())
        .expect_err("an unauthorized public key must be rejected");
    assert_eq!(
        err.exit_code(),
        spt_core::ExitCode::AuthFailed,
        "unauthorized public key must map to an auth failure, got: {err:?}"
    );

    server.shutdown().await;
}

/// P1: per-hop trust in a multi-hop chain. An intermediate (mid-chain) hop
/// whose host key can't be verified (strict, no trust source → no TOFU) MUST
/// abort the WHOLE chain — a bastion can't be silently swapped/MitM'd and
/// tunneled past. Asserts the failure is `TrustFailed` and, crucially, that the
/// FINAL endpoint is never contacted once the mid-chain key is rejected.
#[tokio::test]
async fn multi_hop_untrusted_intermediate_hop_key_aborts_whole_chain() {
    // hop0 (bastion A, trusted via endpoint-fallback TOFU)
    //   -> hop1 (bastion B, MIDDLE, UNTRUSTED key)
    //     -> endpoint (never reached).
    let bastion_a = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("bastion A start");
    let bastion_b = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("bastion B start");
    let endpoint_server = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("endpoint start");

    std::env::set_var("SPT_TEST_TW_HOP_PW", "pw");
    let auth = AuthConfig::new(
        "u",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_TW_HOP_PW".into()),
        }],
    );

    // Strict + empty trust source + no TOFU: the presented key is in NO source,
    // so `verify()` refuses (TrustFailed). Models an unverifiable/MitM'd hop.
    let untrusted = spt_ssh2::TrustPolicy {
        strict: true,
        accept_new: false,
        ..Default::default()
    };

    let proto = Ssh2Protocol::builder()
        // Endpoint + hop0 fallback: accepting TOFU.
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .hop(bastion_a.addr.ip().to_string(), bastion_a.addr.port())
        // Mid-chain hop pins its own UNTRUSTED policy.
        .hop_with_auth_trust(
            bastion_b.addr.ip().to_string(),
            bastion_b.addr.port(),
            auth.clone(),
            untrusted,
        )
        .build();
    let endpoint = Endpoint::new("127.0.0.1", endpoint_server.addr.port());

    let err = proto
        .connect(&endpoint, &auth)
        .await
        .map(|_| ())
        .expect_err("an untrusted mid-chain hop key must abort the whole chain");
    assert!(
        matches!(err, spt_core::Error::TrustFailed(_)),
        "mid-chain host-key rejection must surface TrustFailed, got: {err:?}"
    );
    assert!(
        bastion_a.connection_count() >= 1,
        "the chain must have reached and authed hop0 before verifying hop1"
    );
    assert_eq!(
        endpoint_server.connection_count(),
        0,
        "the final endpoint must NOT be reached once a mid-chain hop key is rejected"
    );

    std::env::remove_var("SPT_TEST_TW_HOP_PW");
    bastion_a.shutdown().await;
    bastion_b.shutdown().await;
    endpoint_server.shutdown().await;
}

/// P1: the FINAL target's host key is independently verified — reaching the end
/// of an otherwise-trusted hop chain does not grant the endpoint a free pass. A
/// strict/empty endpoint trust rejects the final target key with `TrustFailed`,
/// even though the bastion hop was reached and trusted.
#[tokio::test]
async fn multi_hop_final_endpoint_key_is_verified_and_can_reject() {
    let bastion = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("bastion start");
    let endpoint_server = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("endpoint start");

    std::env::set_var("SPT_TEST_TW_FINAL_PW", "pw");
    let auth = AuthConfig::new(
        "u",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_TW_FINAL_PW".into()),
        }],
    );

    // Endpoint trust: strict + empty → the final target's key is rejected.
    let untrusted_endpoint = spt_ssh2::TrustPolicy {
        strict: true,
        accept_new: false,
        ..Default::default()
    };

    let proto = Ssh2Protocol::builder()
        .trust(untrusted_endpoint)
        // Bastion gets its OWN accepting trust so the chain reaches the final
        // leg (otherwise the endpoint's strict policy would reject hop0 too).
        .hop_with_auth_trust(
            bastion.addr.ip().to_string(),
            bastion.addr.port(),
            auth.clone(),
            spt_ssh2::testing::tofu_trust_verifier(),
        )
        .build();
    let endpoint = Endpoint::new("127.0.0.1", endpoint_server.addr.port());

    let err = proto
        .connect(&endpoint, &auth)
        .await
        .map(|_| ())
        .expect_err("the final target's host key must be verified and can reject");
    assert!(
        matches!(err, spt_core::Error::TrustFailed(_)),
        "final-target host-key rejection must surface TrustFailed, got: {err:?}"
    );
    assert!(
        bastion.connection_count() >= 1,
        "the trusted bastion hop must have been reached before the final key check"
    );

    std::env::remove_var("SPT_TEST_TW_FINAL_PW");
    bastion.shutdown().await;
    endpoint_server.shutdown().await;
}

#[tokio::test]
async fn ssh2_protocol_connect_walks_three_hop_chain() {
    // hops[0] -> hops[1] -> endpoint.
    let bastion_a = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("bastion A start");
    let bastion_b = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("bastion B start");
    let endpoint_server = RusshTestServer::new()
        .with_password("u", "pw")
        .start()
        .await
        .expect("endpoint start");

    std::env::set_var("SPT_TEST_HOP3_PW", "pw");
    let auth = AuthConfig::new(
        "u",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_HOP3_PW".into()),
        }],
    );
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .hop(bastion_a.addr.ip().to_string(), bastion_a.addr.port())
        .hop(bastion_b.addr.ip().to_string(), bastion_b.addr.port())
        .build();
    let endpoint = Endpoint::new("127.0.0.1", endpoint_server.addr.port());
    let session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("connect through 3-hop chain");

    assert_eq!(session.session_info().backend, "ssh2-russh");
    assert!(bastion_a.connection_count() >= 1);
    assert!(bastion_b.connection_count() >= 1);
    assert!(endpoint_server.connection_count() >= 1);
    assert!(bastion_a.channel_opens_direct_tcpip() >= 1);
    assert!(bastion_b.channel_opens_direct_tcpip() >= 1);

    session.close().await.expect("close");
    bastion_a.shutdown().await;
    bastion_b.shutdown().await;
    endpoint_server.shutdown().await;
}
