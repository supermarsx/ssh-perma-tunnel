//! e2e (Wave B): ssh2 dynamic SOCKS forward + UDP-forward capability contract +
//! multi-hop chain driven through the supervisor/`OrchestratorBuilder`.
//!
//! All variants drive the **real** `Ssh2Protocol` (pure russh 0.61) against the
//! embedded `RusshTestServer` fixture(s) — loopback only, no real network. They
//! mirror the recipe in the shipped `ssh2_local_forward.rs` / `ssh2_multi_forward.rs`
//! real-russh tests (server `.with_password`, `tofu_trust_verifier`, env-ref
//! password auth, byte round-trip through the server's `server-side-echo:7`
//! echo backend).
//!
//! ## Coverage
//!
//! * **Dynamic (SOCKS) forward** — `open_dynamic_forward` opens a local SOCKS
//!   proxy; a SOCKS5 CONNECT to the sentinel `server-side-echo:7` opens a
//!   server-side `direct-tcpip` channel and a byte payload round-trips. Plus a
//!   two-stream isolation variant and a refused-target negative.
//! * **UDP forward** — the ssh2/russh backend does **not** support UDP forwards
//!   (UDP is an SSH3 capability). Rather than fake a datagram echo, we assert the
//!   real `UnsupportedPlatform` contract the backend returns from
//!   `open_udp_forward`, and that `ProtocolCapabilities::ssh2()` advertises no
//!   UDP support. (Linux gate: nothing cfg(unix)-specific here.)
//! * **Multi-hop via supervisor** — an `Ssh2Protocol` configured with one
//!   intermediate `.hop(A)` reaches endpoint `B` through A's `direct-tcpip`
//!   channel; the chain is brought to `Active` via `OrchestratorBuilder` /
//!   `wait_for_state`, and a forward on `B` round-trips end-to-end across the
//!   hop. A broken-middle-hop negative asserts the supervisor never reaches
//!   `Active`.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::Duration;

use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_config::schema::Profile;
use spt_config::testing::{ForwardBuilder, ProfileBuilder};
use spt_core::BindAddr;
use spt_protocol::{
    BindConflictPolicy, DynamicForwardSpec, Endpoint, ForwardDirection, ForwardRateLimits,
    ProtocolCapabilities, TargetAddr, TunnelProtocol, UdpForwardSpec,
};
use spt_ssh2::testing::RusshTestServer;
use spt_ssh2::Ssh2Protocol;
use spt_supervisor::testing::{
    wait_for_state, OrchestratorBuilder, ProfileStateName, ProfileSupervisorConfig,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

async fn free_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// Build the real `Ssh2Protocol` client (tofu trust, no hops).
fn build_proto() -> Ssh2Protocol {
    Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .build()
}

/// Password `AuthConfig` resolving `user` via the named env var.
fn env_password_auth(user: &str, env_var: &str) -> AuthConfig {
    AuthConfig::new(
        user,
        vec![AuthMethod::Password {
            secret: SecretRef::Env(env_var.into()),
        }],
    )
}

/// Perform a SOCKS5 no-auth greeting + CONNECT to `host:port` over an already
/// connected stream to the local dynamic-forward listener. Returns once the
/// SOCKS reply indicates success (the channel is now wired to the target).
async fn socks5_connect(sock: &mut TcpStream, host: &[u8], port: u16) {
    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
    sock.write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write SOCKS greeting");
    let mut method = [0u8; 2];
    sock.read_exact(&mut method)
        .await
        .expect("read SOCKS method selection");
    assert_eq!(method, [0x05, 0x00], "server must select no-auth");

    // CONNECT request: VER=5, CMD=1(connect), RSV=0, ATYP=3(domain), len, host, port.
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&request).await.expect("write SOCKS connect");

    // Reply: VER, REP, RSV, ATYP, BND.ADDR(4 for ipv4), BND.PORT(2) = 10 bytes.
    let mut reply = [0u8; 10];
    sock.read_exact(&mut reply)
        .await
        .expect("read SOCKS connect reply");
    assert_eq!(reply[0], 0x05, "SOCKS version in reply");
    assert_eq!(reply[1], 0x00, "SOCKS reply must indicate success (0x00)");
}

// =============================================================================
// Dynamic (SOCKS) forward — real russh byte round-trip
// =============================================================================

/// Open a dynamic (SOCKS) forward, SOCKS5-CONNECT to the server's
/// `server-side-echo:7` sentinel, and assert a multi-KiB payload round-trips
/// through the server-side `direct-tcpip` echo backend.
#[tokio::test]
async fn dynamic_socks5_forward_roundtrip_real_russh() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");

    std::env::set_var("SPT_TEST_E2E_DYN_PW", "anything");
    let proto = build_proto();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let mut session = proto
        .connect(
            &endpoint,
            &env_password_auth("tester", "SPT_TEST_E2E_DYN_PW"),
        )
        .await
        .expect("russh backend connects");

    let port = free_loopback_port().await;
    let handle = session
        .open_dynamic_forward(&DynamicForwardSpec {
            name: "dyn-echo".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            max_connections: Some(4),
            allow_socks4: false,
            allow_socks4a: false,
            allow_socks5: true,
            allow_http_connect: false,
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open dynamic forward");

    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect dynamic forward listener");
    socks5_connect(&mut sock, b"server-side-echo", 7).await;

    // A multi-KiB payload exercises chunked channel-data through the SOCKS proxy.
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    sock.write_all(&payload)
        .await
        .expect("write through dynamic forward");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut echoed))
        .await
        .expect("timely echo")
        .expect("read echo");
    assert_eq!(
        echoed, payload,
        "bytes must round-trip through the SOCKS5 dynamic forward"
    );

    // The SOCKS CONNECT opened a server-side direct-tcpip channel.
    assert!(
        server.channel_opens_direct_tcpip() >= 1,
        "dynamic forward must open a direct-tcpip channel; got {}",
        server.channel_opens_direct_tcpip()
    );

    handle.close().await;
    session.close().await.expect("close session");
    server.shutdown().await;
}

/// Two independent SOCKS5 streams over the **same** dynamic forward each carry
/// their own byte round-trip — proving per-connection channel isolation on the
/// single proxy listener.
#[tokio::test]
async fn dynamic_socks5_two_streams_isolated_real_russh() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");

    std::env::set_var("SPT_TEST_E2E_DYN2_PW", "anything");
    let proto = build_proto();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let mut session = proto
        .connect(
            &endpoint,
            &env_password_auth("tester", "SPT_TEST_E2E_DYN2_PW"),
        )
        .await
        .expect("russh backend connects");

    let port = free_loopback_port().await;
    let handle = session
        .open_dynamic_forward(&DynamicForwardSpec {
            name: "dyn-multi".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            max_connections: Some(8),
            allow_socks4: false,
            allow_socks4a: false,
            allow_socks5: true,
            allow_http_connect: false,
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open dynamic forward");

    // Drive two concurrent SOCKS5 streams with distinct payloads.
    let mut tasks = Vec::with_capacity(2);
    for tag in 0u8..2 {
        tasks.push(tokio::spawn(async move {
            let mut sock = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect dynamic forward listener");
            socks5_connect(&mut sock, b"server-side-echo", 7).await;
            let payload: Vec<u8> = (0..1024u32).map(|n| (n as u8) ^ tag).collect();
            sock.write_all(&payload).await.expect("write payload");
            let mut echoed = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut echoed))
                .await
                .expect("timely echo")
                .expect("read echo");
            (payload, echoed)
        }));
    }
    for (i, t) in tasks.into_iter().enumerate() {
        let (sent, got) = t.await.expect("stream task join");
        assert_eq!(got, sent, "SOCKS stream #{i} must round-trip independently");
    }

    assert!(
        server.channel_opens_direct_tcpip() >= 2,
        "each SOCKS stream opens its own direct-tcpip channel; got {}",
        server.channel_opens_direct_tcpip()
    );

    handle.close().await;
    session.close().await.expect("close session");
    server.shutdown().await;
}

/// A SOCKS5 CONNECT to a target the server cannot reach (a closed loopback
/// port) must produce a non-success SOCKS reply — the dynamic forward surfaces
/// the channel-open failure to the client rather than hanging or echoing.
#[tokio::test]
async fn dynamic_socks5_refused_target_real_russh() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");

    std::env::set_var("SPT_TEST_E2E_DYN3_PW", "anything");
    let proto = build_proto();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let mut session = proto
        .connect(
            &endpoint,
            &env_password_auth("tester", "SPT_TEST_E2E_DYN3_PW"),
        )
        .await
        .expect("russh backend connects");

    let port = free_loopback_port().await;
    let handle = session
        .open_dynamic_forward(&DynamicForwardSpec {
            name: "dyn-refused".into(),
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            max_connections: Some(4),
            allow_socks4: false,
            allow_socks4a: false,
            allow_socks5: true,
            allow_http_connect: false,
            limits: ForwardRateLimits::default(),
            idle_timeout: None,
            on_bind_conflict: BindConflictPolicy::default(),
            required: false,
        })
        .await
        .expect("open dynamic forward");

    // A free (then-closed) loopback port: the server's direct-tcpip handler
    // dials it (it IS a loopback target) and fails to connect → rejects the
    // channel → the proxy returns a non-success SOCKS reply.
    let dead_port = free_loopback_port().await;

    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect dynamic forward listener");
    // Greeting.
    sock.write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write SOCKS greeting");
    let mut method = [0u8; 2];
    sock.read_exact(&mut method)
        .await
        .expect("read SOCKS method");
    assert_eq!(method, [0x05, 0x00]);

    // CONNECT to 127.0.0.1:dead_port.
    let host = b"127.0.0.1";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&dead_port.to_be_bytes());
    sock.write_all(&request).await.expect("write SOCKS connect");

    let mut reply = [0u8; 10];
    let read = tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut reply)).await;
    match read {
        // A reply byte stream arrived: REP must be non-zero (failure).
        Ok(Ok(_)) => assert_ne!(
            reply[1], 0x00,
            "SOCKS reply for an unreachable target must not be success"
        ),
        // Or the proxy closed the stream (EOF) without a success reply — also
        // an acceptable failure surfacing for a refused target.
        Ok(Err(_)) => {}
        Err(_) => panic!("SOCKS proxy hung on a refused target instead of failing"),
    }

    handle.close().await;
    session.close().await.expect("close session");
    server.shutdown().await;
}

// =============================================================================
// UDP forward — capability contract (ssh2/russh does NOT support UDP)
// =============================================================================

/// `ProtocolCapabilities::ssh2()` must advertise that UDP forwarding is NOT a
/// capability of the ssh2 backend (UDP is SSH3-only). Documents the contract at
/// the capability level.
#[test]
fn ssh2_capabilities_do_not_advertise_udp() {
    let caps = ProtocolCapabilities::ssh2();
    let ssh3 = ProtocolCapabilities::ssh3();
    assert!(
        !caps.local_udp && !caps.remote_udp,
        "ssh2 backend must not advertise UDP support"
    );
    // Sanity: ssh3 *does* support UDP, so the fields are meaningful.
    assert!(
        ssh3.local_udp && ssh3.remote_udp,
        "ssh3 backend should advertise UDP"
    );
}

/// Driving `open_udp_forward` against a real russh session must return the
/// `UnsupportedPlatform` contract (not a panic, not a fake datagram echo). This
/// is asserted against the live backend — the honest result for ssh2/russh.
#[tokio::test]
async fn udp_forward_unsupported_on_ssh2_real_russh() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");

    std::env::set_var("SPT_TEST_E2E_UDP_PW", "anything");
    let proto = build_proto();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let mut session = proto
        .connect(
            &endpoint,
            &env_password_auth("tester", "SPT_TEST_E2E_UDP_PW"),
        )
        .await
        .expect("russh backend connects");

    let port = free_loopback_port().await;
    let err = session
        .open_udp_forward(&UdpForwardSpec {
            name: "udp-nope".into(),
            direction: ForwardDirection::Local,
            listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
            target: TargetAddr::new("server-side-echo", 7),
            idle_timeout_secs: 30,
            max_flows: None,
            limits: ForwardRateLimits::default(),
        })
        .await
        .expect_err("ssh2/russh must reject UDP forwarding");
    match err {
        spt_core::Error::UnsupportedPlatform(msg) => {
            assert!(
                msg.to_lowercase().contains("udp"),
                "UnsupportedPlatform message should mention UDP; got: {msg}"
            );
        }
        other => panic!("expected UnsupportedPlatform for UDP on ssh2, got {other:?}"),
    }

    session.close().await.expect("close session");
    server.shutdown().await;
}

// =============================================================================
// Multi-hop through the supervisor / OrchestratorBuilder
// =============================================================================

fn hop_profile(name: &str, fwd_name: &str, listen_port: u16) -> Profile {
    ProfileBuilder::new(name)
        .endpoint("127.0.0.1", 22)
        .user("tester")
        .add_forward(
            ForwardBuilder::local_tcp(
                fwd_name,
                &format!("127.0.0.1:{listen_port}"),
                "server-side-echo:7",
            )
            .build(),
        )
        .build()
}

/// Happy path: an `Ssh2Protocol` with one intermediate hop (server A) reaches
/// the endpoint (server B) through A's `direct-tcpip` channel. The supervisor
/// brings the profile to `Active` via `OrchestratorBuilder`, then a local
/// forward on B round-trips a byte payload end-to-end across the hop chain.
#[tokio::test]
async fn multihop_through_supervisor_roundtrip_real_russh() {
    // Hop A and endpoint B are independent russh servers on loopback.
    let hop_a = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start hop A");
    let endpoint_b = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start endpoint B");

    std::env::set_var("SPT_TEST_E2E_HOP_PW", "anything");

    // The protocol carries the hop chain: client -> A -> B. The endpoint passed
    // to the supervisor is B; A is traversed first via direct-tcpip.
    let proto = Arc::new(
        Ssh2Protocol::builder()
            .trust(spt_ssh2::testing::tofu_trust_verifier())
            .hop("127.0.0.1", hop_a.addr.port())
            .build(),
    );
    assert_eq!(proto.hop_count(), 1, "one intermediate hop configured");

    let listen_port = free_loopback_port().await;
    let profile = hop_profile("hopped", "hop-echo", listen_port);
    let endpoints = vec![Endpoint::new("127.0.0.1", endpoint_b.addr.port())];
    let auth = env_password_auth("tester", "SPT_TEST_E2E_HOP_PW");

    let orch = OrchestratorBuilder::new()
        .with_profile(
            profile,
            proto as Arc<dyn TunnelProtocol>,
            auth,
            endpoints,
            ProfileSupervisorConfig::default(),
        )
        .build();

    wait_for_state(
        &orch,
        "hopped",
        ProfileStateName::Active,
        Duration::from_secs(15),
    )
    .await
    .expect("multi-hop profile reaches Active through the chain");

    // The forward on B round-trips end-to-end across the hop.
    let payload: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
    let mut sock = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .expect("connect forward listener on the hopped profile");
    sock.write_all(&payload)
        .await
        .expect("write through hopped forward");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), sock.read_exact(&mut echoed))
        .await
        .expect("timely echo across the hop chain")
        .expect("read echo");
    assert_eq!(
        echoed, payload,
        "bytes must round-trip end-to-end across the A->B hop chain"
    );

    // Hop A must have hosted the direct-tcpip channel that reaches B.
    assert!(
        hop_a.channel_opens_direct_tcpip() >= 1,
        "hop A should host the direct-tcpip channel reaching B; got {}",
        hop_a.channel_opens_direct_tcpip()
    );

    orch.shutdown().await;
    hop_a.shutdown().await;
    endpoint_b.shutdown().await;
}

/// Negative: a broken middle hop (pointed at a dead loopback port) means the
/// chain can never be established, so the supervisor must never reach `Active`.
#[tokio::test]
async fn multihop_broken_middle_hop_never_active_real_russh() {
    // Only the endpoint is real; the hop points at a closed port.
    let endpoint_b = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start endpoint B");

    std::env::set_var("SPT_TEST_E2E_HOPNEG_PW", "anything");

    // A free-then-closed port stands in for an unreachable bastion.
    let dead_hop_port = free_loopback_port().await;
    let proto = Arc::new(
        Ssh2Protocol::builder()
            .trust(spt_ssh2::testing::tofu_trust_verifier())
            .hop("127.0.0.1", dead_hop_port)
            .build(),
    );

    let listen_port = free_loopback_port().await;
    let profile = hop_profile("hop-broken", "broken-echo", listen_port);
    let endpoints = vec![Endpoint::new("127.0.0.1", endpoint_b.addr.port())];
    let auth = env_password_auth("tester", "SPT_TEST_E2E_HOPNEG_PW");

    // Tight backoff so the supervisor churns its (failing) connect attempts
    // quickly inside the observation window.
    let sup_cfg = ProfileSupervisorConfig {
        backoff: spt_supervisor::BackoffConfig {
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_millis(200),
            reset_after: Duration::from_secs(120),
            jitter: 1.0,
            max_attempts: 0,
            retry_auth_failures: false,
        },
        ..ProfileSupervisorConfig::default()
    };

    let orch = OrchestratorBuilder::new()
        .with_profile(
            profile,
            proto as Arc<dyn TunnelProtocol>,
            auth,
            endpoints,
            sup_cfg,
        )
        .build();

    // The chain can never establish (the hop is a black hole), so reaching
    // Active must time out.
    let reached = wait_for_state(
        &orch,
        "hop-broken",
        ProfileStateName::Active,
        Duration::from_secs(2),
    )
    .await;
    assert!(
        reached.is_err(),
        "supervisor must NOT reach Active with a broken middle hop"
    );

    // And the local forward listener must never have been bound (no forward is
    // established while the chain is down) — a connect attempt should fail.
    let connect = TcpStream::connect(("127.0.0.1", listen_port)).await;
    assert!(
        connect.is_err(),
        "no forward listener should exist while the hop chain is broken"
    );

    orch.shutdown().await;
    endpoint_b.shutdown().await;
}
