#![allow(clippy::missing_panics_doc)]

use std::time::Duration;

use spt_auth::{AuthConfig, AuthMethod};
use spt_core::BindAddr;
use spt_protocol::{
    DynamicForwardSpec, Endpoint, LocalForwardSpec, RemoteForwardSpec, TargetAddr, TunnelProtocol,
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
