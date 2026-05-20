#![allow(clippy::missing_panics_doc)]

use std::time::Duration;

use spt_auth::{AuthConfig, AuthMethod};
use spt_core::BindAddr;
use spt_protocol::{Endpoint, LocalForwardSpec, RemoteForwardSpec, TargetAddr, TunnelProtocol};
use spt_ssh2::testing::RusshTestServer;
use spt_ssh2::{Ssh2BackendKind, Ssh2Protocol};
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
        .backend_kind(Ssh2BackendKind::Russh)
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
