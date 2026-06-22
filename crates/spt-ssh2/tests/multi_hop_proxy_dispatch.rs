//! Proxy-hop dispatch coverage (Wave A2): exercises the kind-aware chained
//! session path [`open_chained_session_with_kind`] end-to-end for both
//! [`HopKind::Socks5`] and [`HopKind::HttpConnect`].
//!
//! Topology per test:
//!
//! 1. A real outer SSH server `A` (`RusshTestServer`) → a live client outer
//!    handle (the `prev` hop a proxy hop tunnels through).
//! 2. A loopback "proxy" TCP listener that speaks the SOCKS5 / HTTP CONNECT
//!    server side, then bridges the connection to an inner SSH server `B`.
//! 3. `open_chained_session_with_kind(shared_a, proxy_addr, B_addr, kind, …)`:
//!    server `A` opens a `direct-tcpip` channel to the (loopback) proxy, the
//!    proxy completes the CONNECT handshake aimed at `B`, then a fresh SSH
//!    session is handshaken through the tunneled stream and authenticates
//!    against `B`.
//!
//! This is the dispatch the russh backend's `open_next_leg` selects when a
//! `HopSpec.kind` is a proxy kind. The leaf SOCKS5/HTTP-CONNECT handshake
//! helpers are unit-tested in `proxy_jump.rs`; here we prove the channel ->
//! proxy -> SSH wiring works against a live russh server.

#![cfg(feature = "testing")]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;

use russh::client;
use spt_ssh2::multi_hop::{open_chained_session_with_kind, HopKind};
use spt_ssh2::testing::{wincng_libssh2_compatible_preferred, RusshTestServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Debug, Clone)]
struct PassThroughHandler;

impl client::Handler for PassThroughHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Pipe bytes both directions between an accepted proxy client and the inner
/// SSH backend until either side closes.
async fn pump(client: TcpStream, backend: TcpStream) {
    let (mut cr, mut cw) = client.into_split();
    let (mut br, mut bw) = backend.into_split();
    let c2b = async {
        let _ = tokio::io::copy(&mut cr, &mut bw).await;
        let _ = bw.shutdown().await;
    };
    let b2c = async {
        let _ = tokio::io::copy(&mut br, &mut cw).await;
        let _ = cw.shutdown().await;
    };
    tokio::join!(c2b, b2c);
}

/// Spawn a loopback SOCKS5 proxy that accepts one connection, completes the
/// `NO_AUTH` method negotiation + CONNECT, then bridges to `backend_addr`.
async fn spawn_socks5_proxy(backend_addr: std::net::SocketAddr) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("proxy accept");
        // Method negotiation: VER, NMETHODS, METHODS…
        let mut head = [0u8; 2];
        sock.read_exact(&mut head).await.unwrap();
        let nmethods = head[1] as usize;
        let mut methods = vec![0u8; nmethods];
        sock.read_exact(&mut methods).await.unwrap();
        // Select NO_AUTH.
        sock.write_all(&[0x05, 0x00]).await.unwrap();
        // CONNECT request: VER, CMD, RSV, ATYP, ADDR, PORT.
        let mut req = [0u8; 4];
        sock.read_exact(&mut req).await.unwrap();
        match req[3] {
            0x01 => {
                let mut a = [0u8; 4 + 2];
                sock.read_exact(&mut a).await.unwrap();
            }
            0x03 => {
                let mut len = [0u8; 1];
                sock.read_exact(&mut len).await.unwrap();
                let mut a = vec![0u8; len[0] as usize + 2];
                sock.read_exact(&mut a).await.unwrap();
            }
            0x04 => {
                let mut a = [0u8; 16 + 2];
                sock.read_exact(&mut a).await.unwrap();
            }
            _ => panic!("unexpected ATYP"),
        }
        // Success reply with a dummy IPv4 BND.
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let backend = TcpStream::connect(backend_addr).await.expect("dial inner");
        pump(sock, backend).await;
    });
    addr
}

/// Spawn a loopback HTTP CONNECT proxy that accepts one connection, reads the
/// request head up to `\r\n\r\n`, replies `200`, then bridges to `backend_addr`.
async fn spawn_http_proxy(backend_addr: std::net::SocketAddr) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("proxy accept");
        let mut buf = Vec::new();
        let mut one = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            sock.read_exact(&mut one).await.unwrap();
            buf.push(one[0]);
        }
        sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        let backend = TcpStream::connect(backend_addr).await.expect("dial inner");
        pump(sock, backend).await;
    });
    addr
}

async fn run_proxy_dispatch(kind: HopKind) {
    let a = RusshTestServer::new()
        .with_password("u", "pw")
        .with_algorithm_pinning(wincng_libssh2_compatible_preferred())
        .start()
        .await
        .expect("start outer server A");
    let b = RusshTestServer::new()
        .with_password("u", "pw")
        .with_algorithm_pinning(wincng_libssh2_compatible_preferred())
        .start()
        .await
        .expect("start inner server B");

    // The proxy tunnels to inner B.
    let proxy_addr = match kind {
        HopKind::Socks5 => spawn_socks5_proxy(b.addr).await,
        HopKind::HttpConnect => spawn_http_proxy(b.addr).await,
        HopKind::Ssh => panic!("test is for proxy kinds only"),
    };

    let cfg = Arc::new(client::Config {
        preferred: wincng_libssh2_compatible_preferred(),
        ..Default::default()
    });

    // Outer hop: real SSH session to A.
    let mut handle_a = client::connect(cfg.clone(), a.addr, PassThroughHandler)
        .await
        .expect("connect A");
    assert!(handle_a
        .authenticate_password("u", "pw")
        .await
        .expect("auth A")
        .success());
    let shared_a = Arc::new(AsyncMutex::new(handle_a));

    // Proxy hop: A opens direct-tcpip to the loopback proxy, the proxy runs
    // the CONNECT handshake to B, then the SSH handshake runs over the tunnel.
    let mut handle_b = open_chained_session_with_kind(
        Arc::clone(&shared_a),
        &proxy_addr.ip().to_string(),
        proxy_addr.port(),
        &b.addr.ip().to_string(),
        b.addr.port(),
        kind,
        None,
        cfg.clone(),
        PassThroughHandler,
    )
    .await
    .expect("chained proxy session A -> proxy -> B");

    assert!(
        handle_b
            .authenticate_password("u", "pw")
            .await
            .expect("auth B over proxy tunnel")
            .success(),
        "inner server B must accept auth through the {kind:?} proxy tunnel"
    );

    let _channel = handle_b
        .channel_open_session()
        .await
        .expect("session channel on inner hop B");

    // A hosted the direct-tcpip channel that reached the proxy.
    assert!(
        a.channel_opens_direct_tcpip() >= 1,
        "outer A should host the direct-tcpip channel to the proxy"
    );
    assert!(b.connection_count() >= 1, "inner B had no connections");

    drop(handle_b);
    drop(shared_a);
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn socks5_hop_dispatches_through_with_kind_path() {
    run_proxy_dispatch(HopKind::Socks5).await;
}

#[tokio::test]
async fn http_connect_hop_dispatches_through_with_kind_path() {
    run_proxy_dispatch(HopKind::HttpConnect).await;
}
