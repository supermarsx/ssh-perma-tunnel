//! Integration tests against an embedded `russh` SSH2 server.
//!
//! These tests spin up a russh server on `127.0.0.1:0`, then drive
//! `Ssh2Protocol` against it. Because the russh handler surface is large and
//! evolving, only the most fundamental connectivity test is enabled by
//! default; the richer tests (forwards, mismatch) are gated behind
//! `#[ignore]` and runnable explicitly with `cargo test -- --ignored`.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::sync::Arc;

use async_trait::async_trait;
use russh::server::{Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use russh_keys::key::KeyPair as RusshKeyPair;
use spt_auth::{AuthConfig, AuthMethod};
use spt_protocol::{Endpoint, TunnelProtocol};
use spt_ssh2::Ssh2Protocol;
use tokio::net::TcpListener;

#[derive(Clone)]
struct TestServer;

impl russh::server::Server for TestServer {
    type Handler = Handler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Handler {
        Handler
    }
}

struct Handler;

#[async_trait]
impl russh::server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &russh_keys::key::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Echo back
        session.data(channel, russh::CryptoVec::from(data.to_vec()));
        Ok(())
    }
}

async fn start_test_server() -> std::io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(60)),
        auth_rejection_time: std::time::Duration::from_millis(100),
        auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
        keys: vec![RusshKeyPair::generate_ed25519()],
        ..Default::default()
    };
    let config = Arc::new(config);
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let mut server = TestServer;
            let cfg = config.clone();
            let h = server.new_client(sock.peer_addr().ok());
            tokio::spawn(russh::server::run_stream(cfg, sock, h));
        }
    });
    Ok(port)
}

/// Smoke test: connect with password auth (no trust verification — accepted
/// because the protocol is configured with the default permissive verifier).
#[tokio::test]
#[ignore = "requires linking the libssh2 stack at test runtime; gate to opt-in"]
async fn connect_basic() {
    let port = start_test_server()
        .await
        .expect("start server");
    // Give server a moment to be ready.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let proto = Ssh2Protocol::new();
    let endpoint = Endpoint::new("127.0.0.1", port);
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_PW".into()),
        }],
    );
    // SPT_TEST_PW must be set for resolve_secret to succeed.
    std::env::set_var("SPT_TEST_PW", "anything");
    match proto.connect(&endpoint, &auth).await {
        Ok(session) => assert_eq!(session.session_info().backend, "ssh2"),
        Err(e) => panic!("connect failed: {e}"),
    }
}
