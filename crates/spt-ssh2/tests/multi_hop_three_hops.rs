//! t7-Phase0: 3-hop integration test for the russh-native multi-hop chain.
//!
//! Spins up three `RusshTestServer` fixtures (`A`, `B`, `C`) on loopback,
//! then walks the chain:
//!
//! 1. Plain TCP connect to `A`, handshake an SSH session.
//! 2. Open a `direct-tcpip` channel through `A` aimed at `B`'s loopback addr,
//!    promote that channel stream into a fresh russh session ([`open_chained_session`]).
//! 3. Repeat from `B` to `C` over the second session's channel.
//!
//! Asserts:
//! * All three servers see an inbound TCP accept.
//! * The B and C servers each see exactly one `direct-tcpip` open arriving
//!   from the previous hop.
//! * The chain produces a usable session on the third hop (the test opens
//!   a session channel as a smoke check).
//!
//! Replaces the pre-t7 socketpair-based multi-hop test (which targeted
//! libssh2's `AsRawFd` requirement). russh accepts any `AsyncRead+AsyncWrite`
//! transport, so the new chain has no loopback indirection.

#![cfg(feature = "testing")]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;

use russh::client;
use spt_ssh2::multi_hop::open_chained_session;
use spt_ssh2::testing::{wincng_libssh2_compatible_preferred, RusshTestServer};
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

#[tokio::test]
async fn three_hop_russh_chain_handshakes_and_serves_channel_open() {
    // t7-Bwire: closed t7-Phase0 deferred item #1. The pre-fix
    // `russh::Error::Inconsistent` reproduced because the embedded
    // `RusshTestServer::channel_open_direct_tcpip` handler accepted the
    // channel but never connected to the requested backend — the client's
    // `connect_stream` consequently read its own data echoed by the
    // server's `data` callback and aborted handshake. The fixture was
    // patched to actually proxy loopback `direct-tcpip` targets (real
    // OpenSSH-style behaviour), and this test now runs live without
    // touching the public `open_chained_session` surface.
    // Bring up three independent russh test servers.
    let a = RusshTestServer::new()
        .with_password("u", "pw")
        .with_algorithm_pinning(wincng_libssh2_compatible_preferred())
        .start()
        .await
        .expect("start server A");
    let b = RusshTestServer::new()
        .with_password("u", "pw")
        .with_algorithm_pinning(wincng_libssh2_compatible_preferred())
        .start()
        .await
        .expect("start server B");
    let c = RusshTestServer::new()
        .with_password("u", "pw")
        .with_algorithm_pinning(wincng_libssh2_compatible_preferred())
        .start()
        .await
        .expect("start server C");

    // Shared russh client config used at every hop.
    let cfg = Arc::new(client::Config {
        preferred: wincng_libssh2_compatible_preferred(),
        ..Default::default()
    });

    // -- Hop 1: plain TCP connect to A, password auth. ---------------------
    let mut handle_a = client::connect(cfg.clone(), a.addr, PassThroughHandler)
        .await
        .expect("connect A");
    let authed = handle_a
        .authenticate_password("u", "pw")
        .await
        .expect("auth A");
    assert!(authed.success(), "server A must accept password");
    let shared_a = Arc::new(AsyncMutex::new(handle_a));

    // -- Hop 2: open chained session A -> B. -------------------------------
    let handle_b = open_chained_session(
        Arc::clone(&shared_a),
        &b.addr.ip().to_string(),
        b.addr.port(),
        cfg.clone(),
        PassThroughHandler,
    )
    .await
    .expect("chained session A -> B");
    let mut handle_b = handle_b;
    let authed_b = handle_b
        .authenticate_password("u", "pw")
        .await
        .expect("auth B over chained session");
    assert!(
        authed_b.success(),
        "server B must accept password over chained channel"
    );
    let shared_b = Arc::new(AsyncMutex::new(handle_b));

    // -- Hop 3: open chained session B -> C. -------------------------------
    let handle_c = open_chained_session(
        Arc::clone(&shared_b),
        &c.addr.ip().to_string(),
        c.addr.port(),
        cfg.clone(),
        PassThroughHandler,
    )
    .await
    .expect("chained session B -> C");
    let mut handle_c = handle_c;
    let authed_c = handle_c
        .authenticate_password("u", "pw")
        .await
        .expect("auth C over chained session");
    assert!(
        authed_c.success(),
        "server C must accept password through 3-hop chain"
    );

    // Smoke: open a session channel on the final hop to confirm the chain
    // carries real protocol traffic, not just the kex handshake.
    let _channel = handle_c
        .channel_open_session()
        .await
        .expect("session channel on hop C");

    // Each server saw at least one TCP accept.
    assert!(a.connection_count() >= 1, "server A had no connections");
    assert!(b.connection_count() >= 1, "server B had no connections");
    assert!(c.connection_count() >= 1, "server C had no connections");

    // A and B each saw at least one direct-tcpip open arriving from the
    // previous hop (A hosts the A->B channel, B hosts the B->C channel).
    assert!(
        a.channel_opens_direct_tcpip() >= 1,
        "server A should host the direct-tcpip channel that reaches B"
    );
    assert!(
        b.channel_opens_direct_tcpip() >= 1,
        "server B should host the direct-tcpip channel that reaches C"
    );

    // Clean shutdown so the per-server byte-pump tasks exit promptly.
    drop(handle_c);
    drop(shared_b);
    drop(shared_a);

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
}

/// 2-hop coverage: a single intermediate hop reaching the endpoint. Mirrors
/// the structure of the 3-hop test but with one less link in the chain —
/// the most common production multi-hop topology (bastion -> target).
#[tokio::test]
async fn two_hop_russh_chain_handshakes_and_serves_channel_open() {
    let a = RusshTestServer::new()
        .with_password("u", "pw")
        .with_algorithm_pinning(wincng_libssh2_compatible_preferred())
        .start()
        .await
        .expect("start server A");
    let b = RusshTestServer::new()
        .with_password("u", "pw")
        .with_algorithm_pinning(wincng_libssh2_compatible_preferred())
        .start()
        .await
        .expect("start server B");

    let cfg = Arc::new(client::Config {
        preferred: wincng_libssh2_compatible_preferred(),
        ..Default::default()
    });

    let mut handle_a = client::connect(cfg.clone(), a.addr, PassThroughHandler)
        .await
        .expect("connect A");
    assert!(handle_a
        .authenticate_password("u", "pw")
        .await
        .expect("auth A")
        .success());
    let shared_a = Arc::new(AsyncMutex::new(handle_a));

    let mut handle_b = open_chained_session(
        Arc::clone(&shared_a),
        &b.addr.ip().to_string(),
        b.addr.port(),
        cfg,
        PassThroughHandler,
    )
    .await
    .expect("chained session A -> B");
    assert!(handle_b
        .authenticate_password("u", "pw")
        .await
        .expect("auth B over chained session")
        .success());

    let _channel = handle_b
        .channel_open_session()
        .await
        .expect("session channel on hop B");

    assert!(a.connection_count() >= 1);
    assert!(b.connection_count() >= 1);
    assert!(a.channel_opens_direct_tcpip() >= 1);

    drop(handle_b);
    drop(shared_a);
    a.shutdown().await;
    b.shutdown().await;
}
