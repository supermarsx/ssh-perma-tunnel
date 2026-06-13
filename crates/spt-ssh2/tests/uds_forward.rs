//! Integration tests for `spt_ssh2::uds_forward` (t6-e2).
//!
//! ## Scope and constraints
//!
//! These tests run against an embedded `russh` server (built locally — we
//! cannot extend `crates/spt-ssh2/src/testing.rs::TestHandler` because
//! `testing.rs` is outside this executor's lock scope).
//!
//! Important constraint of russh 0.61: the server's
//! [`russh::server::Handler`] trait has hooks for `streamlocal_forward`
//! and `cancel_streamlocal_forward`, but **no `ChannelType` variant for
//! inbound `direct-streamlocal@openssh.com` channel opens**. The server
//! parses such opens as `ChannelType::Unknown { typ }` and immediately
//! sends `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`. As a consequence, the
//! plan's "`local_uds` positive russh roundtrip (mock russh server)" is
//! infeasible with the available server library — we test the
//! client-side behaviour against the rejection (which is itself the
//! correct production behaviour against a non-streamlocal-capable
//! server) and rely on the byte-exact `encode_direct_streamlocal_body`
//! unit test (in `uds_forward.rs`) plus the streamlocal-forward
//! roundtrip below as the conformance witness. See `t6-e2.md` log.

#![cfg(feature = "testing")]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::server::{self, Auth, Handler as ServerHandler};
use russh::{Channel, Disconnect, MethodKind, MethodSet, Preferred};
use spt_core::Error;
use spt_ssh2::uds_forward::{
    encode_direct_streamlocal_body, open_local_uds, validate_socket_path,
    windows_local_uds_unsupported, RemoteUdsForward, SharedRusshHandle,
};
use tokio::sync::Mutex as AsyncMutex;

// ---------------------------------------------------------------------------
// Local russh server fixture with streamlocal-forward hooks
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Counters {
    streamlocal_forward_requests: AtomicUsize,
    cancel_streamlocal_requests: AtomicUsize,
}

#[derive(Clone)]
struct UdsServerHandler {
    counters: Arc<Counters>,
    /// Paths the server accepts for streamlocal-forward. Empty means accept all.
    accept_paths: Arc<parking_lot::Mutex<Vec<String>>>,
}

impl ServerHandler for UdsServerHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> std::result::Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> std::result::Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        _session: &mut server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }

    async fn streamlocal_forward(
        &mut self,
        socket_path: &str,
        _session: &mut server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        self.counters
            .streamlocal_forward_requests
            .fetch_add(1, Ordering::SeqCst);
        // For the "cancel-streamlocal-forward: clean cancel + reuse" test
        // we accept the same path multiple times so re-registration works.
        let accept = {
            let g = self.accept_paths.lock();
            g.is_empty() || g.iter().any(|p| p == socket_path)
        };
        Ok(accept)
    }

    async fn cancel_streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        self.counters
            .cancel_streamlocal_requests
            .fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}

#[derive(Clone)]
struct ClientHandlerAcceptAll;

impl client::Handler for ClientHandlerAcceptAll {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A small, libssh2-WinCNG-friendly algorithm pinning so the test runs
/// the same on Windows CI. Mirrors `wincng_libssh2_compatible_preferred`
/// in `spt_ssh2::testing` but tailored to RSA-2048 host keys.
fn pinning() -> Preferred {
    use russh::keys::ssh_key::{Algorithm, HashAlg};
    use std::borrow::Cow;
    Preferred {
        kex: Cow::Owned(vec![russh::kex::DH_G14_SHA256, russh::kex::DH_G16_SHA512]),
        key: Cow::Owned(vec![
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        ]),
        cipher: Cow::Owned(vec![russh::cipher::AES_256_CTR]),
        mac: Cow::Owned(vec![russh::mac::HMAC_SHA256]),
        compression: Preferred::DEFAULT.compression,
    }
}

/// Generate an ephemeral RSA host key for the server.
fn ephemeral_host_key() -> russh::keys::ssh_key::PrivateKey {
    use russh::keys::ssh_key::{Algorithm, PrivateKey};
    PrivateKey::random(&mut rand010::rng(), Algorithm::Rsa { hash: None }).expect("rsa keypair")
}

struct RunningServer {
    addr: std::net::SocketAddr,
    counters: Arc<Counters>,
    /// Kept alive only for shared ownership with handler clones; tests
    /// don't currently mutate the accepted-paths whitelist.
    #[allow(dead_code)]
    accept_paths: Arc<parking_lot::Mutex<Vec<String>>>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
}

async fn spawn_server() -> RunningServer {
    let counters = Arc::new(Counters::default());
    let accept_paths = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let cfg = Arc::new(server::Config {
        inactivity_timeout: Some(Duration::from_secs(15)),
        auth_rejection_time: Duration::from_millis(50),
        auth_rejection_time_initial: Some(Duration::from_millis(50)),
        keys: vec![ephemeral_host_key()],
        preferred: pinning(),
        methods: MethodSet::from(&[MethodKind::Password, MethodKind::PublicKey][..]),
        ..Default::default()
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let counters_for_task = Arc::clone(&counters);
    let accept_paths_for_task = Arc::clone(&accept_paths);

    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                incoming = listener.accept() => {
                    let Ok((sock, peer)) = incoming else { break; };
                    let h = UdsServerHandler {
                        counters: Arc::clone(&counters_for_task),
                        accept_paths: Arc::clone(&accept_paths_for_task),
                    };
                    let _ = peer;
                    let cfg = Arc::clone(&cfg);
                    tokio::spawn(async move {
                        let _ = server::run_stream(cfg, sock, h).await;
                    });
                }
            }
        }
    });

    RunningServer {
        addr,
        counters,
        accept_paths,
        shutdown: shutdown_tx,
        join,
    }
}

impl RunningServer {
    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.join.await;
    }
}

async fn connect_client(addr: std::net::SocketAddr) -> SharedRusshHandle<ClientHandlerAcceptAll> {
    let cfg = Arc::new(client::Config {
        preferred: pinning(),
        ..Default::default()
    });
    let mut handle = client::connect(cfg, ("127.0.0.1", addr.port()), ClientHandlerAcceptAll)
        .await
        .expect("client connect");
    let ok = handle
        .authenticate_password("tester", "pw")
        .await
        .expect("auth");
    assert!(ok.success(), "password auth accepted");
    Arc::new(AsyncMutex::new(handle))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `remote_uds` positive russh roundtrip: client calls
/// `streamlocal_forward`, server handler returns `Ok(true)`, the
/// `RemoteUdsForward` is constructed.
#[tokio::test]
async fn remote_uds_positive_russh_roundtrip() {
    let server = spawn_server().await;
    let handle = connect_client(server.addr).await;

    let fwd = RemoteUdsForward::request(Arc::clone(&handle), "/tmp/spt-test-remote.sock")
        .await
        .expect("streamlocal-forward accepted");
    assert_eq!(fwd.socket_path(), "/tmp/spt-test-remote.sock");
    assert_eq!(
        server
            .counters
            .streamlocal_forward_requests
            .load(Ordering::SeqCst),
        1
    );

    // Explicit cancel so Drop is a no-op and we observe a deterministic
    // count.
    fwd.cancel().await.expect("clean cancel");
    assert_eq!(
        server
            .counters
            .cancel_streamlocal_requests
            .load(Ordering::SeqCst),
        1
    );

    server.shutdown().await;
}

/// `cancel-streamlocal-forward`: an explicit cancel allows the same
/// path to be re-requested cleanly.
#[tokio::test]
async fn cancel_streamlocal_forward_clean_cancel_and_reuse() {
    let server = spawn_server().await;
    let handle = connect_client(server.addr).await;

    let first = RemoteUdsForward::request(Arc::clone(&handle), "/tmp/spt-test-reuse.sock")
        .await
        .expect("first registration");
    first.cancel().await.expect("explicit cancel");
    let cancel_count_after_first = server
        .counters
        .cancel_streamlocal_requests
        .load(Ordering::SeqCst);
    assert_eq!(cancel_count_after_first, 1);

    let second = re_request_uds(&server, &handle).await;
    second.cancel().await.expect("second cancel");
    assert_eq!(
        server
            .counters
            .streamlocal_forward_requests
            .load(Ordering::SeqCst),
        2
    );

    server.shutdown().await;
}

async fn re_request_uds(
    server: &RunningServer,
    handle: &SharedRusshHandle<ClientHandlerAcceptAll>,
) -> RemoteUdsForward<ClientHandlerAcceptAll> {
    let _ = server;
    RemoteUdsForward::request(Arc::clone(handle), "/tmp/spt-test-reuse.sock")
        .await
        .expect("second registration after cancel")
}

/// Drop on an active `RemoteUdsForward` triggers a
/// `cancel-streamlocal-forward` (best-effort, spawned on the runtime).
#[tokio::test]
async fn drop_sends_cancel_streamlocal_forward() {
    let server = spawn_server().await;
    let handle = connect_client(server.addr).await;

    let path = "/tmp/spt-test-drop.sock";
    {
        let fwd = RemoteUdsForward::request(Arc::clone(&handle), path)
            .await
            .expect("registration");
        let _ = fwd.socket_path();
        // Drop runs at the end of this block.
    }

    // The cancel is spawned on the runtime — give it a moment to land.
    for _ in 0..50 {
        if server
            .counters
            .cancel_streamlocal_requests
            .load(Ordering::SeqCst)
            >= 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        server
            .counters
            .cancel_streamlocal_requests
            .load(Ordering::SeqCst)
            >= 1,
        "Drop should have triggered cancel-streamlocal-forward",
    );

    server.shutdown().await;
}

/// Concurrent registration of 10 distinct UDS paths all succeed.
///
/// **Note on naming**: the plan calls this "concurrent open: 10 parallel
/// local_uds succeed". As documented in the module header, russh 0.46's
/// server has no inbound `direct-streamlocal` channel-type, so we
/// exercise the closest analogue: 10 concurrent `streamlocal-forward`
/// global requests (remote_uds direction) which the server fully
/// supports. This still validates the parallel-open path through
/// the shared `client::Handle` mutex.
#[tokio::test]
async fn concurrent_open_ten_parallel_succeed() {
    let server = spawn_server().await;
    let handle = connect_client(server.addr).await;

    let mut tasks = Vec::with_capacity(10);
    for i in 0..10 {
        let h = Arc::clone(&handle);
        tasks.push(tokio::spawn(async move {
            RemoteUdsForward::request(h, &format!("/tmp/spt-test-parallel-{i}.sock")).await
        }));
    }

    let mut owned = Vec::with_capacity(10);
    for t in tasks {
        let fwd = t.await.expect("task join").expect("registration");
        owned.push(fwd);
    }
    assert_eq!(
        server
            .counters
            .streamlocal_forward_requests
            .load(Ordering::SeqCst),
        10
    );

    // Cancel them all explicitly so the server sees a deterministic
    // sequence before shutdown.
    for f in owned {
        f.cancel().await.expect("cancel");
    }
    assert_eq!(
        server
            .counters
            .cancel_streamlocal_requests
            .load(Ordering::SeqCst),
        10
    );

    server.shutdown().await;
}

/// Local-UDS direction: russh 0.46 server rejects inbound
/// `direct-streamlocal@openssh.com` channels as
/// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`. We assert the rejection
/// surfaces as a clean `Error::RuntimeFailure` on the client.
///
/// This is the documented pivot from "local_uds positive russh
/// roundtrip" — see module header.
#[tokio::test]
async fn local_uds_against_russh_server_returns_clean_error() {
    let server = spawn_server().await;
    let handle = connect_client(server.addr).await;

    let res = open_local_uds(&handle, "/run/never-listens.sock").await;
    match res {
        Err(Error::RuntimeFailure(msg)) => {
            assert!(
                msg.contains("direct-streamlocal"),
                "expected direct-streamlocal context, got: {msg}"
            );
        }
        other => panic!("expected RuntimeFailure, got {other:?}"),
    }

    server.shutdown().await;
}

/// Schema deserialiser test stub — the real test lives in
/// `spt-config::schema::uds_kind_tests` (where the `Forward` type
/// itself lives). We re-check the byte-exact wire body here as the
/// PROTOCOL.txt §2.4 conformance witness in the integration suite.
#[test]
fn channel_open_body_byte_exact_protocol_txt_2_4() {
    let body = encode_direct_streamlocal_body("/run/foo.sock");
    let expected: [u8; 25] = [
        0x00, 0x00, 0x00, 0x0d, // length 13
        0x2f, 0x72, 0x75, 0x6e, 0x2f, 0x66, 0x6f, 0x6f, 0x2e, 0x73, 0x6f, 0x63, 0x6b, 0x00, 0x00,
        0x00, 0x00, // reserved string
        0x00, 0x00, 0x00, 0x00, // reserved uint32
    ];
    assert_eq!(body, expected);
}

/// Malformed `remote_socket_path` (relative + interior NUL byte) is
/// rejected by [`validate_socket_path`] without touching the wire.
#[tokio::test]
async fn malformed_remote_socket_path_rejected_without_wire_attempt() {
    // No server needed — validation is wire-independent.
    let res = validate_socket_path("relative.sock");
    assert!(matches!(res, Err(Error::InvalidConfig(_))));

    match validate_socket_path("/run/has\0nul.sock") {
        Err(Error::InvalidConfig(ref s)) => assert!(s.contains("NUL")),
        other => panic!("expected InvalidConfig(NUL), got {other:?}"),
    }
}

/// `windows_local_uds_unsupported` returns `UnsupportedPlatform` with
/// the Windows-specific diagnostic.
#[test]
fn windows_local_uds_returns_unsupported_platform() {
    match windows_local_uds_unsupported() {
        Error::UnsupportedPlatform(msg) => {
            assert!(msg.contains("local_uds"), "msg: {msg}");
            assert!(
                msg.contains("Unix") || msg.contains("Windows"),
                "msg: {msg}"
            );
        }
        other => panic!("expected UnsupportedPlatform, got {other:?}"),
    }
}

/// Audit hook fires on open + close (cross-module sanity — the unit
/// tests in `uds_forward.rs` cover the primary case; this test
/// exercises the same machinery from the integration suite to catch
/// any feature-gating drift).
#[tokio::test]
async fn audit_hook_fires_on_open_and_close_through_remote_request() {
    use spt_core::audit::{register_audit_sink, AuditEvent as AE, AuditSink};
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Recorder {
        events: Mutex<Vec<AE>>,
    }
    impl AuditSink for Recorder {
        fn record(&self, ev: AE) {
            self.events.lock().unwrap().push(ev);
        }
    }

    let rec = Arc::new(Recorder::default());
    register_audit_sink(rec.clone());

    let server = spawn_server().await;
    let handle = connect_client(server.addr).await;
    let fwd = RemoteUdsForward::request(Arc::clone(&handle), "/tmp/spt-test-audit.sock")
        .await
        .expect("registration");
    fwd.cancel().await.expect("cancel");

    let events = rec.events.lock().unwrap().clone();
    let opens: Vec<_> = events
        .iter()
        .filter(|e| e.kind == "audit.forward.uds.open")
        .collect();
    let closes: Vec<_> = events
        .iter()
        .filter(|e| e.kind == "audit.forward.uds.close")
        .collect();
    assert!(!opens.is_empty(), "expected at least one open event");
    assert!(!closes.is_empty(), "expected at least one close event");

    // Tame the future Drop noise: send a disconnect.
    {
        let g = handle.lock().await;
        let _ = g
            .disconnect(Disconnect::ByApplication, "test done", "")
            .await;
    }
    server.shutdown().await;
}
