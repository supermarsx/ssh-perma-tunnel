//! e2e: keepalive plumbing.
//!
//! ## Variants
//!
//! * **Mock variant (`keepalive_invocations_recorded_on_session`)** — runs in
//!   CI. Drives `TunnelSession::keepalive()` directly through the
//!   `SharedLogProtocol` wiring and asserts each call is recorded. The
//!   supervisor does **not** itself drive `keepalive()` (that responsibility
//!   sits in the protocol/connection layer); this test pins the session-level
//!   contract instead.
//! * **Real-libssh2 variant (`keepalive_after_5s_real_libssh2`)** —
//!   `#[ignore]`'d. Even if the russh ↔ libssh2 KEX bug is fixed,
//!   `RunningRusshServer::keepalive_packet_count()` is a **best-effort proxy**
//!   over channel-data callbacks (russh 0.46's `Handler` trait does not
//!   surface the `keepalive@openssh.com` global request — see the helper's
//!   docstring). A literal SSH-transport keepalive count would require either
//!   a russh patch or a wire-level proxy, both out of scope for t2-e4.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::Duration;

use spt_auth::AuthConfig;
use spt_core::Result;
use spt_e2e_tests::SharedLogProtocol;
use spt_forward::testing::SessionCall;
use spt_protocol::{Endpoint, TunnelProtocol, TunnelSession};

#[tokio::test]
async fn keepalive_invocations_recorded_on_session() {
    let proto: Arc<SharedLogProtocol> = Arc::new(SharedLogProtocol::new());
    let log = Arc::clone(&proto.shared);

    // Drive a session directly off the protocol — no orchestrator needed for
    // this contract test (the supervisor doesn't currently invoke keepalive).
    let endpoint = Endpoint::new("127.0.0.1", 22);
    let auth = AuthConfig::new("u", vec![]);
    let mut session: Box<dyn TunnelSession> = (proto.as_ref() as &dyn TunnelProtocol)
        .connect(&endpoint, &auth)
        .await
        .expect("connect");

    // Issue four keepalive ticks.
    for _ in 0..4 {
        let _: Result<()> = session.keepalive().await;
        // Yield so the lock release in SharedLogSession is observable; the
        // mock implementation is synchronous so this is precautionary.
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    session.close().await.expect("close");

    let calls = log.lock().clone();
    let n_keepalives = calls
        .iter()
        .filter(|c| matches!(c, SessionCall::Keepalive))
        .count();
    assert!(
        n_keepalives >= 4,
        "expected >=4 Keepalive entries; got {n_keepalives}; full log = {calls:?}"
    );
    assert!(
        calls.iter().any(|c| matches!(c, SessionCall::Close)),
        "expected Close entry; full log = {calls:?}"
    );
}

/// Real-libssh2 variant. **Single-blocked** as of t3-e8: the russh ↔ libssh2
/// KEX bug is worked around at the test-helper layer (see
/// `spt_ssh2::testing::wincng_libssh2_compatible_preferred`), so a libssh2 ↔
/// russh handshake now completes — but russh 0.46's `Handler` trait still
/// does **not** surface the `keepalive@openssh.com` global request. russh's
/// dispatcher swallows it (`server/encrypted.rs:986` default-arm
/// REQUEST_FAILURE) before user code runs.
/// `RunningRusshServer::keepalive_packet_count()` therefore proxies
/// channel-data callbacks rather than literal keepalives. A faithful
/// keepalive-count test would need either an upstream russh patch exposing
/// the global request, or a TCP-layer wire-proxy that recognises the
/// `SSH_MSG_GLOBAL_REQUEST keepalive@openssh.com` packet.
#[tokio::test]
#[ignore = "blocked-by: russh 0.46 Handler trait does not expose \
keepalive@openssh.com global request (russh-0.46 server/encrypted.rs default-arm \
REQUEST_FAILURE before user-code dispatch). Needs upstream russh patch exposing a \
`keepalive_request` hook on the Handler trait. The russh<->libssh2 KEX side of the \
blockage is RESOLVED in t3-e8 via spt_ssh2::testing::wincng_libssh2_compatible_preferred \
(tracking russh#245: https://github.com/warp-tech/russh/issues/245)."]
async fn keepalive_after_5s_real_libssh2() {
    panic!("real-libssh2 variant intentionally unwritten; see #[ignore] reason");
}
