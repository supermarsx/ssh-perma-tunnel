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

/// Real-libssh2 variant. **Doubly blocked**: (1) the russh ↔ libssh2 KEX bug
/// (see `crates/spt-ssh2/tests/russh_basic.rs`) prevents establishing a
/// session at all; (2) even once that's fixed, russh 0.46's `Handler` trait
/// does **not** surface the `keepalive@openssh.com` global request — russh's
/// dispatcher swallows it before user code runs.
/// `RunningRusshServer::keepalive_packet_count()` therefore proxies channel-data
/// callbacks rather than literal keepalives. A faithful test would need a
/// russh patch or a wire-level proxy.
#[tokio::test]
#[ignore = "doubly blocked: russh<->libssh2 KEX bug AND russh 0.46 does not expose \
keepalive@openssh.com to Handler. See crates/spt-ssh2/src/testing.rs \
RunningRusshServer::keepalive_packet_count for the proxy caveat."]
async fn keepalive_after_5s_real_libssh2() {
    panic!("real-libssh2 variant intentionally unwritten; see #[ignore] reason");
}
