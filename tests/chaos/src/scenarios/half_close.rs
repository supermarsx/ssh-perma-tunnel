//! Scenario 9 — **`half_close`**.
//!
//! Server FINs the read-half only. The chaos-proxy doesn't expose
//! half-close as a behaviour, so this scenario fakes it with a custom
//! upstream listener that, *per accepted connection*, sends a single
//! byte, then leaves the socket idle (no reads, no further writes).
//!
//! After t8-FixSup, the supervisor's `run_active` periodically drives
//! `TunnelSession::keepalive`. The probe-based test session opens a
//! *fresh* TCP connection per keepalive, and each fresh connection
//! succeeds against this server (it accepts new connections and
//! writes "k"). That means the half-close pattern does **not**
//! surface as a reconnect under the stateless-probe protocol — the
//! supervisor sits happily in `run_active` issuing successful
//! keepalives. With a real long-lived SSH session (which would notice
//! the silent peer via TCP-level read errors or keepalive read
//! timeouts), the supervisor would reconnect.
//!
//! This scenario therefore asserts the achievable property: the
//! supervisor stays up, fires the initial success callback, and does
//! NOT spam reconnects when the peer half-closes but keeps writing
//! per-connection. Detecting silent-write half-close requires
//! transport-level liveness in the protocol implementation, not
//! generic session-health polling.

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, CountingObserver, ObserverGuard, TcpProbeProtocol,
};
use spt_auth::AuthConfig;
use spt_protocol::Endpoint;
use spt_supervisor::{ProfileSupervisor, ProfileSupervisorConfig};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[tokio::test]
async fn half_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let _server = tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let _ = sock.write_all(b"k").await;
                // Half-close: stop reading by ignoring. (A real
                // shutdown(SHUT_RD) isn't portable across tokio
                // TcpStream halves; the test approximates the
                // observable behaviour: a peer that wrote then went
                // silent.)
                std::future::pending::<()>().await;
            });
        }
    });

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let proto = Arc::new(TcpProbeProtocol::new(addr));
    let mut cfg = ProfileSupervisorConfig::default();
    cfg.backoff = fast_backoff(0);
    cfg.keepalive_interval = Duration::from_millis(100);
    let sup = ProfileSupervisor::spawn(
        "half-close",
        proto,
        AuthConfig::new("u", vec![]),
        vec![Endpoint::new(addr.ip().to_string(), addr.port())],
        vec![],
        cfg,
    );

    tokio::time::sleep(Duration::from_secs(1)).await;

    // With a fresh-TCP-per-keepalive probe protocol, the
    // half-closing server still accepts new connections cleanly, so
    // the supervisor's keepalive loop sees only successes. We assert:
    //   * the first session came up at least once,
    //   * the supervisor did NOT spuriously reconnect (no attempts).
    let successes = obs.successes.lock().len();
    assert!(successes >= 1, "expected ≥1 initial session success");
    let attempts = obs.attempts_snapshot();
    assert!(
        attempts.is_empty(),
        "stateless probe should not see half-close as a session death; got {} attempts",
        attempts.len()
    );

    sup.stop().await;
}
