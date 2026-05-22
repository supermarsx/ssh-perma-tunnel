//! Scenario 8 — **`slow_loris_connect`**.
//!
//! Upstream that accepts the TCP connection but never produces handshake
//! bytes — a textbook slow-loris. Achieved without `spt-chaos-proxy` at
//! all: the per-scenario echo server is replaced with a "silent
//! listener" that accepts and idles.
//!
//! With the `TcpProbeProtocol`'s default 500ms read timeout, every
//! probe times out → backoff fires.  Assertion: ≥2 reconnect attempts
//! within the time budget.
//!
//! Status: **`#[ignore]`** by default — the wall-clock cost is ~2 s per
//! retry under the timeout we picked; we don't want this gating every
//! PR.

use std::time::Duration;

use std::sync::Arc;
use tokio::net::TcpListener;

use crate::scenarios::common::{
    fast_backoff, CountingObserver, ObserverGuard, TcpProbeProtocol,
};
use spt_auth::AuthConfig;
use spt_protocol::Endpoint;
use spt_supervisor::{ProfileSupervisor, ProfileSupervisorConfig};

#[tokio::test]
#[ignore = "slow — runs under SPT_CHAOS_FULL=1"]
async fn slow_loris_connect() {
    // Listener that accepts and idles forever.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let _idle_task = tokio::spawn(async move {
        loop {
            let (sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            // Hold the socket forever — never read.
            tokio::spawn(async move {
                let _keep = sock;
                std::future::pending::<()>().await;
            });
        }
    });

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let proto = Arc::new(TcpProbeProtocol::new(addr).with_timeout(Duration::from_millis(150)));
    let mut cfg = ProfileSupervisorConfig::default();
    cfg.backoff = fast_backoff(5);

    let sup = ProfileSupervisor::spawn(
        "slow-loris",
        proto,
        AuthConfig::new("u", vec![]),
        vec![Endpoint::new(addr.ip().to_string(), addr.port())],
        vec![],
        cfg,
    );

    tokio::time::sleep(Duration::from_secs(3)).await;
    let attempts = obs.attempts_snapshot();
    assert!(
        attempts.len() >= 2,
        "expected ≥2 reconnect attempts under slow-loris, got {} ({:?})",
        attempts.len(),
        attempts
    );

    sup.stop().await;
}
