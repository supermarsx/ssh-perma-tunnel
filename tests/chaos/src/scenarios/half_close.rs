//! Scenario 9 — **`half_close`**.
//!
//! Server FINs the read-half only. The chaos-proxy doesn't expose
//! half-close as a behaviour, so this scenario fakes it with a custom
//! upstream listener that sends a single byte, calls
//! `TcpStream::shutdown` on its read-half, and idles.
//!
//! With the `TcpProbeProtocol` whose probe = `write+read 1 byte`, that
//! pattern allows the *first* probe to succeed. Subsequent probe
//! attempts (which the supervisor doesn't make today due to the
//! `run_active` bug surfaced in scenarios 2/3) would observe the
//! half-closed peer. Status: stubbed pending the supervisor fix.

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
#[ignore = "FIXME(bug): depends on supervisor session-health loop landing — see t8-C2.md"]
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
    let sup = ProfileSupervisor::spawn(
        "half-close",
        proto,
        AuthConfig::new("u", vec![]),
        vec![Endpoint::new(addr.ip().to_string(), addr.port())],
        vec![],
        cfg,
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = obs.attempts_snapshot();
    sup.stop().await;
}
