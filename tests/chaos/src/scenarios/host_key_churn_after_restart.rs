//! Scenario 7 — **`host_key_churn_after_restart`**.
//!
//! C1 deferred the `ChurningSshServer` and `HostKeyChurn` proxy variant
//! (today it's a `Pristine` passthrough). The TCP-probe protocol has no
//! host-key concept either. This scenario therefore stubs the
//! assertions for the day a real SSH harness lands and we can wire the
//! trust policy verifier.
//!
//! Expected real assertion list once unblocked:
//!
//! * supervisor's `TrustPolicy::verify` rejects key B (since only key A
//!   is in `known_hosts`),
//! * `ProfileEvent::AuthFailed` (or `TrustFailed`) is emitted,
//! * exit code maps to `ExitCode::TrustFailed`.

use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor, CountingObserver, EchoServer, ObserverGuard,
};
use spt_chaos_proxy::ChaosBehaviour;

#[tokio::test]
#[ignore = "FIXME(C1-deferred): HostKeyChurn / ChurningSshServer not implemented — see t8-C2.md"]
async fn host_key_churn_after_restart() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (_proxy, proxy_addr, _proxy_task) = spawn_proxy_to(
        echo.addr(),
        ChaosBehaviour::HostKeyChurn {
            new_after: Duration::from_millis(200),
        },
    )
    .await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let sup = spawn_supervisor("hostkey-churn", proxy_addr, fast_backoff(0));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = obs.attempts_snapshot();
    sup.stop().await;
}
