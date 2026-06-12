//! Scenario 6 — **`dns_flap_ttl_1s`**.
//!
//! C1 explicitly deferred `DnsAnswerRotation` (see t8-C1.md, "Behaviours
//! implemented vs. deferred"). The proxy treats the variant as
//! `Pristine` today; the companion `MockResolver` is a stub. Until
//! either C1 or a follow-up implements DNS rotation, this scenario is
//! `#[ignore]`'d with a fixme.
//!
//! When DNS rotation lands the assertions will be:
//!
//! * supervisor re-resolves on each reconnect attempt,
//! * the resolved IP cycles between the two answers,
//! * backoff does not collapse to zero just because the IP changed.

use std::net::IpAddr;
use std::time::Duration;

use crate::scenarios::common::{
    fast_backoff, spawn_proxy_to, spawn_supervisor, CountingObserver, EchoServer, ObserverGuard,
};
use spt_chaos_proxy::ChaosBehaviour;

#[tokio::test]
#[ignore = "feature-gated: ChaosBehaviour::DnsAnswerRotation is a Pristine passthrough (spt-chaos-proxy::dns is a stub); no DNS-rotation mechanism exists to exercise. Cannot be un-ignored until real DNS rotation lands. See t8-C2.md"]
async fn dns_flap_ttl_1s() {
    let echo = EchoServer::spawn().await.expect("echo server");
    let (proxy, proxy_addr, _proxy_task) = spawn_proxy_to(
        echo.addr(),
        ChaosBehaviour::DnsAnswerRotation {
            ttl: Duration::from_secs(1),
            answers: vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
            ],
        },
    )
    .await;

    let obs = CountingObserver::new();
    let _guard = ObserverGuard::install(obs.clone());

    let sup = spawn_supervisor("dns-flap", proxy_addr, fast_backoff(0));

    // Today this is just a Pristine passthrough — assert plumbing only.
    tokio::time::sleep(Duration::from_millis(500)).await;
    // FIXME: real assertion requires DnsAnswerRotation to be implemented.
    let _ = obs.attempts_snapshot();

    let _ = proxy.current(); // suppress unused
    sup.stop().await;
}
