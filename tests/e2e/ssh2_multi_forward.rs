//! e2e: multiple concurrent forwards on a single profile.
//!
//! ## Variants
//!
//! * **Mock variant (`three_concurrent_forwards_all_open`)** — runs in CI.
//!   Asserts the supervisor opens **all three** forwards (a local TCP, a
//!   remote TCP, and a second local TCP) on a single session, demonstrating
//!   per-forward isolation in the wiring (each has its own name/spec).
//! * **Real-libssh2 variant (`three_concurrent_forwards_traffic_isolation_real_libssh2`)** —
//!   `#[ignore]`'d. Blocked on the russh ↔ libssh2 KEX bug.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use spt_auth::AuthConfig;
use spt_config::schema::Profile;
use spt_config::testing::{ForwardBuilder, ProfileBuilder};
use spt_e2e_tests::SharedLogProtocol;
use spt_forward::testing::SessionCall;
use spt_protocol::{Endpoint, TunnelProtocol};
use spt_supervisor::testing::{
    wait_for_state, OrchestratorBuilder, ProfileStateName, ProfileSupervisorConfig,
};

fn profile_with_three_forwards() -> Profile {
    ProfileBuilder::new("multi")
        .endpoint("127.0.0.1", 22)
        .user("alice")
        .add_forward(ForwardBuilder::local_tcp("a", "127.0.0.1:0", "127.0.0.1:1").build())
        .add_forward(ForwardBuilder::remote_tcp("b", "127.0.0.1:0", "127.0.0.1:2").build())
        .add_forward(ForwardBuilder::local_tcp("c", "127.0.0.1:0", "127.0.0.1:3").build())
        .build()
}

#[tokio::test]
async fn three_concurrent_forwards_all_open() {
    let proto = Arc::new(SharedLogProtocol::new());
    let log = Arc::clone(&proto.shared);

    let endpoints = vec![Endpoint::new("127.0.0.1", 22)];
    let orch = OrchestratorBuilder::new()
        .with_profile(
            profile_with_three_forwards(),
            proto.clone() as Arc<dyn TunnelProtocol>,
            AuthConfig::new("alice", vec![]),
            endpoints,
            ProfileSupervisorConfig::default(),
        )
        .build();

    wait_for_state(
        &orch,
        "multi",
        ProfileStateName::Active,
        Duration::from_secs(3),
    )
    .await
    .expect("multi reaches active");

    // Wait for all three forwards to be opened.
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..100 {
        seen.clear();
        for c in log.lock().iter() {
            match c {
                SessionCall::OpenLocal(n) | SessionCall::OpenRemote(n) => {
                    seen.insert(n.clone());
                }
                _ => {}
            }
        }
        if seen.contains("a") && seen.contains("b") && seen.contains("c") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        seen.contains("a") && seen.contains("b") && seen.contains("c"),
        "all three forwards must be opened on the single session; observed = {seen:?}; \
         full log = {:?}",
        log.lock()
    );

    // Each forward must be opened *exactly once* per session — wiring
    // isolation invariant.
    let log_snap = log.lock().clone();
    for fname in ["a", "b", "c"] {
        let n = log_snap
            .iter()
            .filter(|c| match c {
                SessionCall::OpenLocal(n) | SessionCall::OpenRemote(n) => n == fname,
                _ => false,
            })
            .count();
        assert_eq!(
            n, 1,
            "forward `{fname}` must be opened exactly once; got {n}"
        );
    }

    orch.shutdown().await;
}

/// Real-libssh2 variant — would assert that bytes pushed to forward `a`'s
/// listener are *not* observed on forward `c`'s listener (and vice versa)
/// across distinct `direct-tcpip` channels on the same SSH session.
/// `#[ignore]`'d on the same upstream KEX bug.
#[tokio::test]
#[ignore = "body unwritten; KEX side unblocked by t3-e8 workaround \
(spt_ssh2::testing::wincng_libssh2_compatible_preferred + with_algorithm_pinning). \
russh upstream tracking: https://github.com/warp-tech/russh/issues/245."]
async fn three_concurrent_forwards_traffic_isolation_real_libssh2() {
    panic!("real-libssh2 variant intentionally unwritten; see #[ignore] reason");
}
