//! Dedicated memory-leak / bounded-growth test binary for `spt-dns`.
//!
//! Dedicated test binary so it can install the process-global
//! [`CountingAllocator`] (see `.orchestration/logs/memleak-e2.md`). Never mix
//! with unit tests. Allocator assertions compare deltas at two iteration
//! counts with generous slack — never an absolute floor.
//!
//! Coverage:
//!
//! * [`ManagedZone`] / [`Record`] — the zone is a fixed `Vec<Record>` sized by
//!   config; building many zones and dropping them does not accumulate live
//!   bytes (the structure has no hidden cache).
//! * Split-horizon server query path — a running [`LocalhostResolver`] answers
//!   many managed-name queries without leaking per query. The handler builds a
//!   response from the static zone each time and must not retain it.

use std::net::Ipv4Addr;

use spt_dns::testing::{fixtures, FakeZone, LocalhostResolver};
use spt_dns::{query_resolver, RecordKind};
use spt_mem_hygiene::testing::CountingAllocator;

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

const SLACK_BYTES: usize = 512 * 1024;

/// Serialize allocator-delta measurements: the `#[global_allocator]` is
/// process-global and tests in this binary run on parallel threads. Each
/// allocator-sensitive test acquires this gate for its full body. Each
/// `#[tokio::test]` runs on its own runtime, so holding the std guard across an
/// `.await` only serializes against other tests — it cannot self-deadlock.
static ALLOC_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn alloc_gate() -> std::sync::MutexGuard<'static, ()> {
    ALLOC_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn live_delta<F: FnMut(usize)>(iters: usize, mut op: F) -> usize {
    GLOBAL.reset_peak();
    let before = GLOBAL.live_bytes();
    for i in 0..iters {
        op(i);
    }
    GLOBAL.live_bytes().saturating_sub(before)
}

// ---------------------------------------------------------------------------
// ManagedZone: fixed-size record storage, no hidden cache
// ---------------------------------------------------------------------------

#[test]
fn building_zones_does_not_leak() {
    let _gate = alloc_gate();
    // Build + drop many zones. Each `ManagedZone` owns a `Vec<Record>` sized by
    // the number of records added; building and dropping them in a loop must
    // not accumulate live bytes (no interned/static cache hides behind it).
    let run = |iters: usize| -> usize {
        live_delta(iters, |i| {
            let zone = FakeZone::new("tunnel.local.")
                .a(
                    format!("h{}.tunnel.local.", i % 8),
                    Ipv4Addr::new(10, 0, 0, (i % 250) as u8 + 1),
                )
                .txt(format!("t{}.tunnel.local.", i % 8), "spt-leak-test")
                .build();
            // Record count is bounded by what we added — never by `i`.
            assert_eq!(zone.records.len(), 2);
            // zone dropped at end of iteration.
        })
    };
    let small = run(10_000);
    let large = run(100_000);
    assert!(
        large <= small + SLACK_BYTES,
        "ManagedZone build/drop looks like a leak: small={small} large={large}"
    );
}

#[test]
fn zone_record_count_is_bounded_by_input_not_churn() {
    // Re-assert the bound explicitly: appending N records yields exactly N — the
    // zone has no growth source independent of the caller's input.
    let mut z = FakeZone::new("tunnel.local.");
    for i in 0..256u16 {
        z = z.a(
            format!("n{i}.tunnel.local."),
            Ipv4Addr::new(127, 0, 0, (i % 250) as u8 + 1),
        );
    }
    let zone = z.build();
    assert_eq!(zone.records.len(), 256);
}

// ---------------------------------------------------------------------------
// Server query path: forwarder/handler does not leak across many queries
// ---------------------------------------------------------------------------

/// Run `iters` queries for `name` against `addr`, returning the net live-byte
/// growth across the loop. `expect_answers` asserts the per-query answer count.
async fn query_loop(
    iters: usize,
    addr: std::net::SocketAddr,
    name: &str,
    expect_answers: usize,
) -> usize {
    GLOBAL.reset_peak();
    let before = GLOBAL.live_bytes();
    for _ in 0..iters {
        let answers = query_resolver(addr, name, RecordKind::A)
            .await
            .expect("query ok");
        assert_eq!(answers.len(), expect_answers);
    }
    GLOBAL.live_bytes().saturating_sub(before)
}

#[allow(clippy::await_holding_lock)] // serializes allocator measurements; per-test runtime cannot self-deadlock
#[tokio::test]
async fn repeated_managed_queries_do_not_leak() {
    let _gate = alloc_gate();
    let zone = fixtures::loopback_zone();
    let resolver = LocalhostResolver::start(vec![zone])
        .await
        .expect("resolver starts");
    let addr = resolver.udp_addr();

    // Managed name answered locally by the split-horizon handler. The handler
    // synthesizes the answer from the static zone each call and must not retain
    // it. Warm up the resolver client construction + socket pool first.
    let _ = query_loop(50, addr, "alpha.tunnel.local.", 1).await;
    let small = query_loop(100, addr, "alpha.tunnel.local.", 1).await;
    let large = query_loop(1_000, addr, "alpha.tunnel.local.", 1).await;
    // Each query builds a fresh single-upstream resolver, so per-query slack is
    // larger than the pure-CPU paths; the delta must still be bounded, not
    // linear, across a 10x iteration increase.
    assert!(
        large <= small * 4 + SLACK_BYTES,
        "DNS query path looks like a leak: 100={small} 1000={large}"
    );

    resolver.shutdown().await;
}

#[allow(clippy::await_holding_lock)] // serializes allocator measurements; per-test runtime cannot self-deadlock
#[tokio::test]
async fn missing_name_queries_do_not_leak() {
    let _gate = alloc_gate();
    // NXDOMAIN path: empty answer set, no error. Ensure the empty-answer branch
    // does not accumulate state across many misses.
    let zone = FakeZone::new("tunnel.local.")
        .a("present.tunnel.local.", "10.0.0.1".parse().unwrap())
        .build();
    let resolver = LocalhostResolver::start(vec![zone])
        .await
        .expect("resolver starts");
    let addr = resolver.udp_addr();

    let _ = query_loop(50, addr, "ghost.tunnel.local.", 0).await;
    let small = query_loop(100, addr, "ghost.tunnel.local.", 0).await;
    let large = query_loop(1_000, addr, "ghost.tunnel.local.", 0).await;
    assert!(
        large <= small * 4 + SLACK_BYTES,
        "DNS NXDOMAIN path looks like a leak: 100={small} 1000={large}"
    );

    resolver.shutdown().await;
}
