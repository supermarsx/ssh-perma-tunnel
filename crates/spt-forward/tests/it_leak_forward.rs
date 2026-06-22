//! Dedicated memory-leak / bounded-growth test binary for `spt-forward`.
//!
//! This is a **dedicated** integration-test binary so it can install the
//! process-global [`CountingAllocator`] as the `#[global_allocator]`. It must
//! never be mixed with unit tests (which run in a separate binary with the
//! default allocator). See `.orchestration/plans/t-memleak.md` (decision C,
//! risk 6) and `.orchestration/logs/memleak-e2.md`.
//!
//! Coverage:
//!
//! * [`UdpFlowTable`] — `.len()` bounded by `max_flows`; `evict_idle` reclaims
//!   under churn; allocator-delta over insert/evict cycles is bounded.
//! * **Default `max_flows` is now a finite cap** ([`DEFAULT_MAX_FLOWS`] =
//!   65536) — closing the former latent unbounded-growth risk (plan risk 6).
//!   An unset/default config bounds the table at a generous-but-finite cap, so
//!   a runaway flood cannot grow it without bound. The legacy escape hatch is
//!   preserved: an *explicit* `max_flows = 0` still means unbounded, where idle
//!   eviction is the *only* thing that bounds the table. The tests below assert
//!   both halves: the default yields a finite cap, and explicit-0 stays
//!   unbounded while idle eviction still reclaims under churn.
//! * bidirectional copy buffer reuse (`copy_bidirectional_throttled`) — the
//!   16 KiB scratch buffer is allocated once per direction and reused; repeated
//!   copies must not leak per byte.
//! * Allocator hot-path harness — `TokenBucket::try_acquire` / `acquire` on the
//!   high-traffic throttle path must not allocate per call.
//!
//! All assertions compare the *delta* in live bytes between two iteration
//! counts with generous slack, never an absolute floor (the harness, lazy
//! statics, and background threads all contribute baseline allocations).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use spt_forward::limits::TokenBucket;
use spt_forward::udp::{UdpFlowKey, UdpFlowTable, UdpFlowTableConfig, DEFAULT_MAX_FLOWS};
use spt_mem_hygiene::testing::CountingAllocator;

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

/// Generous per-iteration-count slack for allocator deltas. The global
/// allocator is shared with the test harness + tokio worker threads, so a
/// clean (non-leaking) op can still show a small, *bounded* delta from
/// lazy-static warmup and thread-local arenas. A real leak grows ~linearly
/// with iterations and blows past this; a clean op stays well under it.
const SLACK_BYTES: usize = 256 * 1024;

fn addr(p: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), p)
}

/// The `#[global_allocator]` is process-global and `cargo test` runs the tests
/// in this binary on parallel threads. Allocator-delta tests measuring
/// `live_bytes()` concurrently would observe each other's allocations and
/// produce noisy/false deltas. Every allocator-sensitive test (and every test
/// that allocates heavily enough to perturb a concurrent measurement) acquires
/// this gate for its full body so measurements are serialized. Each
/// `#[tokio::test]` runs on its own runtime, so holding the std guard across an
/// `.await` only serializes against other tests — it cannot self-deadlock.
static ALLOC_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn alloc_gate() -> std::sync::MutexGuard<'static, ()> {
    ALLOC_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Run `op` `iters` times and return the net growth in live bytes across the
/// loop (clamped at zero). `op` takes the 0-based iteration index.
fn live_delta<F: FnMut(usize)>(iters: usize, mut op: F) -> usize {
    GLOBAL.reset_peak();
    let before = GLOBAL.live_bytes();
    for i in 0..iters {
        op(i);
    }
    GLOBAL.live_bytes().saturating_sub(before)
}

// ---------------------------------------------------------------------------
// UdpFlowTable: bounded by max_flows
// ---------------------------------------------------------------------------

#[test]
fn flow_table_len_bounded_by_max_flows() {
    let _gate = alloc_gate();
    let cap = 64u32;
    let t: UdpFlowTable<UdpFlowKey, u64> = UdpFlowTable::new(UdpFlowTableConfig {
        max_flows: cap,
        idle_timeout: Duration::from_secs(3600),
        ..Default::default()
    });
    // Try to insert 10x the cap with distinct keys. The table must never
    // exceed `cap` live flows, and the overflow must be counted as rejected.
    for p in 0..(cap * 10) {
        // Ports wrap into u16; keep them distinct within the loop range.
        t.touch_or_insert(addr(p as u16), || u64::from(p));
    }
    assert!(
        t.len() <= cap as usize,
        "flow table exceeded max_flows: len={} cap={cap}",
        t.len()
    );
    assert!(
        t.rejected_full_count() > 0,
        "expected some inserts to be rejected once the cap was hit"
    );
}

#[allow(clippy::await_holding_lock)] // serializes allocator measurements; per-test runtime cannot self-deadlock
#[tokio::test(start_paused = true)]
async fn flow_table_evict_idle_reclaims_under_churn() {
    let _gate = alloc_gate();
    let t: UdpFlowTable<UdpFlowKey, ()> = UdpFlowTable::new(UdpFlowTableConfig {
        idle_timeout: Duration::from_secs(10),
        max_flows: 0, // explicit opt-out: unbounded — eviction is the only bound (see risk 6)
        ..Default::default()
    });
    // Insert a wave, age it out, evict, repeat. Each generation must be fully
    // reclaimed so the table does not grow across generations.
    for gen in 0..20u32 {
        for p in 0..100u16 {
            t.touch_or_insert(addr(p), || ());
        }
        assert_eq!(t.len(), 100, "generation {gen} should hold its wave");
        // Age past the idle timeout and evict.
        tokio::time::advance(Duration::from_secs(20)).await;
        let evicted = t.evict_idle();
        assert_eq!(evicted, 100, "generation {gen} should be fully reclaimed");
        assert!(
            t.is_empty(),
            "generation {gen} left residue: len={}",
            t.len()
        );
    }
}

/// **Plan risk 6 — default half.** The default config must now carry a finite
/// hard cap ([`DEFAULT_MAX_FLOWS`] = 65536), closing the former unbounded
/// default. This is the conscious change flagged by the old risk note.
#[test]
fn default_config_yields_finite_cap() {
    let cfg = UdpFlowTableConfig::default();
    assert_eq!(
        cfg.max_flows, DEFAULT_MAX_FLOWS,
        "DEFAULT max_flows must be the finite cap, not 0 (unbounded)"
    );
    assert_eq!(DEFAULT_MAX_FLOWS, 65_536, "default cap is 65536 flows");
    assert!(
        cfg.max_flows > 0,
        "default must be a hard cap; only an EXPLICIT max_flows = 0 is unbounded"
    );
}

/// **Plan risk 6 — escape-hatch half.** With an *explicit* `max_flows = 0`
/// (the power-user opt-out) there is NO hard cap on the flow table. The table
/// can grow without bound for as long as flows keep arriving and stay live;
/// idle eviction is the *only* mechanism that bounds it. This test documents
/// that the escape hatch is preserved and proves idle eviction still bounds
/// the table over time under steady churn.
#[allow(clippy::await_holding_lock)] // serializes allocator measurements; per-test runtime cannot self-deadlock
#[tokio::test(start_paused = true)]
async fn explicit_max_flows_zero_is_unbounded_but_eviction_bounds_over_time() {
    let _gate = alloc_gate();
    // Explicit 0 = unbounded (escape hatch), distinct from the finite default.
    let cfg = UdpFlowTableConfig {
        max_flows: 0,
        ..Default::default()
    };
    assert_eq!(
        cfg.max_flows, 0,
        "explicit opt-out keeps unbounded behaviour"
    );

    let t: UdpFlowTable<UdpFlowKey, u64> = UdpFlowTable::new(cfg);
    let mut high_water = 0usize;
    // Simulate a steady stream of short-lived flows. Each "tick" admits a
    // fresh batch and ages out the previous batch, then evicts. Because every
    // batch goes idle before the next eviction, the live set stays bounded to
    // roughly one batch even though there is NO max_flows cap.
    for tick in 0..50u32 {
        // 50 fresh flows per tick (distinct ports per tick window).
        let base = (tick % 256) as u16; // keep ports in range; churn is the point
        for off in 0..50u16 {
            let port = base.wrapping_add(off).wrapping_add(1);
            t.touch_or_insert(addr(port), || u64::from(tick));
        }
        high_water = high_water.max(t.len());
        // Age the batch past idle and reclaim before the next tick.
        tokio::time::advance(Duration::from_secs(120)).await;
        t.evict_idle();
    }
    // With eviction running every tick the live set never accumulates across
    // ticks: it is bounded by a single tick's batch (<= 50), NOT by tick count.
    assert!(
        t.len() <= 50,
        "post-eviction live set should be bounded by one batch, got {}",
        t.len()
    );
    assert!(
        high_water <= 50,
        "high-water mark should be one batch (~50), got {high_water} — \
         unbounded growth would show ~50*ticks"
    );
}

#[allow(clippy::await_holding_lock)] // serializes allocator measurements; per-test runtime cannot self-deadlock
#[tokio::test(start_paused = true)]
async fn flow_table_alloc_delta_bounded_over_insert_evict_cycles() {
    let _gate = alloc_gate();
    // Build the table once; the leak surface under test is the repeated
    // insert/evict churn, not the one-time table construction.
    let t: UdpFlowTable<UdpFlowKey, u64> = UdpFlowTable::new(UdpFlowTableConfig {
        idle_timeout: Duration::from_secs(1),
        max_flows: 0,
        ..Default::default()
    });

    // Each cycle re-touches a small, fixed key space (so the map size stays
    // bounded while the touch/insert code path runs `iters` times), then we
    // age + evict from the async context between measurements so the table
    // churns rather than monotonically fills.
    let cycle = |iters: usize| -> usize {
        live_delta(iters, |i| {
            let port = (i % 200) as u16;
            t.touch_or_insert(addr(port), || i as u64);
        })
    };

    // Warm up dashmap shard arenas first so the 1k baseline already includes
    // one-time growth.
    let _ = cycle(1_000);
    tokio::time::advance(Duration::from_secs(5)).await;
    t.evict_idle();

    let small = cycle(1_000);
    tokio::time::advance(Duration::from_secs(5)).await;
    t.evict_idle();
    let large = cycle(10_000);
    tokio::time::advance(Duration::from_secs(5)).await;
    t.evict_idle();

    assert!(
        large <= small + SLACK_BYTES,
        "UdpFlowTable insert churn looks like a leak: 1k delta={small} 10k delta={large}"
    );
}

// ---------------------------------------------------------------------------
// bidir copy buffer reuse
// ---------------------------------------------------------------------------

#[allow(clippy::await_holding_lock)] // serializes allocator measurements; per-test runtime cannot self-deadlock
#[tokio::test]
async fn bidir_copy_buffer_reuse_does_not_leak() {
    use spt_forward::copy_bidirectional_throttled;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    // One round of: open a duplex pair, copy a payload both ways, close. The
    // copy loop heap-allocates a single 16 KiB scratch buffer per direction and
    // reuses it across reads, then frees it on completion. Repeating this must
    // not accumulate live bytes per round.
    async fn one_round() {
        let (mut left_app, mut left_tun) = duplex(64 * 1024);
        let (mut right_tun, mut right_app) = duplex(64 * 1024);

        let bridge = tokio::spawn(async move {
            copy_bidirectional_throttled(
                &mut left_tun,
                &mut right_tun,
                TokenBucket::unlimited(),
                TokenBucket::unlimited(),
            )
            .await
        });

        let payload = vec![0xCDu8; 8 * 1024];
        left_app.write_all(&payload).await.unwrap();
        left_app.shutdown().await.unwrap();
        right_app.shutdown().await.unwrap();

        let mut got = Vec::new();
        right_app.read_to_end(&mut got).await.unwrap();
        assert_eq!(got.len(), payload.len());
        let _ = bridge.await.unwrap();
    }

    async fn run(rounds: usize) -> usize {
        GLOBAL.reset_peak();
        let before = GLOBAL.live_bytes();
        for _ in 0..rounds {
            one_round().await;
        }
        GLOBAL.live_bytes().saturating_sub(before)
    }

    let _gate = alloc_gate();
    // Warm up the runtime + duplex machinery first.
    let _ = run(50).await;
    let small = run(100).await;
    let large = run(1_000).await;
    assert!(
        large <= small + SLACK_BYTES,
        "bidir copy looks like a leak: 100 rounds={small} 1000 rounds={large}"
    );
}

// ---------------------------------------------------------------------------
// Allocator hot-path harness: TokenBucket
// ---------------------------------------------------------------------------

#[test]
fn token_bucket_try_acquire_hot_path_does_not_leak() {
    let _gate = alloc_gate();
    // The token bucket sits on the per-byte throttle path; `try_acquire` must
    // be allocation-free so a high-traffic forward does not leak per chunk.
    let bucket = TokenBucket::new(1024 * 1024, 4 * 1024 * 1024);

    let run = |iters: usize| -> usize {
        live_delta(iters, |_| {
            // Mixed accept/reject — both arms are zero-alloc.
            let _ = bucket.try_acquire(1024);
        })
    };

    let small = run(10_000);
    let large = run(100_000);
    assert!(
        large <= small + SLACK_BYTES,
        "TokenBucket::try_acquire hot path looks like a leak: 10k={small} 100k={large}"
    );
}

#[allow(clippy::await_holding_lock)] // serializes allocator measurements; per-test runtime cannot self-deadlock
#[tokio::test(start_paused = true)]
async fn token_bucket_acquire_hot_path_does_not_leak() {
    // `acquire` is the awaiting variant. With an unlimited bucket it is an
    // immediate no-op; with paused time we can also drive a throttling bucket
    // deterministically. Either way it must not allocate per call.
    async fn run<F, Fut>(iters: usize, mut op: F) -> usize
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        GLOBAL.reset_peak();
        let before = GLOBAL.live_bytes();
        for _ in 0..iters {
            op().await;
        }
        GLOBAL.live_bytes().saturating_sub(before)
    }

    let _gate = alloc_gate();
    let unlimited = TokenBucket::unlimited();
    let small = run(10_000, || {
        let b = unlimited.clone();
        async move { b.acquire(4096).await }
    })
    .await;
    let large = run(100_000, || {
        let b = unlimited.clone();
        async move { b.acquire(4096).await }
    })
    .await;
    assert!(
        large <= small + SLACK_BYTES,
        "TokenBucket::acquire hot path looks like a leak: 10k={small} 100k={large}"
    );
}
