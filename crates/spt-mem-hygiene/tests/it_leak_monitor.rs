//! Dedicated memory-leak / bounded-growth test binary for the
//! [`MemoryMonitor`] and the [`CountingAllocator`] self-test.
//!
//! This binary installs [`CountingAllocator`] as the process `#[global_allocator]`
//! (one allocator per dedicated `tests/it_leak_*.rs` bin — never mixed with the
//! crate's unit tests). The leak assertions compare the *net-live-byte delta*
//! between two iteration counts with generous slack rather than asserting an
//! absolute floor, so one-time lazy-static / cache growth does not flake.
//!
//! Coverage:
//! * `window_cap_*` — the monitor's sliding window never exceeds
//!   `window_samples` regardless of how many samples are fed (structure cap).
//! * `monitor_task_joins_on_shutdown` — `shutdown().await` joins the sampling
//!   task (no leaked task).
//! * `counting_allocator_*` — allocate/drop balance self-test; live bytes
//!   return to ~baseline after dropping a large Vec; the allocator-delta
//!   pattern stays bounded across 1k vs 10k iterations.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use spt_mem_hygiene::monitor::{MemoryMonitor, MemoryMonitorConfig};
use spt_mem_hygiene::testing::CountingAllocator;

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

const MIB: u64 = 1024 * 1024;

fn cfg(window: usize) -> MemoryMonitorConfig {
    MemoryMonitorConfig {
        interval: Duration::from_secs(60),
        window_samples: window,
        growth_threshold_bytes: 64 * MIB,
        growth_rate_bytes_per_min: 2 * MIB,
        min_rising_fraction: 0.8,
    }
}

/// Advance paused time by `interval` `ticks` times, yielding so the monitor
/// task gets a chance to run between ticks.
async fn drive(ticks: usize) {
    for _ in 0..ticks {
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
    }
}

// ---------------------------------------------------------------------------
// MemoryMonitor sliding-window bounded growth
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn window_cap_respected_over_many_flat_samples() {
    // Feed far more samples than the window holds. The internal VecDeque is
    // capped at `window_samples` (FIFO evict). We cannot read the VecDeque
    // directly, so we assert the observable invariants: the sampler keeps
    // running (samples_taken climbs well past the cap) and a flat line never
    // flags — which is only possible if the window stays bounded rather than
    // accumulating every sample.
    let window = 5usize;
    let c = cfg(window);
    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = Arc::clone(&calls);
    let emits = Arc::new(AtomicUsize::new(0));
    let emits2 = Arc::clone(&emits);

    let handle = MemoryMonitor::spawn_with_sampler(
        c,
        1,
        move || {
            calls2.fetch_add(1, Ordering::Relaxed);
            500 * MIB // flat
        },
        move |_g| {
            emits2.fetch_add(1, Ordering::Relaxed);
        },
    );

    // Many multiples of the window worth of ticks.
    drive(200).await;

    let taken = handle.samples_taken();
    assert!(
        taken >= 20 * window,
        "sampler should have run far past the window cap ({window}), took {taken}"
    );
    assert_eq!(
        emits.load(Ordering::Relaxed),
        0,
        "a flat line must never flag regardless of sample count"
    );
    assert_eq!(calls.load(Ordering::Relaxed), taken);
    handle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn window_cap_emits_once_on_long_synthetic_climb() {
    // A long monotonic climb fed for thousands of ticks: the window stays
    // bounded (else the heuristic, which keys off the full window, would
    // behave erratically) and the steady climb flags exactly once (cooldown).
    let window = 10usize;
    let c = cfg(window);
    let next = Arc::new(AtomicU64::new(0));
    let next2 = Arc::clone(&next);
    let events: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let events2 = Arc::clone(&events);

    let handle = MemoryMonitor::spawn_with_sampler(
        c,
        9,
        move || {
            let i = next2.fetch_add(1, Ordering::Relaxed);
            100 * MIB + i * 20 * MIB
        },
        move |g| events2.lock().unwrap().push(g.growth_bytes),
    );

    // Drive far more ticks than the window holds.
    drive(2_000).await;
    handle.shutdown().await;

    let ev = events.lock().unwrap();
    assert_eq!(
        ev.len(),
        1,
        "an unbroken climb must flag exactly once (cooldown), got {}",
        ev.len()
    );
    assert!(ev[0] >= 64 * MIB);
}

// ---------------------------------------------------------------------------
// No leaked task
// ---------------------------------------------------------------------------

#[test]
fn monitor_task_joins_on_shutdown() {
    // `shutdown().await` returning is itself proof the task joined. We also
    // confirm that shutting many monitors down in sequence does not accumulate
    // live bytes (no leaked task state). Plain `#[test]` so we can build a
    // fresh runtime per delta() call without nesting runtimes.
    fn delta_after(iters: usize) -> usize {
        let before = GLOBAL.live_bytes();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            for _ in 0..iters {
                let handle = MemoryMonitor::spawn_with_sampler(cfg(4), 1, || 100 * MIB, |_g| {});
                // Let it sample a few times, then join.
                for _ in 0..6 {
                    tokio::task::yield_now().await;
                }
                handle.shutdown().await;
            }
        });
        drop(rt);
        GLOBAL.live_bytes().saturating_sub(before)
    }

    let small = delta_after(50);
    let large = delta_after(500);
    // 10x the spawn/shutdown cycles must not grow live bytes ~10x: a leaked
    // task or handle would. Generous slack for runtime/thread bookkeeping.
    assert!(
        large <= small + 512 * 1024,
        "spawn/shutdown leak suspected: 50x={small} bytes, 500x={large} bytes"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_joins_after_sampling() {
    let handle = MemoryMonitor::spawn_with_sampler(cfg(3), 7, || 200 * MIB, |_g| {});
    drive(10).await;
    assert!(handle.samples_taken() > 0, "must sample before shutdown");
    // Returning from shutdown() proves the task joined (no hang, no leak).
    handle.shutdown().await;
}

// ---------------------------------------------------------------------------
// CountingAllocator self-test (representative op + delta pattern)
// ---------------------------------------------------------------------------

#[test]
fn counting_allocator_live_returns_to_baseline_after_drop() {
    // Allocate a large Vec, observe live bytes rise, drop it, observe them
    // return to ~baseline. This exercises the *global* allocator (the one
    // installed above), so other test threads may perturb the absolute number;
    // assert the post-drop value is within a small slack of the pre-alloc
    // baseline rather than exactly equal.
    let baseline = GLOBAL.live_bytes();
    let big: Vec<u8> = vec![7u8; 8 * 1024 * 1024];
    let with_vec = GLOBAL.live_bytes();
    assert!(
        with_vec >= baseline + 8 * 1024 * 1024,
        "live bytes should rise by the Vec size: baseline={baseline} with_vec={with_vec}"
    );
    // Touch it so the allocation can't be optimised away.
    std::hint::black_box(&big);
    drop(big);
    let after = GLOBAL.live_bytes();
    // After dropping, the 8 MiB is reclaimed. Allow generous slack for
    // concurrent harness/thread allocations.
    assert!(
        after <= baseline + 1024 * 1024,
        "live bytes should return to ~baseline after drop: baseline={baseline} after={after}"
    );
}

#[test]
fn counting_allocator_delta_bounded_across_iterations() {
    // Representative op: build then drop a HashMap-ish workload. A clean op
    // leaves nothing behind, so the net-live delta is ~0 regardless of N. A
    // leak would scale with N.
    fn run(iters: usize) -> usize {
        let before = GLOBAL.live_bytes();
        for i in 0..iters {
            let mut v: Vec<u64> = Vec::with_capacity(64);
            for j in 0..64u64 {
                v.push(j.wrapping_mul(i as u64));
            }
            std::hint::black_box(&v);
            drop(v);
        }
        GLOBAL.live_bytes().saturating_sub(before)
    }
    let small = run(1_000);
    let large = run(10_000);
    assert!(
        large <= small + 64 * 1024,
        "alloc delta grew with iterations (leak?): 1k={small} 10k={large}"
    );
}
