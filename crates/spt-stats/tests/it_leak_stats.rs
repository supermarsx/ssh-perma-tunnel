//! Dedicated memory-leak / bounded-growth test binary for `spt-stats`.
//!
//! Dedicated test binary so it can install the process-global
//! [`CountingAllocator`] (see `.orchestration/logs/memleak-e2.md`). Never mix
//! with unit tests. All allocator assertions compare deltas at two iteration
//! counts with generous slack — never an absolute floor.
//!
//! Coverage:
//!
//! * [`SessionTable`] / [`ConnectionTable`] — `evict_idle` shrinks the table
//!   under churn; insert/remove balance returns to empty; allocator-delta on
//!   record→evict cycles is bounded.
//! * [`RollingCounter`] / [`SlidingWindow`] — bucket storage is fixed-size; a
//!   long stream of `add`/`tick` calls does not grow the structure.
//! * [`Ewma`] — holds a single scalar; unbounded sampling does not leak.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use spt_core::{ConnectionId, ForwardId, ProfileId, SessionId};
use spt_mem_hygiene::testing::CountingAllocator;
use spt_stats::{
    ConnectionEntry, ConnectionTable, Ewma, RollingCounter, SessionEntry, SessionTable,
    SlidingWindow, TestClock,
};

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

const SLACK_BYTES: usize = 256 * 1024;

/// The `#[global_allocator]` is process-global and `cargo test` runs the tests
/// in this binary on parallel threads. Two allocator-delta tests measuring
/// `live_bytes()` at the same time would see each other's allocations and
/// produce noisy/false deltas. Each allocator-sensitive test acquires this lock
/// for the duration of BOTH its measurements so they are serialized. (Poison is
/// ignored — a panicking test still releases the lock for the rest.)
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

fn dt(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
}

fn mksess(id: &str, last: i64) -> SessionEntry {
    SessionEntry {
        session_id: SessionId::new(id).unwrap(),
        profile_id: ProfileId::new("p").unwrap(),
        opened_at: dt(0),
        remote_endpoint: "host:22".into(),
        last_activity: dt(last),
        bytes_in: 0,
        bytes_out: 0,
    }
}

fn mkconn(id: &str, fid: &str) -> ConnectionEntry {
    ConnectionEntry {
        connection_id: ConnectionId::new(id).unwrap(),
        session_id: SessionId::new("s1").unwrap(),
        forward_id: ForwardId::new(fid).unwrap(),
        opened_at: dt(0),
        peer: "1.2.3.4:1234".into(),
        local: "127.0.0.1:5000".into(),
        bytes_in: 0,
        bytes_out: 0,
    }
}

// ---------------------------------------------------------------------------
// SessionTable / ConnectionTable: shrink under eviction + add/remove balance
// ---------------------------------------------------------------------------

#[test]
fn session_table_evict_idle_shrinks_under_churn() {
    let t = SessionTable::new();
    // Insert 1000 sessions, all "old". Evicting against a cutoff newer than all
    // of them must reclaim every row.
    for i in 0..1000 {
        t.insert(mksess(&format!("s{i}"), 10));
    }
    assert_eq!(t.len(), 1000);
    let n = t.evict_idle(dt(100));
    assert_eq!(n, 1000);
    assert!(t.is_empty(), "evict_idle must shrink the table to empty");
}

#[test]
fn session_table_add_remove_balance() {
    let t = SessionTable::new();
    for gen in 0..50 {
        for i in 0..100 {
            t.insert(mksess(&format!("g{gen}-{i}"), 1));
        }
        assert_eq!(t.len(), 100);
        for i in 0..100 {
            assert!(t
                .remove(&SessionId::new(format!("g{gen}-{i}")).unwrap())
                .is_some());
        }
        assert!(t.is_empty(), "generation {gen} did not balance to empty");
    }
}

#[test]
fn connection_table_add_remove_balance() {
    let t = ConnectionTable::new();
    for gen in 0..50 {
        for i in 0..100 {
            t.insert(mkconn(&format!("c{gen}-{i}"), "f1"));
        }
        assert_eq!(t.len(), 100);
        for i in 0..100 {
            assert!(t
                .remove(&ConnectionId::new(format!("c{gen}-{i}")).unwrap())
                .is_some());
        }
        assert!(t.is_empty(), "generation {gen} did not balance to empty");
    }
}

#[test]
fn session_table_record_evict_cycle_alloc_bounded() {
    let _gate = alloc_gate();
    let t = SessionTable::new();
    // One cycle = insert a fixed wave, then evict it all. The table returns to
    // empty each cycle, so repeated cycles must not accumulate live bytes.
    let cycle = |iters: usize| -> usize {
        live_delta(iters, |i| {
            let id = format!("k{}", i % 256);
            t.insert(mksess(&id, 10));
            if i % 256 == 255 {
                t.evict_idle(dt(100));
            }
        })
    };
    // Warm shard arenas.
    let _ = cycle(1_000);
    t.evict_idle(dt(100));
    let small = cycle(2_000);
    t.evict_idle(dt(100));
    let large = cycle(20_000);
    t.evict_idle(dt(100));
    assert!(
        large <= small + SLACK_BYTES,
        "SessionTable record/evict looks like a leak: small={small} large={large}"
    );
}

// ---------------------------------------------------------------------------
// RollingCounter / SlidingWindow: fixed bucket storage
// ---------------------------------------------------------------------------

#[test]
fn rolling_counter_storage_is_bounded() {
    let _gate = alloc_gate();
    let clock = TestClock::at_now();
    let counter = RollingCounter::with_clock(Duration::from_secs(60), 12, Arc::new(clock.clone()));
    // A long stream of adds (advancing time so buckets roll) must not grow the
    // structure — slots are a fixed-size Vec of `buckets` entries.
    let run = |iters: usize| -> usize {
        live_delta(iters, |i| {
            counter.add(i as u64);
            if i % 100 == 0 {
                // sum_over_window walks the fixed slot Vec; allocation-free.
                let _ = counter.sum_over_window();
            }
        })
    };
    // Advance time across the stream so buckets are recycled rather than just
    // accumulated into one slot.
    let small = run(5_000);
    clock.advance(Duration::from_secs(120));
    let large = run(50_000);
    assert!(
        large <= small + SLACK_BYTES,
        "RollingCounter looks like a leak: small={small} large={large}"
    );
}

#[test]
fn sliding_window_aggregates_bounded() {
    let _gate = alloc_gate();
    let clock = TestClock::at_now();
    let w = SlidingWindow::with_clock(Duration::from_secs(30), 6, Arc::new(clock.clone()));
    let run = |iters: usize| -> usize {
        live_delta(iters, |i| {
            w.add_bytes(i as u64);
            w.record_conn();
            if i % 3 == 0 {
                w.record_error();
            }
            let _ = w.aggregates();
        })
    };
    let small = run(5_000);
    clock.advance(Duration::from_secs(60));
    let large = run(50_000);
    assert!(
        large <= small + SLACK_BYTES,
        "SlidingWindow looks like a leak: small={small} large={large}"
    );
}

// ---------------------------------------------------------------------------
// Ewma: single scalar, no growth
// ---------------------------------------------------------------------------

#[test]
fn ewma_sampling_does_not_leak() {
    let _gate = alloc_gate();
    let ewma = Ewma::new(Duration::from_secs(10));
    let run = |iters: usize| -> usize {
        live_delta(iters, |i| {
            ewma.sample(i as f64, Duration::from_millis(100));
            let _ = ewma.value();
        })
    };
    let small = run(10_000);
    let large = run(100_000);
    assert!(
        large <= small + SLACK_BYTES,
        "Ewma sampling looks like a leak: small={small} large={large}"
    );
}
