//! Dedicated memory-leak / bounded-growth test binary for `spt-state`.
//!
//! Installs [`CountingAllocator`] as the process `#[global_allocator]` (one per
//! dedicated `tests/it_leak_*.rs` bin — never mixed with unit tests). Leak
//! assertions compare the *net-live-byte delta* between two iteration counts
//! with generous slack; bounded-growth assertions use on-disk file counts and
//! byte caps.
//!
//! Coverage:
//! * `event_ring_file_count_bounded_by_retention` — appending across many
//!   simulated days never retains more than `retain_days` daily files.
//! * `disk_spool_bytes_bounded_by_cap_under_flood` — flooding a `DiskSpool`
//!   keeps `total_bytes() <= max_bytes` and `len() <= max_files`.
//! * `runtime_status_write_read_cycles_do_not_leak` — repeated runtime.json
//!   write/read cycles leave live bytes bounded (allocator delta).
//! * `status_snapshot_write_read_cycles_do_not_leak` — repeated status snapshot
//!   serialize/deserialize cycles leave live bytes bounded (allocator delta).

use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone, Utc};

use spt_state::clock::TestClock;
use spt_state::events::{Event, EventRing, EventRingConfig};
use spt_state::runtime::{read_runtime, write_runtime, RuntimeStatus};
use spt_state::spool::{DiskSpool, SpoolConfig};
use spt_state::status::StatusSnapshot;
use spt_state::{paths, Counters};

use spt_mem_hygiene::testing::CountingAllocator;

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

// ---------------------------------------------------------------------------
// EventRing: daily file count bounded by retention
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn event_ring_file_count_bounded_by_retention() {
    let tmp = tempfile::tempdir().unwrap();
    let retain_days = 3usize;
    let clock = Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap(),
    ));
    let ring = EventRing::spawn_with_clock(
        tmp.path().to_path_buf(),
        EventRingConfig {
            channel_capacity: 64,
            retain_days,
        },
        clock.clone(),
    )
    .unwrap();

    // Walk 60 distinct days, appending one event each. Each day-boundary open
    // triggers prune_old, which keeps only the newest `retain_days` files.
    for day in 1..=60i64 {
        let ts =
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap() + chrono::Duration::days(day - 1);
        clock.set(ts);
        ring.append(Event::new(ts, "k", "info"));
    }
    ring.stop().await;

    let edir = paths::events_dir(tmp.path());
    let files: Vec<_> = std::fs::read_dir(&edir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
        .collect();
    assert!(
        files.len() <= retain_days,
        "event ring file count must be bounded by retain_days={retain_days}, got {} files",
        files.len()
    );
}

// ---------------------------------------------------------------------------
// DiskSpool: on-disk bytes bounded by cap under flood
// ---------------------------------------------------------------------------

#[test]
fn disk_spool_bytes_bounded_by_cap_under_flood() {
    let tmp = tempfile::tempdir().unwrap();
    let max_bytes = 4096u64;
    let max_files = 100usize;
    let mut spool = DiskSpool::open(
        tmp.path().to_path_buf(),
        SpoolConfig {
            max_bytes,
            max_files,
        },
    )
    .unwrap();

    // Flood with thousands of 64-byte payloads; eviction must keep both caps.
    let payload = vec![0xABu8; 64];
    for _ in 0..10_000 {
        spool.push(&payload).unwrap();
        assert!(
            spool.total_bytes() <= max_bytes,
            "spool bytes exceeded cap: {} > {max_bytes}",
            spool.total_bytes()
        );
        assert!(
            spool.len() <= max_files,
            "spool file count exceeded cap: {} > {max_files}",
            spool.len()
        );
    }
    // Final invariants after the flood.
    assert!(spool.total_bytes() <= max_bytes);
    assert!(spool.len() <= max_files);

    // Cross-check on-disk reality: count actual .bin files on disk.
    let on_disk = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".bin"))
        .count();
    assert!(
        on_disk <= max_files,
        "on-disk .bin file count must respect max_files: {on_disk} > {max_files}"
    );
}

// ---------------------------------------------------------------------------
// RuntimeStatus write/read cycles — allocator delta
// ---------------------------------------------------------------------------

#[test]
fn runtime_status_write_read_cycles_do_not_leak() {
    fn run(dir: &std::path::Path, rs: &mut RuntimeStatus, iters: usize) -> usize {
        let before = GLOBAL.live_bytes();
        for i in 0..iters {
            rs.pid = (i % 65_536) as u32;
            write_runtime(dir, rs).unwrap();
            let back = read_runtime(dir).unwrap();
            assert!(back.is_some());
            std::hint::black_box(&back);
        }
        GLOBAL.live_bytes().saturating_sub(before)
    }

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let mut rs = RuntimeStatus {
        pid: 4242,
        version: "1.2.3".into(),
        config_path: "/etc/spt/config.toml".into(),
        state_dir: dir.display().to_string(),
        ..Default::default()
    };

    let small = run(dir, &mut rs, 1_000);
    let large = run(dir, &mut rs, 10_000);
    assert!(
        large <= small + 256 * 1024,
        "runtime status write/read net-live grew with iterations (leak?): 1k={small} 10k={large}"
    );
}

// ---------------------------------------------------------------------------
// StatusSnapshot serialize/deserialize cycles — allocator delta
// ---------------------------------------------------------------------------

#[test]
fn status_snapshot_write_read_cycles_do_not_leak() {
    fn run(snap: &mut StatusSnapshot, iters: usize) -> usize {
        let before = GLOBAL.live_bytes();
        for i in 0..iters {
            snap.counters.bytes_in = i as u64;
            let bytes = serde_json::to_vec(&*snap).unwrap();
            let back: StatusSnapshot = serde_json::from_slice(&bytes).unwrap();
            std::hint::black_box(&back);
        }
        GLOBAL.live_bytes().saturating_sub(before)
    }

    let mut snap = StatusSnapshot {
        pid: 7,
        version: "v1".into(),
        counters: Counters {
            bytes_in: 1,
            bytes_out: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let small = run(&mut snap, 1_000);
    let large = run(&mut snap, 10_000);
    assert!(
        large <= small + 256 * 1024,
        "status snapshot ser/de net-live grew with iterations (leak?): 1k={small} 10k={large}"
    );

    // Sanity touch of a duration-typed API so the `Duration` import is used and
    // staleness logic is exercised on the cycle output.
    assert!(snap.is_stale(Duration::from_secs(5)));
}
