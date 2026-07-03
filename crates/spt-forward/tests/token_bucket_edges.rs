//! Edge-case regression tests for [`spt_forward::TokenBucket`] — the byte-rate
//! throttle that backs `bidir::copy_bidirectional_throttled`. Complements the
//! in-crate unit tests (`limits.rs`) with the corner cases the data-plane
//! coverage audit called out: burst, refill-cap, zero-rate, very-low-rate,
//! exactly-at-limit, over-burst chunking, and the burst<rate clamp.
//!
//! All timing assertions run on `tokio`'s paused clock, so they depend only on
//! the bucket's integer-nanos math, never on wall-clock scheduling.

use std::time::Duration;

use tokio::time::Instant;

use spt_forward::TokenBucket;

// zero-rate == unlimited: never throttles, admits arbitrarily large requests
// with no wait, and reports itself inactive.
#[test]
fn zero_rate_is_unlimited_and_inactive() {
    let b = TokenBucket::unlimited();
    assert!(!b.is_active());
    assert_eq!(b.rate_bps(), 0);
    // try_acquire never asks the caller to wait.
    assert!(b.try_acquire(u64::MAX).is_none());
    // Equivalent explicit construction.
    assert!(!TokenBucket::new(0, 0).is_active());
}

#[tokio::test(start_paused = true)]
async fn zero_rate_acquire_is_immediate() {
    let b = TokenBucket::unlimited();
    let start = Instant::now();
    b.acquire(4 * 1024 * 1024).await;
    assert!(start.elapsed() < Duration::from_millis(1));
}

// acquire(0) is a no-op even on an active, drained bucket (no spurious wait).
#[tokio::test(start_paused = true)]
async fn acquire_zero_bytes_is_noop() {
    let b = TokenBucket::new(1024, 1024);
    // Drain the bucket first.
    b.acquire(1024).await;
    let start = Instant::now();
    b.acquire(0).await;
    assert!(start.elapsed() < Duration::from_millis(1));
}

// The full burst is immediately available; one byte beyond it must wait. This
// pins the exact accept/reject boundary at capacity.
#[tokio::test(start_paused = true)]
async fn exactly_at_limit_boundary() {
    let b = TokenBucket::new(1000, 1000);
    // Exactly the burst drains without waiting.
    assert!(
        b.try_acquire(1000).is_none(),
        "draining exactly the burst must succeed immediately"
    );
    // One byte past the (now empty) bucket must report a wait.
    assert!(
        b.try_acquire(1).is_some(),
        "one byte beyond an empty bucket must require a wait"
    );
}

// Burst is available at once; the immediately following equal amount must take
// ~1 s at a 1x rate (classic token-bucket behaviour).
#[tokio::test(start_paused = true)]
async fn burst_then_steady_rate() {
    let b = TokenBucket::new(1024, 1024);
    let start = Instant::now();
    b.acquire(1024).await; // burst, immediate
    assert!(start.elapsed() < Duration::from_millis(1));

    let mark = Instant::now();
    b.acquire(1024).await; // must refill at 1 KiB/s => ~1 s
    let dt = mark.elapsed();
    assert!(
        dt >= Duration::from_millis(900),
        "expected >=900ms, got {dt:?}"
    );
}

// A request larger than the burst is internally chunked but the cumulative wait
// still reflects the full byte count.
#[tokio::test(start_paused = true)]
async fn over_burst_request_is_chunked_with_full_wait() {
    // 1 KiB/s, 1 KiB burst. Bucket starts full: first KiB immediate, remaining
    // 3 KiB at 1 KiB/s => ~3 s total for a single acquire(4 KiB).
    let b = TokenBucket::new(1024, 1024);
    let start = Instant::now();
    b.acquire(4096).await;
    let dt = start.elapsed();
    assert!(
        dt >= Duration::from_millis(2900),
        "expected >=2.9s, got {dt:?}"
    );
}

// After a long idle period tokens must be capped at `burst`, not accumulate
// without bound. Guards against unbounded-credit bursts after quiescence.
#[tokio::test(start_paused = true)]
async fn refill_caps_at_burst_after_long_idle() {
    let b = TokenBucket::new(1024, 2048);
    // Drain to empty, then idle far longer than an uncapped bucket would need
    // to overfill.
    b.acquire(2048).await;
    tokio::time::advance(Duration::from_secs(1000)).await;
    // Exactly one burst is available instantly...
    let start = Instant::now();
    b.acquire(2048).await;
    assert!(start.elapsed() < Duration::from_millis(1));
    // ...and no more: tokens were capped at burst, not accumulated over 1000 s.
    assert!(
        b.try_acquire(1).is_some(),
        "tokens must be capped at burst, not accumulated during idle"
    );
}

// Very low rate: 1 byte/sec. The second byte takes ~1 s; timing must be exact
// under the integer-nanos math (this is the regime f64 drift used to bite).
#[tokio::test(start_paused = true)]
async fn very_low_rate_one_byte_per_second() {
    let b = TokenBucket::new(1, 1);
    b.acquire(1).await; // burst, immediate
    let start = Instant::now();
    b.acquire(1).await;
    let dt = start.elapsed();
    assert!(
        dt >= Duration::from_millis(900) && dt <= Duration::from_secs(2),
        "expected ~1s for 1 byte at 1 B/s, got {dt:?}"
    );
}

// burst < rate is clamped up to rate, so at least one second of tokens is always
// drainable at once (steady-state rate is achievable).
#[test]
fn burst_clamped_up_to_rate() {
    let b = TokenBucket::new(1000, 0);
    assert_eq!(b.burst(), 1000, "burst must clamp up to rate");
    assert_eq!(b.rate_bps(), 1000);
    let b2 = TokenBucket::new(4096, 100);
    assert_eq!(b2.burst(), 4096, "burst below rate must clamp up to rate");
}
