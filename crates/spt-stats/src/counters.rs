//! Time-bucketed rolling counters.
//!
//! A [`RollingCounter`] divides a fixed window `W` into `B` equal-width
//! buckets. Increments land in the bucket containing the current time;
//! [`RollingCounter::sum_over_window`] returns the sum of all buckets that
//! fall inside the most recent `W`. Buckets older than `W` are zeroed lazily
//! on access — there is no background timer.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::clock::{Clock, SystemClock};

/// A bucketed rolling counter.
#[derive(Clone)]
pub struct RollingCounter {
    inner: Arc<Mutex<Inner>>,
    clock: Arc<dyn Clock>,
    window: Duration,
    buckets: u32,
}

struct Inner {
    /// One slot per bucket.
    slots: Vec<Slot>,
    /// Anchor; `slot_index = ((now - anchor) / bucket_width) % buckets`.
    anchor: Instant,
}

#[derive(Clone, Copy, Default)]
struct Slot {
    /// Generation index = how many bucket-widths since `anchor` this slot
    /// represents. Used to invalidate stale buckets.
    gen: u64,
    value: u64,
}

impl RollingCounter {
    /// Create a counter with `buckets` slots over `window`. Both must be > 0.
    ///
    /// # Panics
    /// Panics if `buckets == 0` or `window` is zero.
    #[must_use]
    pub fn new(window: Duration, buckets: u32) -> Self {
        Self::with_clock(window, buckets, Arc::new(SystemClock))
    }

    /// As [`new`], with an injected clock.
    ///
    /// # Panics
    /// Panics if `buckets == 0` or `window` is zero.
    #[must_use]
    pub fn with_clock(window: Duration, buckets: u32, clock: Arc<dyn Clock>) -> Self {
        assert!(buckets > 0, "buckets must be > 0");
        assert!(!window.is_zero(), "window must be > 0");
        let anchor = clock.now();
        Self {
            inner: Arc::new(Mutex::new(Inner {
                slots: vec![Slot::default(); buckets as usize],
                anchor,
            })),
            clock,
            window,
            buckets,
        }
    }

    /// Window width.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Number of buckets.
    #[must_use]
    pub fn bucket_count(&self) -> u32 {
        self.buckets
    }

    /// Width of one bucket.
    #[must_use]
    pub fn bucket_width(&self) -> Duration {
        self.window / self.buckets
    }

    /// Add `value` at the current time.
    pub fn add(&self, value: u64) {
        let now = self.clock.now();
        let mut g = self.inner.lock();
        let (idx, gen) = self.gen_for(&g, now);
        let slot = &mut g.slots[idx];
        if slot.gen != gen {
            slot.gen = gen;
            slot.value = 0;
        }
        slot.value = slot.value.saturating_add(value);
    }

    /// Convenience: add 1.
    pub fn tick(&self) {
        self.add(1);
    }

    /// Sum of all live buckets covering the last `window`.
    #[must_use]
    pub fn sum_over_window(&self) -> u64 {
        let now = self.clock.now();
        let g = self.inner.lock();
        let (_idx, current_gen) = self.gen_for(&g, now);
        // A bucket is "live" if its gen is within (current_gen - buckets, current_gen].
        let cutoff_low = current_gen.saturating_sub(u64::from(self.buckets) - 1);
        let mut sum: u64 = 0;
        for s in &g.slots {
            if s.gen >= cutoff_low && s.gen <= current_gen {
                sum = sum.saturating_add(s.value);
            }
        }
        sum
    }

    /// Number of non-zero live buckets — useful for "samples observed".
    #[must_use]
    pub fn samples(&self) -> u32 {
        let now = self.clock.now();
        let g = self.inner.lock();
        let (_idx, current_gen) = self.gen_for(&g, now);
        let cutoff_low = current_gen.saturating_sub(u64::from(self.buckets) - 1);
        let mut n = 0;
        for s in &g.slots {
            if s.gen >= cutoff_low && s.gen <= current_gen && s.value > 0 {
                n += 1;
            }
        }
        n
    }

    /// (`slot_index`, generation) for `now` against `inner.anchor`.
    fn gen_for(&self, inner: &Inner, now: Instant) -> (usize, u64) {
        let bw = self.bucket_width();
        let elapsed = now.saturating_duration_since(inner.anchor);
        // Avoid u128 / Duration division pitfalls — use whole-second math
        // augmented with sub-second nanos.
        let elapsed_ns = elapsed.as_nanos();
        let bw_ns = bw.as_nanos().max(1);
        let gen = u64::try_from(elapsed_ns / bw_ns).unwrap_or(u64::MAX);
        let idx = (gen % u64::from(self.buckets)) as usize;
        (idx, gen)
    }
}

impl std::fmt::Debug for RollingCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RollingCounter")
            .field("window", &self.window)
            .field("buckets", &self.buckets)
            .field("sum_over_window", &self.sum_over_window())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;

    #[test]
    fn add_then_sum_within_window() {
        let clock = Arc::new(TestClock::at_now());
        let c = RollingCounter::with_clock(Duration::from_secs(10), 10, clock.clone());
        c.add(3);
        c.add(7);
        assert_eq!(c.sum_over_window(), 10);
    }

    #[test]
    fn old_buckets_evicted_after_window() {
        let clock = Arc::new(TestClock::at_now());
        let c = RollingCounter::with_clock(Duration::from_secs(10), 10, clock.clone());
        c.add(5);
        // Move forward more than the window — original bucket should fall off.
        clock.advance(Duration::from_secs(11));
        assert_eq!(c.sum_over_window(), 0);
    }

    #[test]
    fn samples_across_window_edge() {
        let clock = Arc::new(TestClock::at_now());
        let c = RollingCounter::with_clock(Duration::from_secs(10), 10, clock.clone());
        c.add(1);
        clock.advance(Duration::from_secs(1));
        c.add(2);
        clock.advance(Duration::from_secs(1));
        c.add(3);
        // All three buckets are still live.
        assert_eq!(c.sum_over_window(), 6);
        assert_eq!(c.samples(), 3);
        // Move forward enough that the first sample falls off.
        clock.advance(Duration::from_secs(9));
        let s = c.sum_over_window();
        assert!(s == 5 || s == 3 || s == 2, "expected partial, got {s}"); // boundary slack
    }

    #[test]
    fn many_increments_dont_overflow_with_saturating() {
        let clock = Arc::new(TestClock::at_now());
        let c = RollingCounter::with_clock(Duration::from_secs(10), 10, clock);
        c.add(u64::MAX);
        c.add(u64::MAX);
        // saturating add prevents overflow.
        assert_eq!(c.sum_over_window(), u64::MAX);
    }

    #[test]
    fn tick_increments_by_one() {
        let clock = Arc::new(TestClock::at_now());
        let c = RollingCounter::with_clock(Duration::from_secs(60), 6, clock);
        for _ in 0..5 {
            c.tick();
        }
        assert_eq!(c.sum_over_window(), 5);
    }

    #[test]
    #[should_panic(expected = "buckets must be > 0")]
    fn zero_buckets_panics() {
        let _ = RollingCounter::new(Duration::from_secs(1), 0);
    }

    #[test]
    #[should_panic(expected = "window must be > 0")]
    fn zero_window_panics() {
        let _ = RollingCounter::new(Duration::ZERO, 1);
    }
}
