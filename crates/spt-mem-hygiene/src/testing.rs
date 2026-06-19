//! Dependency-free test allocator for leak detection.
//!
//! [`CountingAllocator`] wraps the system allocator and tracks the number of
//! live bytes (allocated minus freed) plus an observed peak. It is intended to
//! be installed as the `#[global_allocator]` in **dedicated leak-test
//! binaries** so a test can run an operation N times and assert that the
//! net-live-byte delta is bounded rather than growing linearly with N.
//!
//! This module is gated behind `#[cfg(any(test, feature = "test-alloc"))]`.
//! Other crates' leak-test binaries reuse it by depending on
//! `spt-mem-hygiene` with `features = ["test-alloc"]`.
//!
//! ## Caveats
//!
//! * The global allocator is **process-global**, so only one test binary may
//!   install it, and counts include allocations made by the test harness and
//!   any background threads. Compare *deltas* across two iteration counts (e.g.
//!   1k vs 10k) rather than asserting an absolute floor, and allow generous
//!   slack for lazy statics / thread-locals.
//! * [`live_bytes`](CountingAllocator::live_bytes) can briefly read as a value
//!   captured between the size accounting and the underlying alloc/dealloc; it
//!   is intended for coarse leak assertions, not exact byte-for-byte balance at
//!   an arbitrary instant.
//!
//! ## Usage
//!
//! In a dedicated integration-test binary (e.g. `tests/it_leak_foo.rs`):
//!
//! ```ignore
//! use spt_mem_hygiene::testing::{CountingAllocator, COUNTING_ALLOCATOR};
//!
//! #[global_allocator]
//! static GLOBAL: CountingAllocator = COUNTING_ALLOCATOR;
//!
//! #[test]
//! fn op_does_not_leak() {
//!     fn run(iters: usize) -> usize {
//!         GLOBAL.reset_peak();
//!         let before = GLOBAL.live_bytes();
//!         for _ in 0..iters {
//!             // ... exercise the operation under test ...
//!         }
//!         GLOBAL.live_bytes().saturating_sub(before)
//!     }
//!     let small = run(1_000);
//!     let large = run(10_000);
//!     // A leak grows ~linearly with iterations; a clean op stays bounded.
//!     assert!(large <= small + 64 * 1024, "leak: 1k={small} 10k={large}");
//! }
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A `GlobalAlloc` that forwards to [`System`] while tracking live and peak
/// bytes. See the [module docs](self) for usage and caveats.
#[derive(Debug)]
pub struct CountingAllocator {
    live: AtomicUsize,
    peak: AtomicUsize,
}

/// A ready-to-install [`CountingAllocator`] instance. Assign it to a
/// `#[global_allocator] static` in a leak-test binary.
pub static COUNTING_ALLOCATOR: CountingAllocator = CountingAllocator::new();

impl CountingAllocator {
    /// Construct a zeroed allocator. `const` so it can initialise a `static`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    /// Current live bytes (sum of successful allocations minus deallocations).
    #[must_use]
    pub fn live_bytes(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// Highest [`live_bytes`](Self::live_bytes) observed since the last
    /// [`reset_peak`](Self::reset_peak) (or since construction).
    #[must_use]
    pub fn peak_bytes(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// Reset the peak watermark to the current live total.
    pub fn reset_peak(&self) {
        let now = self.live.load(Ordering::Relaxed);
        self.peak.store(now, Ordering::Relaxed);
    }

    /// Account for `size` freshly allocated bytes and bump the peak.
    fn record_alloc(&self, size: usize) {
        let now = self.live.fetch_add(size, Ordering::Relaxed) + size;
        // Monotonically raise the peak watermark (CAS loop; relaxed is fine
        // since we only need eventual correctness for a coarse test metric).
        let mut peak = self.peak.load(Ordering::Relaxed);
        while now > peak {
            match self
                .peak
                .compare_exchange_weak(peak, now, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(observed) => peak = observed,
            }
        }
    }

    /// Account for `size` freshly freed bytes.
    fn record_dealloc(&self, size: usize) {
        self.live.fetch_sub(size, Ordering::Relaxed);
    }
}

impl Default for CountingAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: every method forwards to the corresponding `System` allocator method
// with the same arguments and contracts; we only add atomic bookkeeping around
// successful (non-null) results. The accounting never dereferences the returned
// pointers and never changes the layout passed to `System`.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding `layout` unchanged to the system allocator.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            self.record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding `layout` unchanged to the system allocator.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            self.record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr`/`layout` come from a prior `alloc` of this allocator,
        // per the `GlobalAlloc` contract; forwarded unchanged to `System`.
        unsafe { System.dealloc(ptr, layout) };
        self.record_dealloc(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `ptr`/`layout` come from a prior allocation; `new_size` is a
        // valid resize request per the `GlobalAlloc` contract. Forwarded
        // unchanged to `System`.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if new_ptr.is_null() {
            // Reallocation failed: the original block is untouched, so the live
            // accounting is unchanged.
            return new_ptr;
        }
        // Success: the old `layout.size()` bytes are gone, `new_size` are live.
        let old = layout.size();
        if new_size >= old {
            self.record_alloc(new_size - old);
        } else {
            self.record_dealloc(old - new_size);
        }
        new_ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_dealloc_balance() {
        // Use a private (non-global) instance so the test is independent of
        // whatever global allocator the test binary installed.
        let a = CountingAllocator::new();
        assert_eq!(a.live_bytes(), 0);

        let layout = Layout::from_size_align(4096, 8).unwrap();
        // SAFETY: layout is valid and non-zero; pointer freed below with the
        // same layout.
        let p = unsafe { a.alloc(layout) };
        assert!(!p.is_null());
        assert_eq!(a.live_bytes(), 4096);
        assert!(a.peak_bytes() >= 4096);

        // SAFETY: `p`/`layout` are the pair returned/used by `a.alloc` above.
        unsafe { a.dealloc(p, layout) };
        assert_eq!(a.live_bytes(), 0, "alloc/dealloc must balance to zero");
        // Peak persists across the dealloc until reset.
        assert!(a.peak_bytes() >= 4096);
        a.reset_peak();
        assert_eq!(a.peak_bytes(), 0);
    }

    #[test]
    fn realloc_grow_and_shrink_accounting() {
        let a = CountingAllocator::new();
        let l1 = Layout::from_size_align(1024, 8).unwrap();
        // SAFETY: valid non-zero layout.
        let p = unsafe { a.alloc(l1) };
        assert!(!p.is_null());
        assert_eq!(a.live_bytes(), 1024);

        // Grow to 4096.
        // SAFETY: `p`/`l1` from the alloc above; new_size > 0.
        let p = unsafe { a.realloc(p, l1, 4096) };
        assert!(!p.is_null());
        assert_eq!(a.live_bytes(), 4096);

        // Shrink to 512. Layout now describes the 4096 block.
        let l2 = Layout::from_size_align(4096, 8).unwrap();
        // SAFETY: `p`/`l2` describe the current block; new_size > 0.
        let p = unsafe { a.realloc(p, l2, 512) };
        assert!(!p.is_null());
        assert_eq!(a.live_bytes(), 512);

        let l3 = Layout::from_size_align(512, 8).unwrap();
        // SAFETY: final free with the current layout.
        unsafe { a.dealloc(p, l3) };
        assert_eq!(a.live_bytes(), 0);
    }
}
