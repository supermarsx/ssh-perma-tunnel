//! Minimal property-test driver and shrinker for the spt workspace.
//!
//! This crate intentionally avoids `proptest` (its MSRV exceeds the
//! workspace's 1.83 floor) and rolls a small driver on top of `arbitrary`.
//!
//! # Model
//!
//! A *property* is a closure `&mut Unstructured -> arbitrary::Result<()>`
//! that returns `Ok(())` when the invariant holds and either returns an
//! `Err(arbitrary::Error::NotEnoughData)` (skipped — the seed didn't carry
//! enough bytes to construct a meaningful input) or **panics** when the
//! invariant fails. Panics are caught by the driver, which then runs a tiny
//! shrinker over the offending byte buffer.
//!
//! # Shrinker
//!
//! The shrinker is deliberately the simplest thing that works:
//!
//! 1. Halve the buffer (try keeping just the first half) — repeat while the
//!    failure reproduces.
//! 2. Byte removal — try removing one byte at a time, keep the smaller
//!    buffer iff the failure reproduces.
//!
//! We make no attempt to interpret the structure; we operate on the raw
//! seed bytes. This is enough to whittle a 512-byte failing seed down to a
//! handful of bytes for almost all of our property shapes.
//!
//! # Iteration count
//!
//! The default is 1 000 iterations per property. The environment variable
//! `SPT_PROPTEST_ITERS` can dial this up or down (e.g. for CI). A value of
//! 0 disables the property entirely (skip).

#![forbid(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use arbitrary::Unstructured;

/// Default number of iterations per property.
pub const DEFAULT_ITERS: usize = 1_000;

/// Environment-variable override for [`DEFAULT_ITERS`].
pub const ITERS_ENV: &str = "SPT_PROPTEST_ITERS";

/// Resolve the actual iteration count for a property run.
#[must_use]
pub fn iterations() -> usize {
    std::env::var(ITERS_ENV)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_ITERS)
}

/// A trait for byte-oriented shrinkers.
pub trait Shrinker {
    /// Try to produce a smaller seed that still triggers the predicate. The
    /// driver returns the *smallest* seed it could find.
    fn shrink<P>(&self, seed: Vec<u8>, predicate: P) -> Vec<u8>
    where
        P: FnMut(&[u8]) -> bool;
}

/// Halving + byte-removal shrinker.
///
/// Cheap, structure-blind, and good enough to bring a 512-byte failing seed
/// down to a handful of bytes for our parser-style invariants.
pub struct HalveAndRemoveShrinker;

impl Shrinker for HalveAndRemoveShrinker {
    fn shrink<P>(&self, seed: Vec<u8>, mut predicate: P) -> Vec<u8>
    where
        P: FnMut(&[u8]) -> bool,
    {
        let mut current = seed;

        // Phase 1: greedy halving.
        loop {
            if current.len() <= 1 {
                break;
            }
            let half = current.len() / 2;
            let candidate = &current[..half];
            if predicate(candidate) {
                current = candidate.to_vec();
            } else {
                break;
            }
        }

        // Phase 2: byte-by-byte removal. One pass is enough in practice.
        let mut i = 0;
        while i < current.len() {
            let mut candidate = current.clone();
            candidate.remove(i);
            if predicate(&candidate) {
                current = candidate;
            } else {
                i += 1;
            }
        }

        current
    }
}

/// Run a property closure against a deterministic seed corpus.
///
/// `name` is reported on failure. `prop` runs against an `Unstructured`
/// view of the per-iteration seed; it must `panic!` on invariant failure
/// or return an `arbitrary::Error` when the seed is too small.
///
/// Each iteration's seed is derived from a stable LCG over `iter_index`,
/// padded out to 512 bytes. The driver does not depend on `rand` so its
/// behavior is reproducible across machines and toolchain versions.
pub fn run_property<F>(name: &str, mut prop: F)
where
    F: FnMut(&mut Unstructured<'_>) -> arbitrary::Result<()>,
{
    let iters = iterations();
    if iters == 0 {
        eprintln!("[{name}] skipped (SPT_PROPTEST_ITERS=0)");
        return;
    }

    for i in 0..iters {
        let seed = derive_seed(i as u64, 512);

        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let mut u = Unstructured::new(&seed);
            prop(&mut u)
        }));

        match outcome {
            Ok(Ok(())) | Ok(Err(_)) => continue,
            Err(panic) => {
                // Reproduce + shrink.
                let shrinker = HalveAndRemoveShrinker;
                let smaller = shrinker.shrink(seed.clone(), |bytes| {
                    let r = catch_unwind(AssertUnwindSafe(|| {
                        let mut u = Unstructured::new(bytes);
                        prop(&mut u)
                    }));
                    matches!(r, Err(_))
                });

                let msg = panic_message(&panic);
                panic!(
                    "property `{name}` failed at iteration {i}\n  \
                     original seed len: {}\n  \
                     shrunk seed: len={} bytes={:02x?}\n  \
                     panic: {msg}",
                    seed.len(),
                    smaller.len(),
                    smaller,
                );
            }
        }
    }
}

/// Deterministic seed derivation.
///
/// We use `splitmix64` — small, dependency-free, and gives well-distributed
/// bytes from a single `u64` index.
fn derive_seed(index: u64, bytes: usize) -> Vec<u8> {
    let mut state = index
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0xBF58_476D_1CE4_E5B9);
    let mut out = Vec::with_capacity(bytes);
    while out.len() < bytes {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        out.extend_from_slice(&z.to_le_bytes());
    }
    out.truncate(bytes);
    out
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shrinker_halves_to_minimum() {
        // Predicate: "any non-empty slice".
        let s = HalveAndRemoveShrinker;
        let small = s.shrink(vec![0u8; 64], |b| !b.is_empty());
        assert_eq!(small.len(), 1);
    }

    #[test]
    fn shrinker_removes_until_failure_lost() {
        // Predicate: "contains byte 0xAA".
        let mut seed = vec![0u8; 32];
        seed[20] = 0xAA;
        let s = HalveAndRemoveShrinker;
        let small = s.shrink(seed, |b| b.contains(&0xAA));
        assert_eq!(small, vec![0xAA]);
    }

    #[test]
    fn driver_passes_when_property_holds() {
        // Trivial always-Ok property; iteration count irrelevant — we just
        // verify the driver doesn't panic.
        run_property("trivial", |_u| Ok(()));
    }
}
