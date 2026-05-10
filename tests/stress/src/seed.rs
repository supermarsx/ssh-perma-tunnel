//! Deterministic seeding for stress tests.
//!
//! Each test reads a fixed default seed which the operator may override via
//! the `SPT_STRESS_SEED` env var (decimal `u64`). All randomness in the
//! stress crate must flow through [`rng`] so re-runs with the same seed
//! reproduce the same connection ordering, payload sizes, etc.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Hardcoded fallback seed. Picked once and never changed.
pub const DEFAULT_SEED: u64 = 0x5057_5f53_7472_5353_u64;

/// Resolve the active seed: env override (`SPT_STRESS_SEED`, decimal) or the
/// hardcoded default.
#[must_use]
pub fn active_seed() -> u64 {
    match std::env::var("SPT_STRESS_SEED") {
        Ok(s) => s.parse::<u64>().unwrap_or(DEFAULT_SEED),
        Err(_) => DEFAULT_SEED,
    }
}

/// A fresh seeded `ChaCha20` RNG.
#[must_use]
pub fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(active_seed())
}
