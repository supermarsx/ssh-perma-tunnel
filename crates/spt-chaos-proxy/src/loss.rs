//! [`ChaosBehaviour::LossPct`](crate::ChaosBehaviour::LossPct) helpers.
//!
//! Uses `rand::thread_rng()`. Tests that care about determinism can stub
//! the percentage to 0 or 100 instead of mocking the rng.

use rand::Rng;

/// `true` ⇒ drop this chunk. `pct` is clamped to `[0, 100]`.
#[must_use]
pub fn should_drop(pct: u8) -> bool {
    let pct = pct.min(100);
    if pct == 0 {
        return false;
    }
    if pct >= 100 {
        return true;
    }
    let r: u8 = rand::thread_rng().gen_range(0..100);
    r < pct
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_never_drops() {
        for _ in 0..1000 {
            assert!(!should_drop(0));
        }
    }

    #[test]
    fn hundred_always_drops() {
        for _ in 0..1000 {
            assert!(should_drop(100));
        }
    }

    #[test]
    fn clamps_above_hundred() {
        for _ in 0..1000 {
            assert!(should_drop(250));
        }
    }
}
