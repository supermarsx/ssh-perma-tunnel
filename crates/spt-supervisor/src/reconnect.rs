//! Reconnect backoff per spec §11.2.
//!
//! Algorithm: **full-jitter exponential backoff**:
//!
//! ```text
//! delay_n = uniform(0, min(max_delay, initial_delay * 2^n))
//! ```
//!
//! After a stable connection holds for `reset_after`, the attempt counter is
//! reset to zero on the next failure.

use std::time::Duration;

use rand::Rng;

/// Backoff configuration. Mirrors `[profiles.reconnect]`.
#[derive(Debug, Clone, Copy)]
pub struct BackoffConfig {
    /// First retry delay (ceiling).
    pub initial_delay: Duration,
    /// Cap on the exponentially-increasing delay.
    pub max_delay: Duration,
    /// Reset attempt counter after this much continuous uptime.
    pub reset_after: Duration,
    /// Jitter ratio (informational; full-jitter implementation always
    /// samples in `[0, ceiling)` regardless of this value).
    pub jitter: f32,
    /// Maximum attempts (`0` = unlimited).
    pub max_attempts: u32,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            reset_after: Duration::from_secs(120),
            jitter: 1.0,
            max_attempts: 0,
        }
    }
}

/// Stateful backoff calculator.
#[derive(Debug, Clone)]
pub struct Backoff {
    cfg: BackoffConfig,
    attempt: u32,
}

impl Backoff {
    /// New backoff at attempt 0.
    #[must_use]
    pub fn new(cfg: BackoffConfig) -> Self {
        Self { cfg, attempt: 0 }
    }

    /// Current attempt count (number of failures so far).
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Whether further attempts are allowed under `max_attempts`.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.cfg.max_attempts != 0 && self.attempt >= self.cfg.max_attempts
    }

    /// Reset attempt counter (call on stable uptime).
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Compute the next-attempt delay and bump the attempt counter.
    ///
    /// `rng` is taken explicitly so tests are deterministic.
    pub fn next_delay<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Duration {
        let n = self.attempt;
        self.attempt = self.attempt.saturating_add(1);
        ceiling_for_attempt(self.cfg.initial_delay, self.cfg.max_delay, n)
            .map(|c| sample_jitter(c, rng))
            .unwrap_or(Duration::ZERO)
    }

    /// Compute the next-attempt delay using thread-local rng.
    pub fn next_delay_default(&mut self) -> Duration {
        let mut r = rand::thread_rng();
        self.next_delay(&mut r)
    }
}

fn ceiling_for_attempt(initial: Duration, max: Duration, n: u32) -> Option<Duration> {
    let initial_ms = initial.as_millis() as u64;
    let max_ms = max.as_millis() as u64;
    if initial_ms == 0 {
        return Some(Duration::ZERO);
    }
    let factor: u64 = 1_u64.checked_shl(n.min(31))?;
    let ceiling_ms = initial_ms
        .saturating_mul(factor)
        .min(max_ms.max(initial_ms));
    Some(Duration::from_millis(ceiling_ms))
}

fn sample_jitter<R: Rng + ?Sized>(ceiling: Duration, rng: &mut R) -> Duration {
    let max_ms = ceiling.as_millis() as u64;
    if max_ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(rng.gen_range(0..=max_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn ceiling_doubles_until_cap() {
        let init = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        let cs: Vec<u64> = (0..10)
            .map(|n| ceiling_for_attempt(init, max, n).unwrap().as_secs())
            .collect();
        // 1, 2, 4, 8, 16, 32, then capped at 60.
        assert_eq!(cs[0], 1);
        assert_eq!(cs[1], 2);
        assert_eq!(cs[5], 32);
        assert!(cs.iter().skip(6).all(|&v| v == 60));
    }

    #[test]
    fn full_jitter_within_ceiling() {
        let mut rng = StdRng::seed_from_u64(42);
        let mut b = Backoff::new(BackoffConfig {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(8),
            ..Default::default()
        });
        for n in 0..20 {
            let d = b.next_delay(&mut rng);
            let cap =
                ceiling_for_attempt(Duration::from_secs(1), Duration::from_secs(8), n).unwrap();
            assert!(d <= cap, "attempt {n}: {d:?} > ceiling {cap:?}");
        }
    }

    #[test]
    fn reset_clears_attempt_counter() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut b = Backoff::new(BackoffConfig::default());
        for _ in 0..5 {
            let _ = b.next_delay(&mut rng);
        }
        assert_eq!(b.attempt(), 5);
        b.reset();
        assert_eq!(b.attempt(), 0);
    }

    #[test]
    fn max_attempts_exhausts() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut b = Backoff::new(BackoffConfig {
            max_attempts: 3,
            ..Default::default()
        });
        for _ in 0..3 {
            assert!(!b.exhausted());
            let _ = b.next_delay(&mut rng);
        }
        assert!(b.exhausted());
    }

    #[test]
    fn unlimited_max_attempts_never_exhausts() {
        let b = Backoff::new(BackoffConfig {
            max_attempts: 0,
            ..Default::default()
        });
        assert!(!b.exhausted());
    }
}

// ---------------------------------------------------------------------------
// t8-C1: in-process reconnect observer hook (testing only).
//
// The chaos test harness (`tests/chaos` + `spt-chaos-proxy`) needs to observe
// the reconnect attempt sequence (delay, attempt count, success, exhaustion)
// without scraping logs or events. We expose a global slot for a single
// `ReconnectObserver` implementation, gated on `cfg(test)` *or* the crate's
// `testing` feature so production builds carry no overhead and no extra
// symbol.
//
// The static is `std::sync::Mutex<Option<Arc<dyn ReconnectObserver>>>`. We
// always `.clone()` the `Arc` out under the lock and then drop the guard
// before invoking the trait method, so an observer that re-enters
// supervisor code (e.g. logs a tracing event that the same fixture is
// listening for) can't deadlock.
//
// Call-site wiring lives in `profile.rs::ProfileTask::next_backoff` and
// the session-failure / exhaustion arms. Those edits are minimum-invasive
// (three notify lines, no behaviour changes).
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "testing"))]
use std::sync::Arc;

/// Observer trait for chaos / harness tests. Implementations must be
/// `Send + Sync` because the supervisor invokes them from its
/// `ProfileTask` future, which may move across runtime workers.
#[cfg(any(test, feature = "testing"))]
pub trait ReconnectObserver: Send + Sync {
    /// Called once per scheduled reconnect attempt, *before* the sleep.
    /// `attempt` is 1-based (i.e. matches `ProfileEvent::ReconnectScheduled.attempt`).
    fn on_attempt(&self, attempt: u32, delay: Duration);
    /// Called when an attempt produced a healthy session.
    fn on_success(&self, attempt: u32);
    /// Called when `BackoffConfig::max_attempts` has been reached.
    fn on_max_exhausted(&self, attempt: u32);
}

#[cfg(any(test, feature = "testing"))]
static RECONNECT_OBSERVER: std::sync::Mutex<Option<Arc<dyn ReconnectObserver>>> =
    std::sync::Mutex::new(None);

/// Install (or replace) the process-wide reconnect observer. Returns the
/// previously installed observer, if any, so tests can stack/restore.
///
/// This is intentionally a plain function (not a builder method on
/// `ProfileSupervisor`) so the harness can wire it once at startup and
/// then drive multiple profiles without threading the observer through
/// every config struct.
#[cfg(any(test, feature = "testing"))]
pub fn install_test_hook(
    hook: Arc<dyn ReconnectObserver>,
) -> Option<Arc<dyn ReconnectObserver>> {
    let mut g = RECONNECT_OBSERVER.lock().expect("RECONNECT_OBSERVER poisoned");
    g.replace(hook)
}

/// Remove the currently installed reconnect observer, if any.
#[cfg(any(test, feature = "testing"))]
pub fn clear_test_hook() -> Option<Arc<dyn ReconnectObserver>> {
    let mut g = RECONNECT_OBSERVER.lock().expect("RECONNECT_OBSERVER poisoned");
    g.take()
}

/// Internal: snapshot the current observer (clones the `Arc`, drops the
/// guard) so the supervisor can notify without holding the lock across an
/// `.await` or user code.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn current_observer() -> Option<Arc<dyn ReconnectObserver>> {
    RECONNECT_OBSERVER
        .lock()
        .expect("RECONNECT_OBSERVER poisoned")
        .clone()
}

/// Production builds compile this no-op so call sites in `profile.rs` can
/// be unconditional. The optimiser strips it away.
#[cfg(not(any(test, feature = "testing")))]
#[inline(always)]
pub(crate) fn notify_attempt(_attempt: u32, _delay: Duration) {}
#[cfg(any(test, feature = "testing"))]
#[inline]
pub(crate) fn notify_attempt(attempt: u32, delay: Duration) {
    if let Some(obs) = current_observer() {
        obs.on_attempt(attempt, delay);
    }
}

#[cfg(not(any(test, feature = "testing")))]
#[inline(always)]
pub(crate) fn notify_success(_attempt: u32) {}
#[cfg(any(test, feature = "testing"))]
#[inline]
pub(crate) fn notify_success(attempt: u32) {
    if let Some(obs) = current_observer() {
        obs.on_success(attempt);
    }
}

#[cfg(not(any(test, feature = "testing")))]
#[inline(always)]
pub(crate) fn notify_max_exhausted(_attempt: u32) {}
#[cfg(any(test, feature = "testing"))]
#[inline]
pub(crate) fn notify_max_exhausted(attempt: u32) {
    if let Some(obs) = current_observer() {
        obs.on_max_exhausted(attempt);
    }
}

// ---- Public test-only re-exports of the notify_* helpers ----------------
//
// The internal `notify_*` functions are `pub(crate)` because production
// `profile.rs` call sites should be the only emitters. But the chaos
// harness in `tests/chaos` needs to fabricate synthetic events to verify
// its observer wiring without booting a full supervisor. We expose
// `notify_*_for_test` aliases under the `testing` feature for that.

/// Test-only: directly invoke `on_attempt` on the installed observer.
/// **Only available with `feature = "testing"`** (or in this crate's tests).
#[cfg(any(test, feature = "testing"))]
pub fn notify_attempt_for_test(attempt: u32, delay: Duration) {
    notify_attempt(attempt, delay);
}

/// Test-only: directly invoke `on_success` on the installed observer.
#[cfg(any(test, feature = "testing"))]
pub fn notify_success_for_test(attempt: u32) {
    notify_success(attempt);
}

/// Test-only: directly invoke `on_max_exhausted` on the installed observer.
#[cfg(any(test, feature = "testing"))]
pub fn notify_max_exhausted_for_test(attempt: u32) {
    notify_max_exhausted(attempt);
}

#[cfg(test)]
mod hook_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Default)]
    struct Counting {
        attempts: AtomicU32,
        successes: AtomicU32,
        exhausted: AtomicU32,
    }
    impl ReconnectObserver for Counting {
        fn on_attempt(&self, _: u32, _: Duration) {
            self.attempts.fetch_add(1, Ordering::SeqCst);
        }
        fn on_success(&self, _: u32) {
            self.successes.fetch_add(1, Ordering::SeqCst);
        }
        fn on_max_exhausted(&self, _: u32) {
            self.exhausted.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn install_then_notify_dispatches() {
        // Note: this test mutates process-wide state. Other hook-using
        // tests in this crate should serialize via a mutex or run with
        // `--test-threads=1` if added.
        let c = Arc::new(Counting::default());
        let prev = install_test_hook(c.clone());
        notify_attempt(1, Duration::from_millis(10));
        notify_success(1);
        notify_max_exhausted(7);
        assert_eq!(c.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(c.successes.load(Ordering::SeqCst), 1);
        assert_eq!(c.exhausted.load(Ordering::SeqCst), 1);
        // Restore.
        match prev {
            Some(p) => {
                install_test_hook(p);
            }
            None => {
                let _ = clear_test_hook();
            }
        }
    }
}
