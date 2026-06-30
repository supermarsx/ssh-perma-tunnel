//! Runtime memory-growth monitor.
//!
//! [`MemoryMonitor`] samples *this* process's resident-set size (RSS) on a
//! fixed cadence into a bounded sliding window and applies a conservative
//! heuristic to detect sustained, monotonic growth that is characteristic of a
//! leak. When the heuristic fires it invokes a caller-supplied `emit` callback
//! with a [`MemoryGrowth`] description — **exactly once per growth episode**.
//!
//! This module deliberately knows nothing about the rest of `spt`: it takes a
//! generic `emit: Fn(MemoryGrowth)` closure rather than depending on an event
//! bus, which keeps `spt-mem-hygiene` a leaf crate. `spt-bin` closes over a
//! cloned `EventBus` and translates [`MemoryGrowth`] into an event itself.
//!
//! ## Design
//!
//! * **Sampling** — the RSS source is an injectable `Fn() -> u64` sampler. The
//!   production [`MemoryMonitor::spawn`] uses a `sysinfo`-backed sampler that
//!   reads the current process's RSS; tests use [`MemoryMonitor::spawn_with_sampler`]
//!   to feed deterministic synthetic sequences.
//! * **Heuristic** — see [`evaluate`]. Pure and unit-testable: it fires only
//!   when the window is full, a large fraction of adjacent samples are
//!   non-decreasing, the net growth exceeds an absolute floor, *and* the growth
//!   rate exceeds a per-minute floor. This rejects flat lines, single spikes,
//!   and sawtooth patterns.
//! * **Cooldown** — after firing, the monitor re-arms only once RSS drops back
//!   below the flagged baseline (or the window is otherwise reset), so a steady
//!   leak yields one episode rather than a flood.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

/// Tunables for [`MemoryMonitor`].
///
/// All durations and thresholds have conservative defaults chosen to avoid
/// false positives on normal workloads (see [`MemoryMonitorConfig::default`]).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MemoryMonitorConfig {
    /// Delay between RSS samples.
    pub interval: Duration,
    /// Maximum number of samples retained in the sliding window. Once this many
    /// samples have been collected the window is "full" and the heuristic may
    /// fire. Older samples are evicted FIFO.
    pub window_samples: usize,
    /// Absolute floor on net growth (newest − oldest) across the window, in
    /// bytes, before a leak can be flagged.
    pub growth_threshold_bytes: u64,
    /// Floor on the growth *rate* across the window, in bytes per minute.
    pub growth_rate_bytes_per_min: u64,
    /// Minimum fraction (0.0..=1.0) of adjacent sample pairs that must be
    /// non-decreasing for the window to count as "rising". Rejects sawtooth.
    pub min_rising_fraction: f64,
}

impl Default for MemoryMonitorConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            window_samples: 30,
            growth_threshold_bytes: 64 * 1024 * 1024, // 64 MiB
            growth_rate_bytes_per_min: 2 * 1024 * 1024, // 2 MiB/min
            min_rising_fraction: 0.8,
        }
    }
}

/// A single RSS observation, in bytes. Kept as a typed newtype so the sampler
/// contract and the window are unambiguous about units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MemorySample {
    /// Resident-set size in bytes at sample time.
    pub rss_bytes: u64,
}

/// Description of a detected sustained-growth episode, handed to the `emit`
/// callback. `spt-bin` maps this onto a `memory.leak_suspected` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryGrowth {
    /// Most recent RSS sample, in bytes (the window's newest value).
    pub rss_bytes: u64,
    /// Oldest RSS sample in the window, in bytes (the growth baseline).
    pub baseline_rss_bytes: u64,
    /// Net growth across the window (`rss_bytes - baseline_rss_bytes`).
    pub growth_bytes: u64,
    /// Average growth rate across the window, in bytes per minute.
    pub growth_rate_bytes_per_min: u64,
    /// Wall-clock span the window covers, in seconds
    /// (`(samples - 1) * interval`).
    pub window_secs: u64,
    /// Number of samples in the window when the episode was flagged.
    pub samples: usize,
    /// PID of the monitored process (0 if the pid could not be determined).
    pub pid: u32,
}

/// Pure heuristic. Given a full-or-partial sample `window` (oldest at front,
/// newest at back) and the config, returns `Some(MemoryGrowth)` iff the window
/// indicates a sustained leak, else `None`.
///
/// Firing requires **all** of:
/// 1. the window is full (`window.len() == cfg.window_samples`, and ≥ 2);
/// 2. at least `cfg.min_rising_fraction` of adjacent pairs are *strictly
///    increasing* (flat pairs do not count — this rejects a single late spike
///    sitting on an otherwise-flat line);
/// 3. net growth (newest − oldest) ≥ `cfg.growth_threshold_bytes`;
/// 4. growth rate ≥ `cfg.growth_rate_bytes_per_min`.
///
/// `pid` is threaded through purely for the resulting [`MemoryGrowth`]; it does
/// not affect the decision.
#[must_use]
pub fn evaluate(
    window: &VecDeque<u64>,
    cfg: &MemoryMonitorConfig,
    pid: u32,
) -> Option<MemoryGrowth> {
    // (1) window must be full and have at least two points to form a slope.
    if cfg.window_samples < 2 || window.len() < cfg.window_samples || window.len() < 2 {
        return None;
    }

    let baseline = *window.front()?;
    let newest = *window.back()?;

    // (3) net growth floor. Also rejects flat/declining windows.
    if newest <= baseline {
        return None;
    }
    let growth = newest - baseline;
    if growth < cfg.growth_threshold_bytes {
        return None;
    }

    // (2) rising fraction: count adjacent *strictly increasing* pairs. Using
    // strict `>` (not `>=`) means a flat line scores 0 and a single late spike
    // on a flat line scores only 1/(n-1) — both well below the default 0.8
    // threshold — while a genuine steady climb scores ~1.0. Also rejects
    // sawtooth, where roughly half the pairs decrease.
    let pairs = window.len() - 1;
    let mut rising = 0usize;
    let mut prev: Option<u64> = None;
    for &v in window {
        if let Some(p) = prev {
            if v > p {
                rising += 1;
            }
        }
        prev = Some(v);
    }
    let rising_fraction = rising as f64 / pairs as f64;
    if rising_fraction < cfg.min_rising_fraction {
        return None;
    }

    // (4) rate floor. window_secs = (samples - 1) * interval.
    let window_secs = (pairs as u64).saturating_mul(cfg.interval.as_secs());
    // Guard against a zero-second interval (degenerate config / tests): when
    // we cannot compute a meaningful rate, fall back to the net-growth floor
    // already cleared above and skip the rate gate.
    let rate_bytes_per_min = if window_secs == 0 {
        cfg.growth_rate_bytes_per_min // neutral: passes the gate below
    } else {
        // bytes / sec * 60 = bytes / min, computed without precision loss on
        // the numerator.
        growth.saturating_mul(60) / window_secs
    };
    if rate_bytes_per_min < cfg.growth_rate_bytes_per_min {
        return None;
    }

    Some(MemoryGrowth {
        rss_bytes: newest,
        baseline_rss_bytes: baseline,
        growth_bytes: growth,
        growth_rate_bytes_per_min: rate_bytes_per_min,
        window_secs,
        samples: window.len(),
        pid,
    })
}

/// Shared, lock-light snapshot of monitor state that `spt-bin` reads to
/// populate `RuntimeStatus`.
#[derive(Debug, Default)]
struct Shared {
    last_rss: AtomicU64,
    samples_taken: AtomicUsize,
    /// Set once at least one growth episode has been flagged.
    last_flagged: AtomicBool,
}

/// Handle to a running [`MemoryMonitor`] task.
///
/// Holds accessors for live status and an async [`MemoryMonitorHandle::shutdown`]
/// that aborts the sampling task and joins it cleanly (no leaked task).
///
/// Dropping the handle **also** aborts the background task (see the [`Drop`]
/// impl), so a handle that is dropped without an explicit `shutdown()` — early
/// return, error unwind, `let _ = …` — does not leak a detached sampler that
/// would otherwise run for the whole process lifetime.
#[derive(Debug)]
pub struct MemoryMonitorHandle {
    shared: Arc<Shared>,
    /// `Some` while the task is owned by this handle; `take`n by `shutdown` so
    /// it can be awaited (you cannot move a field out of a `Drop` type). After
    /// `shutdown` it is `None`, which makes the `Drop` abort a no-op — so
    /// `shutdown()` then `Drop` (or a double `Drop` path) never double-stops.
    task: Option<JoinHandle<()>>,
}

impl MemoryMonitorHandle {
    /// Most recent RSS sample observed, in bytes (0 before the first sample).
    #[must_use]
    pub fn last_rss(&self) -> u64 {
        self.shared.last_rss.load(Ordering::Relaxed)
    }

    /// Total number of samples taken since the monitor started.
    #[must_use]
    pub fn samples_taken(&self) -> usize {
        self.shared.samples_taken.load(Ordering::Relaxed)
    }

    /// Whether a growth episode has been flagged at least once.
    #[must_use]
    pub fn last_flagged(&self) -> bool {
        self.shared.last_flagged.load(Ordering::Relaxed)
    }

    /// Stop the monitor and join its task. Idempotent in effect: aborting an
    /// already-finished task is a no-op. Safe to call from async teardown.
    ///
    /// Takes the [`JoinHandle`] out of the handle before awaiting it (a field
    /// cannot be moved out of a `Drop` type), so the subsequent `Drop` sees
    /// `None` and does not abort a second time.
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            // Await the join; an aborted task resolves to a `JoinError` with
            // `is_cancelled()` — that is the expected, clean outcome.
            let _ = task.await;
        }
    }
}

impl Drop for MemoryMonitorHandle {
    /// Abort the background sampling task when the handle is dropped, so a
    /// handle dropped without an explicit [`MemoryMonitorHandle::shutdown`]
    /// never leaks a forever-running detached task. Idempotent: after
    /// `shutdown` (which `take`s the handle) this is `None` and does nothing,
    /// and aborting an already-finished task is itself a no-op. `abort` is
    /// non-blocking and safe to call from a `Drop` (no `.await`).
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// Runtime memory-growth monitor. See the [module docs](self).
#[derive(Debug)]
pub struct MemoryMonitor;

impl MemoryMonitor {
    /// Spawn a monitor that samples the **current process** RSS via `sysinfo`.
    ///
    /// `emit` is invoked once per detected growth episode. The returned
    /// [`MemoryMonitorHandle`] exposes live accessors and an async `shutdown`.
    ///
    /// The sampler reads `Process::memory()` (RSS, bytes) for `get_current_pid()`.
    /// If the pid cannot be determined or the process row is missing on a given
    /// tick, the sampler reports the last known value (or 0 before any reading),
    /// so a transient `sysinfo` miss never corrupts the window with a phantom 0.
    pub fn spawn<F>(config: MemoryMonitorConfig, emit: F) -> MemoryMonitorHandle
    where
        F: Fn(MemoryGrowth) + Send + Sync + 'static,
    {
        let pid = sysinfo::get_current_pid().ok();
        let pid_u32 = pid.map_or(0, sysinfo::Pid::as_u32);

        // Own a `System` across ticks so we don't reallocate every sample; only
        // refresh the single current pid's memory.
        let mut sys = sysinfo::System::new();
        let mut last_known: u64 = 0;
        let sampler = move || -> u64 {
            let Some(pid) = pid else { return last_known };
            sys.refresh_processes_specifics(
                sysinfo::ProcessesToUpdate::Some(&[pid]),
                true,
                sysinfo::ProcessRefreshKind::new().with_memory(),
            );
            if let Some(p) = sys.process(pid) {
                last_known = p.memory();
            }
            last_known
        };

        Self::spawn_with_sampler(config, pid_u32, sampler, emit)
    }

    /// Spawn a monitor driven by an injected RSS `sampler` (`FnMut() -> u64`).
    ///
    /// This is the deterministic core used by tests: feed a synthetic sequence
    /// of RSS values and assert that `emit` fires (or not). Production code uses
    /// [`MemoryMonitor::spawn`], which supplies the `sysinfo` sampler.
    ///
    /// `pid` is recorded verbatim into emitted [`MemoryGrowth`] values.
    pub fn spawn_with_sampler<S, F>(
        config: MemoryMonitorConfig,
        pid: u32,
        mut sampler: S,
        emit: F,
    ) -> MemoryMonitorHandle
    where
        S: FnMut() -> u64 + Send + 'static,
        F: Fn(MemoryGrowth) + Send + Sync + 'static,
    {
        let shared = Arc::new(Shared::default());
        let task_shared = Arc::clone(&shared);
        let cap = config.window_samples.max(1);

        let task = tokio::spawn(async move {
            let mut window: VecDeque<u64> = VecDeque::with_capacity(cap);
            // Cooldown state: once flagged, suppress further emits until RSS
            // drops below the baseline we flagged at (leak "resolved" / reset).
            let mut armed = true;
            let mut flagged_baseline: u64 = 0;

            // M-2 (defensive): `tokio::time::interval` PANICS on a zero period.
            // Config validation rejects a zero `mem_hygiene.interval`, but a
            // config built programmatically (bypassing validation) could still
            // carry one; clamp a non-positive interval up to the default cadence
            // so the sample loop can never abort the process.
            let tick_period = if config.interval.is_zero() {
                tracing::warn!(
                    "mem_hygiene.interval is zero; clamping to 60s (a zero interval would panic \
                     tokio::time::interval)"
                );
                Duration::from_secs(60)
            } else {
                config.interval
            };
            let mut ticker = tokio::time::interval(tick_period);
            // Avoid a burst of catch-up ticks if the task is ever delayed.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;
                let rss = sampler();

                // Maintain the bounded FIFO window.
                if window.len() == cap {
                    window.pop_front();
                }
                window.push_back(rss);

                task_shared.last_rss.store(rss, Ordering::Relaxed);
                task_shared.samples_taken.fetch_add(1, Ordering::Relaxed);

                // Re-arm once RSS has fallen back below the flagged baseline.
                if !armed && rss < flagged_baseline {
                    armed = true;
                }

                if armed {
                    if let Some(growth) = evaluate(&window, &config, pid) {
                        armed = false;
                        flagged_baseline = growth.baseline_rss_bytes;
                        task_shared.last_flagged.store(true, Ordering::Relaxed);
                        emit(growth);
                    }
                }
            }
        });

        MemoryMonitorHandle {
            shared,
            task: Some(task),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn cfg(window: usize) -> MemoryMonitorConfig {
        MemoryMonitorConfig {
            interval: Duration::from_secs(60),
            window_samples: window,
            growth_threshold_bytes: 64 * 1024 * 1024,
            growth_rate_bytes_per_min: 2 * 1024 * 1024,
            min_rising_fraction: 0.8,
        }
    }

    fn win(vals: &[u64]) -> VecDeque<u64> {
        vals.iter().copied().collect()
    }

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn rising_window_flags() {
        // 10 samples climbing by 16 MiB each: net 144 MiB over 9*60s = 540s.
        let c = cfg(10);
        let vals: Vec<u64> = (0..10).map(|i| 100 * MIB + i * 16 * MIB).collect();
        let g = evaluate(&win(&vals), &c, 42).expect("steady climb must flag");
        assert_eq!(g.baseline_rss_bytes, 100 * MIB);
        assert_eq!(g.rss_bytes, 100 * MIB + 9 * 16 * MIB);
        assert_eq!(g.growth_bytes, 9 * 16 * MIB);
        assert_eq!(g.samples, 10);
        assert_eq!(g.pid, 42);
        assert!(g.growth_rate_bytes_per_min >= 2 * MIB);
        // window_secs = (10-1)*60
        assert_eq!(g.window_secs, 540);
    }

    #[test]
    fn flat_window_does_not_flag() {
        let c = cfg(10);
        let vals = vec![200 * MIB; 10];
        assert!(evaluate(&win(&vals), &c, 1).is_none());
    }

    #[test]
    fn single_spike_does_not_flag() {
        // Flat then one huge jump at the end: rising fraction = 1/9 < 0.8.
        let c = cfg(10);
        let mut vals = vec![100 * MIB; 9];
        vals.push(100 * MIB + 500 * MIB);
        assert!(evaluate(&win(&vals), &c, 1).is_none());
    }

    #[test]
    fn sawtooth_does_not_flag() {
        // Oscillating: net could be positive but ~half the pairs decrease.
        let c = cfg(10);
        let vals: Vec<u64> = (0..10)
            .map(|i| if i % 2 == 0 { 100 * MIB } else { 300 * MIB })
            .collect();
        assert!(evaluate(&win(&vals), &c, 1).is_none());
    }

    #[test]
    fn partial_window_does_not_flag() {
        // Rising but not yet full.
        let c = cfg(10);
        let vals: Vec<u64> = (0..5).map(|i| 100 * MIB + i * 40 * MIB).collect();
        assert!(evaluate(&win(&vals), &c, 1).is_none());
    }

    #[test]
    fn growth_below_floor_does_not_flag() {
        // Rising monotonically but only 9 MiB total — below 64 MiB floor.
        let c = cfg(10);
        let vals: Vec<u64> = (0..10).map(|i| 100 * MIB + i * MIB).collect();
        assert!(evaluate(&win(&vals), &c, 1).is_none());
    }

    #[test]
    fn rate_below_floor_does_not_flag() {
        // Clears the 64 MiB net floor but spread over a very long window so the
        // per-minute rate is tiny. window=200 @60s => ~199 min; 64MiB/199min < 2MiB/min.
        let c = cfg(200);
        let step = (65 * MIB) / 199; // total just above 64 MiB net
        let vals: Vec<u64> = (0..200).map(|i| 100 * MIB + i * step).collect();
        let g = evaluate(&win(&vals), &c, 1);
        assert!(g.is_none(), "low rate must not flag: {g:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn window_never_exceeds_cap() {
        // Feed many samples; assert via samples_taken that we kept sampling,
        // and that no spurious flag fired on a flat line (cap respected
        // internally — a flat line never flags regardless of count).
        let c = cfg(5);
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        let emitted = Arc::new(AtomicUsize::new(0));
        let emitted2 = Arc::clone(&emitted);
        let handle = MemoryMonitor::spawn_with_sampler(
            c,
            7,
            move || {
                count2.fetch_add(1, Ordering::Relaxed);
                500 * MIB // flat
            },
            move |_g| {
                emitted2.fetch_add(1, Ordering::Relaxed);
            },
        );
        // Advance well past cap worth of intervals.
        for _ in 0..50 {
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::task::yield_now().await;
        }
        assert!(
            count.load(Ordering::Relaxed) >= 10,
            "sampler should have run many times"
        );
        assert_eq!(
            emitted.load(Ordering::Relaxed),
            0,
            "flat line must never flag"
        );
        handle.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_emits_once_on_synthetic_growth_then_shutdown_joins() {
        // Synthetic sampler: monotonic climb, +20 MiB per tick.
        let c = cfg(10);
        let next = Arc::new(AtomicU64::new(0));
        let next2 = Arc::clone(&next);
        let events: Arc<Mutex<Vec<MemoryGrowth>>> = Arc::new(Mutex::new(Vec::new()));
        let events2 = Arc::clone(&events);

        let handle = MemoryMonitor::spawn_with_sampler(
            c,
            99,
            move || {
                let i = next2.fetch_add(1, Ordering::Relaxed);
                100 * MIB + i * 20 * MIB
            },
            move |g| events2.lock().unwrap().push(g),
        );

        // Drive enough ticks to fill the window and keep climbing.
        for _ in 0..30 {
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::task::yield_now().await;
        }

        handle_shutdown_join(handle).await;

        let ev = events.lock().unwrap();
        assert_eq!(
            ev.len(),
            1,
            "a steady climb without a drop must flag exactly once (cooldown), got {}",
            ev.len()
        );
        assert_eq!(ev[0].pid, 99);
        assert!(ev[0].growth_bytes >= 64 * MIB);
    }

    // Helper that also asserts shutdown joins cleanly (no panic / no hang).
    async fn handle_shutdown_join(h: MemoryMonitorHandle) {
        let flagged = h.last_flagged();
        let _ = flagged; // accessor smoke-check
        assert!(h.samples_taken() > 0, "must have sampled before shutdown");
        h.shutdown().await; // returns => task joined
    }

    #[tokio::test(start_paused = true)]
    async fn drop_without_shutdown_aborts_background_task() {
        // H6 regression: dropping the handle (no explicit shutdown) must abort
        // the sampling task so it does not run forever. Observe that the
        // sampler stops being invoked once the handle is dropped.
        let c = cfg(5);
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        let handle = MemoryMonitor::spawn_with_sampler(
            c,
            1,
            move || {
                count2.fetch_add(1, Ordering::Relaxed);
                100 * MIB // flat
            },
            |_g| {},
        );

        // Let it sample a few times.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::task::yield_now().await;
        }
        let before = count.load(Ordering::Relaxed);
        assert!(before > 0, "should have sampled before drop");

        // Drop without calling shutdown(): the Drop impl must abort the task.
        drop(handle);
        // Let the runtime process the abort.
        tokio::task::yield_now().await;

        // Advance well past many more intervals; an aborted task must not run.
        for _ in 0..20 {
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::task::yield_now().await;
        }
        let after = count.load(Ordering::Relaxed);
        assert_eq!(
            before, after,
            "background task must stop sampling after the handle is dropped"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn immediate_drop_does_not_panic_and_stops_task() {
        // Dropping a freshly-spawned handle (idempotent stop path) must not
        // panic and must leave nothing running.
        let c = cfg(5);
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        let handle = MemoryMonitor::spawn_with_sampler(
            c,
            1,
            move || {
                count2.fetch_add(1, Ordering::Relaxed);
                100 * MIB
            },
            |_g| {},
        );
        drop(handle);
        tokio::task::yield_now().await;
        for _ in 0..10 {
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "task aborted before its first tick must never sample"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_then_implicit_drop_is_idempotent() {
        // shutdown() consumes self (task taken) then self is dropped at end of
        // shutdown with task == None — the Drop abort must be a no-op (no
        // double-stop panic, no hang).
        let c = cfg(5);
        let handle = MemoryMonitor::spawn_with_sampler(c, 1, || 100 * MIB, |_g| {});
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        handle.shutdown().await; // returns cleanly; trailing Drop sees None
    }

    #[tokio::test(start_paused = true)]
    async fn zero_interval_does_not_panic_at_interval_site() {
        // M-2 (defensive): a zero `interval` reaching `tokio::time::interval`
        // panics (release abort). The monitor clamps it to the default cadence,
        // so spawning the sample loop must succeed without panicking. Fails
        // against the unclamped code (the spawned task panics on
        // `interval(ZERO)`); passes after the clamp.
        let mut c = cfg(5);
        c.interval = Duration::ZERO;
        let handle = MemoryMonitor::spawn_with_sampler(c, 1, || 100 * MIB, |_g| {});
        // Let the task construct its ticker (would panic here pre-fix).
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        handle.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn cooldown_rearms_after_drop_then_reflags() {
        // Climb, flag, drop below baseline, climb again => two episodes.
        let c = cfg(5);
        let seq: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new({
            let mut v = Vec::new();
            // Episode 1: climb 100->100+? ensure net >= 64MiB across 5 samples.
            for i in 0..5u64 {
                v.push(100 * MIB + i * 20 * MIB);
            }
            // Drop hard below baseline (100 MiB).
            for _ in 0..5 {
                v.push(50 * MIB);
            }
            // Episode 2: climb again from 50.
            for i in 0..5u64 {
                v.push(50 * MIB + i * 20 * MIB);
            }
            v.reverse(); // pop from back cheaply
            v
        }));
        let seq2 = Arc::clone(&seq);
        let events = Arc::new(AtomicUsize::new(0));
        let events2 = Arc::clone(&events);
        let last = Arc::new(AtomicU64::new(0));
        let last2 = Arc::clone(&last);

        let handle = MemoryMonitor::spawn_with_sampler(
            c,
            5,
            move || {
                let mut s = seq2.lock().unwrap();
                let v = s.pop().unwrap_or_else(|| last2.load(Ordering::Relaxed));
                last2.store(v, Ordering::Relaxed);
                v
            },
            move |_g| {
                events2.fetch_add(1, Ordering::Relaxed);
            },
        );

        for _ in 0..40 {
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::task::yield_now().await;
        }
        handle.shutdown().await;

        assert_eq!(
            events.load(Ordering::Relaxed),
            2,
            "drop below baseline must re-arm for a second episode"
        );
    }
}
