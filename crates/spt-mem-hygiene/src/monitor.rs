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
    /// Absolute RSS ceiling, in bytes, that triggers a WARN **independent of**
    /// the slope heuristic — the fast-path that catches a sudden spike or a
    /// fast leak the ~30-min window would miss. `0` disables the check
    /// (the conservative default: no absolute ceiling until an operator sets
    /// one). Rate-limited so a sustained breach is not a per-tick flood.
    pub rss_high_bytes: u64,
    /// Percentage of the cgroup memory limit (`0.0..=100.0`) at or above which
    /// the Linux cgroup-pressure watch logs a pre-OOM WARN. Default `90.0`.
    /// Ignored on non-Linux targets and when no cgroup limit is discoverable.
    pub cgroup_pressure_pct: f64,
    /// Enable the Linux cgroup memory-pressure watch (usage-vs-limit and
    /// `oom_kill`-delta). Default `true`; a transparent no-op off Linux and when
    /// `cgroupfs` is not mounted.
    pub cgroup_watch: bool,
}

impl Default for MemoryMonitorConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            window_samples: 30,
            growth_threshold_bytes: 64 * 1024 * 1024, // 64 MiB
            growth_rate_bytes_per_min: 2 * 1024 * 1024, // 2 MiB/min
            min_rising_fraction: 0.8,
            rss_high_bytes: 0, // disabled until configured
            cgroup_pressure_pct: 90.0,
            cgroup_watch: true,
        }
    }
}

/// How often a *sustained* pressure/ceiling condition is re-logged, in seconds,
/// so a long-lived breach neither floods per-tick nor goes silent forever.
const PRESSURE_REWARN_SECS: u64 = 300;

/// Only log a new RSS high-water mark once it exceeds the last-logged mark by at
/// least this many bytes, so slow growth does not produce a per-tick DEBUG flood.
const HWM_LOG_DELTA_BYTES: u64 = 32 * 1024 * 1024;

/// A memory-observability signal produced by [`Observer::observe`] on a tick.
/// Kept as data (rather than logging inline) so the decision logic is pure and
/// unit-testable; the monitor loop renders each variant to `tracing`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum MemorySignal {
    /// RSS crossed the absolute configured ceiling (WARN).
    RssHigh {
        rss_bytes: u64,
        threshold_bytes: u64,
        pct: f64,
    },
    /// A new RSS high-water mark worth recording (DEBUG trajectory).
    HighWaterMark { rss_bytes: u64, hwm_bytes: u64 },
    /// cgroup usage reached the configured fraction of its limit (WARN).
    CgroupPressure {
        usage: u64,
        limit: u64,
        pct: f64,
        psi_some_avg10: Option<f64>,
    },
    /// The cgroup `oom_kill` counter advanced — a confirmed OOM-kill (WARN).
    OomKill { total: u64, delta: u64 },
}

/// Per-tick observability state for the absolute-RSS ceiling, RSS high-water
/// mark, and Linux cgroup pressure/OOM signals. Separated from the slope
/// heuristic so it is deterministically testable without spawning a task.
pub(crate) struct Observer {
    cfg: MemoryMonitorConfig,
    rewarn_ticks: u64,
    tick_idx: u64,
    hwm: u64,
    last_hwm_logged: u64,
    last_pressure_warn_tick: Option<u64>,
    last_rss_high_warn_tick: Option<u64>,
    last_oom_kill: Option<u64>,
}

impl Observer {
    /// Build an observer for `cfg`, deriving the re-warn cadence from the (already
    /// clamped, non-zero) sample `interval`.
    pub(crate) fn new(cfg: MemoryMonitorConfig, interval: Duration) -> Self {
        let interval_secs = interval.as_secs().max(1);
        Self {
            cfg,
            rewarn_ticks: (PRESSURE_REWARN_SECS / interval_secs).max(1),
            tick_idx: 0,
            hwm: 0,
            last_hwm_logged: 0,
            last_pressure_warn_tick: None,
            last_rss_high_warn_tick: None,
            last_oom_kill: None,
        }
    }

    /// A rate-limited condition is "due" if it has never warned or at least
    /// `rewarn_ticks` have elapsed since the last warn.
    fn due(&self, last: Option<u64>) -> bool {
        match last {
            None => true,
            Some(t) => self.tick_idx.saturating_sub(t) >= self.rewarn_ticks,
        }
    }

    /// Evaluate this tick's `rss` (and optional cgroup snapshot) and return the
    /// signals to log. Mutates internal rate-limit / high-water state.
    pub(crate) fn observe(
        &mut self,
        rss: u64,
        cgroup: Option<&crate::cgroup::CgroupSnapshot>,
    ) -> Vec<MemorySignal> {
        self.tick_idx += 1;
        let mut out = Vec::new();

        // (P3) RSS high-water mark — records the climb even when nothing fires.
        if rss > self.hwm {
            self.hwm = rss;
            if self.hwm.saturating_sub(self.last_hwm_logged) >= HWM_LOG_DELTA_BYTES {
                self.last_hwm_logged = self.hwm;
                out.push(MemorySignal::HighWaterMark {
                    rss_bytes: rss,
                    hwm_bytes: self.hwm,
                });
            }
        }

        // (P3) Absolute RSS ceiling — fires on any tick, independent of slope.
        if self.cfg.rss_high_bytes > 0 && rss >= self.cfg.rss_high_bytes {
            if self.due(self.last_rss_high_warn_tick) {
                self.last_rss_high_warn_tick = Some(self.tick_idx);
                let pct = rss as f64 / self.cfg.rss_high_bytes as f64 * 100.0;
                out.push(MemorySignal::RssHigh {
                    rss_bytes: rss,
                    threshold_bytes: self.cfg.rss_high_bytes,
                    pct,
                });
            }
        } else {
            // Reset so the next breach warns immediately rather than waiting out
            // the previous cooldown.
            self.last_rss_high_warn_tick = None;
        }

        // (P2) Linux cgroup pressure + OOM-kill delta.
        if let Some(snap) = cgroup {
            if let Some(cur) = snap.oom_kill {
                if let Some(prev) = self.last_oom_kill {
                    if cur > prev {
                        out.push(MemorySignal::OomKill {
                            total: cur,
                            delta: cur - prev,
                        });
                    }
                }
                self.last_oom_kill = Some(cur);
            }

            if let Some(pct) = snap.usage_pct() {
                if pct >= self.cfg.cgroup_pressure_pct {
                    if self.due(self.last_pressure_warn_tick) {
                        self.last_pressure_warn_tick = Some(self.tick_idx);
                        out.push(MemorySignal::CgroupPressure {
                            usage: snap.current.unwrap_or(0),
                            limit: snap.limit.unwrap_or(0),
                            pct,
                            psi_some_avg10: snap.psi_some_avg10,
                        });
                    }
                } else {
                    self.last_pressure_warn_tick = None;
                }
            }
        }

        out
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

            // (P2) Linux cgroup memory-pressure reader. A transparent no-op off
            // Linux and when `cgroupfs` is not mounted / the watch is disabled.
            #[cfg(target_os = "linux")]
            let cgroup_reader: Option<crate::cgroup::CgroupReader> = if config.cgroup_watch {
                crate::cgroup::CgroupReader::detect()
            } else {
                None
            };
            #[cfg(not(target_os = "linux"))]
            let cgroup_reader: Option<crate::cgroup::CgroupReader> = None;

            // (P2/P3) fast-path observability state (absolute ceiling, high-water
            // mark, cgroup pressure/OOM), independent of the slope window.
            let mut observer = Observer::new(config, tick_period);

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

                // (P2/P3) fast-path signals: caught every tick, so a spike or a
                // near-limit cgroup is visible long before the 30-min slope
                // window could fire.
                let cgroup_snap = cgroup_reader
                    .as_ref()
                    .map(crate::cgroup::CgroupReader::snapshot);
                for sig in observer.observe(rss, cgroup_snap.as_ref()) {
                    match sig {
                        MemorySignal::HighWaterMark {
                            rss_bytes,
                            hwm_bytes,
                        } => {
                            tracing::debug!(
                                target: "spt_mem_hygiene",
                                rss_bytes,
                                hwm_bytes,
                                pid,
                                "RSS high-water mark"
                            );
                        }
                        MemorySignal::RssHigh {
                            rss_bytes,
                            threshold_bytes,
                            pct,
                        } => {
                            tracing::warn!(
                                target: "spt_mem_hygiene",
                                rss_bytes,
                                threshold_bytes,
                                pct,
                                pid,
                                "process RSS exceeded configured high-water threshold — \
                                 possible fast leak/spike"
                            );
                        }
                        MemorySignal::CgroupPressure {
                            usage,
                            limit,
                            pct,
                            psi_some_avg10,
                        } => {
                            tracing::warn!(
                                target: "spt_mem_hygiene",
                                usage,
                                limit,
                                pct,
                                psi_some_avg10 = ?psi_some_avg10,
                                pid,
                                "memory usage approaching cgroup limit — OOM-kill likely if it \
                                 continues"
                            );
                        }
                        MemorySignal::OomKill { total, delta } => {
                            tracing::warn!(
                                target: "spt_mem_hygiene",
                                oom_kill_total = total,
                                oom_kill_delta = delta,
                                pid,
                                "cgroup reported {delta} OOM-kill(s)"
                            );
                        }
                    }
                }

                // Re-arm once RSS has fallen back below the flagged baseline.
                if !armed && rss < flagged_baseline {
                    armed = true;
                }

                if armed {
                    if let Some(growth) = evaluate(&window, &config, pid) {
                        armed = false;
                        flagged_baseline = growth.baseline_rss_bytes;
                        task_shared.last_flagged.store(true, Ordering::Relaxed);
                        // audit-fix (monitor.rs RSS-growth detection): the slope
                        // heuristic previously fired the `emit` callback ONLY,
                        // so an operator watching logs saw nothing. Log at WARN
                        // as well so both the event bus and the log stream see a
                        // suspected leak.
                        tracing::warn!(
                            target: "spt_mem_hygiene",
                            rss_bytes = growth.rss_bytes,
                            baseline_rss_bytes = growth.baseline_rss_bytes,
                            growth_bytes = growth.growth_bytes,
                            growth_rate_bytes_per_min = growth.growth_rate_bytes_per_min,
                            window_secs = growth.window_secs,
                            samples = growth.samples,
                            pid = growth.pid,
                            "sustained RSS growth detected — suspected memory leak"
                        );
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
            ..MemoryMonitorConfig::default()
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

    // -----------------------------------------------------------------------
    // Observer: absolute RSS ceiling / high-water / cgroup pressure / OOM-kill
    // -----------------------------------------------------------------------

    use crate::cgroup::CgroupSnapshot;

    fn observer_cfg() -> MemoryMonitorConfig {
        // interval 60s => PRESSURE_REWARN_SECS/60 = 5 ticks between re-warns.
        MemoryMonitorConfig {
            interval: Duration::from_secs(60),
            rss_high_bytes: 500 * MIB,
            cgroup_pressure_pct: 90.0,
            ..MemoryMonitorConfig::default()
        }
    }

    fn snap(current: u64, limit: Option<u64>, oom_kill: Option<u64>) -> CgroupSnapshot {
        CgroupSnapshot {
            current: Some(current),
            limit,
            oom_kill,
            psi_some_avg10: None,
        }
    }

    #[test]
    fn observer_absolute_rss_threshold_fires_and_rate_limits() {
        let mut o = Observer::new(observer_cfg(), Duration::from_secs(60));

        // Below threshold: no RssHigh (a HighWaterMark is expected/allowed).
        assert!(!o
            .observe(400 * MIB, None)
            .iter()
            .any(|s| matches!(s, MemorySignal::RssHigh { .. })));

        // Cross threshold: exactly one RssHigh (HWM may also appear — filter it).
        let sigs = o.observe(600 * MIB, None);
        let rss_high: Vec<_> = sigs
            .iter()
            .filter(|s| matches!(s, MemorySignal::RssHigh { .. }))
            .collect();
        assert_eq!(rss_high.len(), 1, "one RssHigh on first breach: {sigs:?}");
        match rss_high[0] {
            MemorySignal::RssHigh {
                threshold_bytes,
                pct,
                ..
            } => {
                assert_eq!(*threshold_bytes, 500 * MIB);
                assert!((*pct - 120.0).abs() < 0.01, "pct was {pct}");
            }
            _ => unreachable!(),
        }

        // Sustained breach within the re-warn window (5 ticks): suppressed.
        for _ in 0..3 {
            let s = o.observe(600 * MIB, None);
            assert!(
                !s.iter().any(|x| matches!(x, MemorySignal::RssHigh { .. })),
                "must not re-warn every tick"
            );
        }
    }

    #[test]
    fn observer_rss_threshold_rearms_after_dropping_below() {
        let mut o = Observer::new(observer_cfg(), Duration::from_secs(60));
        assert!(o
            .observe(600 * MIB, None)
            .iter()
            .any(|s| matches!(s, MemorySignal::RssHigh { .. })));
        // Drop below: resets the rate-limit.
        assert!(!o
            .observe(100 * MIB, None)
            .iter()
            .any(|s| matches!(s, MemorySignal::RssHigh { .. })));
        // Re-breach warns immediately (no cooldown wait).
        assert!(o
            .observe(600 * MIB, None)
            .iter()
            .any(|s| matches!(s, MemorySignal::RssHigh { .. })));
    }

    #[test]
    fn observer_rss_threshold_disabled_when_zero() {
        let cfg = MemoryMonitorConfig {
            rss_high_bytes: 0,
            ..MemoryMonitorConfig::default()
        };
        let mut o = Observer::new(cfg, Duration::from_secs(60));
        let sigs = o.observe(10 * 1024 * MIB, None);
        assert!(
            !sigs
                .iter()
                .any(|s| matches!(s, MemorySignal::RssHigh { .. })),
            "rss_high_bytes=0 disables the ceiling"
        );
    }

    #[test]
    fn observer_high_water_mark_logs_on_new_max_beyond_delta() {
        let cfg = MemoryMonitorConfig {
            rss_high_bytes: 0, // isolate HWM
            ..MemoryMonitorConfig::default()
        };
        let mut o = Observer::new(cfg, Duration::from_secs(60));

        // First sample above the 32 MiB delta: HWM logged.
        let s = o.observe(100 * MIB, None);
        assert_eq!(
            s.iter()
                .filter(|x| matches!(x, MemorySignal::HighWaterMark { .. }))
                .count(),
            1
        );
        // A tiny new max (< 32 MiB above last logged): no HWM log.
        let s = o.observe(110 * MIB, None);
        assert!(!s
            .iter()
            .any(|x| matches!(x, MemorySignal::HighWaterMark { .. })));
        // A non-max (lower): no HWM log.
        let s = o.observe(50 * MIB, None);
        assert!(!s
            .iter()
            .any(|x| matches!(x, MemorySignal::HighWaterMark { .. })));
        // Cumulative climb crossing the delta from the last-logged mark: logs.
        let s = o.observe(140 * MIB, None);
        assert!(s
            .iter()
            .any(|x| matches!(x, MemorySignal::HighWaterMark { .. })));
    }

    #[test]
    fn observer_cgroup_pressure_fires_at_threshold() {
        let mut o = Observer::new(observer_cfg(), Duration::from_secs(60));

        // 80% of limit: below the 90% threshold — no pressure warn.
        let s = o.observe(1, Some(&snap(80, Some(100), Some(0))));
        assert!(!s
            .iter()
            .any(|x| matches!(x, MemorySignal::CgroupPressure { .. })));

        // 95% of limit: pressure warn.
        let s = o.observe(1, Some(&snap(95, Some(100), Some(0))));
        let p: Vec<_> = s
            .iter()
            .filter(|x| matches!(x, MemorySignal::CgroupPressure { .. }))
            .collect();
        assert_eq!(p.len(), 1, "pressure warn at 95%: {s:?}");
        match p[0] {
            MemorySignal::CgroupPressure {
                usage, limit, pct, ..
            } => {
                assert_eq!(*usage, 95);
                assert_eq!(*limit, 100);
                assert!((*pct - 95.0).abs() < 0.01);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn observer_cgroup_pressure_none_when_unlimited() {
        let mut o = Observer::new(observer_cfg(), Duration::from_secs(60));
        let s = o.observe(1, Some(&snap(u64::MAX / 2, None, Some(0))));
        assert!(!s
            .iter()
            .any(|x| matches!(x, MemorySignal::CgroupPressure { .. })));
    }

    #[test]
    fn observer_oom_kill_delta_logged() {
        let mut o = Observer::new(observer_cfg(), Duration::from_secs(60));

        // First reading establishes the baseline — no signal even if non-zero.
        let s = o.observe(1, Some(&snap(1, Some(1_000_000), Some(2))));
        assert!(!s.iter().any(|x| matches!(x, MemorySignal::OomKill { .. })));

        // Counter advances by 3: delta logged.
        let s = o.observe(1, Some(&snap(1, Some(1_000_000), Some(5))));
        let k: Vec<_> = s
            .iter()
            .filter(|x| matches!(x, MemorySignal::OomKill { .. }))
            .collect();
        assert_eq!(k.len(), 1);
        match k[0] {
            MemorySignal::OomKill { total, delta } => {
                assert_eq!(*total, 5);
                assert_eq!(*delta, 3);
            }
            _ => unreachable!(),
        }

        // No further advance: no signal.
        let s = o.observe(1, Some(&snap(1, Some(1_000_000), Some(5))));
        assert!(!s.iter().any(|x| matches!(x, MemorySignal::OomKill { .. })));
    }

    #[test]
    fn observer_pressure_rewarns_after_cooldown() {
        // rewarn_ticks = 300/60 = 5. Fire on tick 1, then not until tick 6.
        let mut o = Observer::new(observer_cfg(), Duration::from_secs(60));
        let fired = |s: &[MemorySignal]| {
            s.iter()
                .any(|x| matches!(x, MemorySignal::CgroupPressure { .. }))
        };

        assert!(
            fired(&o.observe(1, Some(&snap(95, Some(100), Some(0))))),
            "tick1 fires"
        );
        for tick in 2..=5 {
            assert!(
                !fired(&o.observe(1, Some(&snap(95, Some(100), Some(0))))),
                "tick{tick} suppressed"
            );
        }
        assert!(
            fired(&o.observe(1, Some(&snap(95, Some(100), Some(0))))),
            "tick6 re-warns after cooldown"
        );
    }
}
