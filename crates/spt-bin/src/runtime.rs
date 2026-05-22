#![allow(clippy::map_unwrap_or, clippy::redundant_closure_for_method_calls)]
//! Tokio runtime construction per `[runtime.threads]` (spec §17.2).
//!
//! The spec calls for dedicated worker counts for orchestrator / service /
//! logging / dns / observability / blocking pools. Tokio's `Builder` only
//! exposes a single worker-thread count and a single blocking-thread count;
//! `spt-bin` aligns the two configurable knobs to the spec's most relevant
//! totals (sum of orchestrator+service+observability for workers; the
//! configured blocking pool size for blocking). A future revision can replace
//! this with multiple `Runtime`s if dedicated isolation becomes required.

use spt_config::schema::RuntimeThreads;
use spt_core::{Error, Result};
use tokio::runtime::{Builder, Runtime};

/// Build a runtime suitable for short-lived commands when no config is loaded.
pub fn build_default_runtime() -> Result<Runtime> {
    Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_cpus_clamped(2, 8))
        .max_blocking_threads(32)
        .thread_name("spt-worker")
        .build()
        .map_err(|e| Error::RuntimeFailure(format!("tokio runtime build failed: {e}")))
}

/// Propagate the portable-mode state-directory anchor to a long-running
/// command's resolver. When portable mode is active and no explicit
/// `--state-dir` was supplied, returns the `<exe-dir>/data/state/` path.
/// Otherwise returns the explicit override or `None`.
#[must_use]
pub fn resolve_state_root(explicit: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    spt_state::portable::current().map(|ctx| ctx.state_dir())
}

/// `true` when `--portable` was supplied. Long-running commands consult
/// this to suppress journald (Linux) and the Windows Event Log writer,
/// and to skip `AppArmor` / `SELinux` profile loading.
#[must_use]
pub fn is_portable() -> bool {
    spt_state::portable::current().is_some()
}

/// Resolve the log-file path for portable deployments. Returns
/// `<exe-dir>/data/logs/spt.log` when portable mode is active, otherwise
/// `None` (so the caller falls back to `state_dir.join("spt.log")` or
/// the `[logging].file` override).
#[must_use]
pub fn portable_log_file() -> Option<std::path::PathBuf> {
    spt_state::portable::current().map(|ctx| ctx.logs_dir().join("spt.log"))
}

/// Build a runtime configured per `[runtime.threads]`.
pub fn build_runtime(cfg: &RuntimeThreadsConfig) -> Result<Runtime> {
    let workers = cfg.total_workers().max(1);
    let blocking = cfg.blocking.max(8);
    Builder::new_multi_thread()
        .enable_all()
        .worker_threads(workers)
        .max_blocking_threads(blocking)
        .thread_name("spt-worker")
        .build()
        .map_err(|e| Error::RuntimeFailure(format!("tokio runtime build failed: {e}")))
}

/// Distilled `[runtime.threads]` view consumed by [`build_runtime`].
#[derive(Debug, Clone, Copy)]
pub struct RuntimeThreadsConfig {
    pub orchestrator: usize,
    pub service: usize,
    pub logging: usize,
    pub dns: usize,
    pub observability: usize,
    pub blocking: usize,
}

impl RuntimeThreadsConfig {
    pub fn total_workers(&self) -> usize {
        // Sum the non-blocking pools; spec §17.2 treats orchestrator/service/
        // observability as primary worker consumers; logging and dns also
        // schedule async work.
        self.orchestrator + self.service + self.logging + self.dns + self.observability
    }

    pub fn from_schema(t: Option<&RuntimeThreads>) -> Self {
        let cores = num_cpus_clamped(2, 16);
        let default = Self {
            orchestrator: 1,
            service: cores.max(2),
            logging: 1,
            dns: 1,
            observability: 1,
            blocking: 32,
        };
        let Some(t) = t else { return default };
        Self {
            orchestrator: t
                .orchestrator_threads
                .map(|n| n as usize)
                .unwrap_or(default.orchestrator),
            service: t
                .service_threads
                .map(|n| n as usize)
                .unwrap_or(default.service),
            logging: t
                .logging_threads
                .map(|n| n as usize)
                .unwrap_or(default.logging),
            dns: t.dns_threads.map(|n| n as usize).unwrap_or(default.dns),
            observability: t
                .observability_threads
                .map(|n| n as usize)
                .unwrap_or(default.observability),
            blocking: t
                .blocking_worker_threads
                .map(|n| n as usize)
                .unwrap_or(default.blocking),
        }
    }
}

fn num_cpus_clamped(lo: usize, hi: usize) -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(lo)
        .clamp(lo, hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_threads_picks_sensible_values() {
        let c = RuntimeThreadsConfig::from_schema(None);
        assert!(c.total_workers() >= 4);
        assert!(c.blocking >= 8);
    }

    #[test]
    fn build_default_runtime_works() {
        let rt = build_default_runtime().unwrap();
        rt.block_on(async { 1 + 1 });
    }

    #[test]
    fn runtime_threads_total_workers_sums_all_pools() {
        let c = RuntimeThreadsConfig {
            orchestrator: 1,
            service: 2,
            logging: 3,
            dns: 4,
            observability: 5,
            blocking: 99,
        };
        assert_eq!(c.total_workers(), 1 + 2 + 3 + 4 + 5);
    }

    #[test]
    fn runtime_threads_from_schema_uses_explicit_overrides() {
        let t = RuntimeThreads {
            orchestrator_threads: Some(7),
            service_threads: Some(8),
            logging_threads: Some(9),
            dns_threads: Some(10),
            observability_threads: Some(11),
            blocking_worker_threads: Some(12),
            ..Default::default()
        };
        let c = RuntimeThreadsConfig::from_schema(Some(&t));
        assert_eq!(c.orchestrator, 7);
        assert_eq!(c.service, 8);
        assert_eq!(c.logging, 9);
        assert_eq!(c.dns, 10);
        assert_eq!(c.observability, 11);
        assert_eq!(c.blocking, 12);
        assert_eq!(c.total_workers(), 7 + 8 + 9 + 10 + 11);
    }

    #[test]
    fn runtime_threads_from_schema_fills_missing_fields_with_defaults() {
        let t = RuntimeThreads {
            orchestrator_threads: Some(42),
            ..Default::default()
        };
        let c = RuntimeThreadsConfig::from_schema(Some(&t));
        assert_eq!(c.orchestrator, 42);
        // Other fields fall back to defaults.
        assert!(c.service >= 2);
        assert_eq!(c.blocking, 32);
    }

    #[test]
    fn build_runtime_with_explicit_config_succeeds() {
        let cfg = RuntimeThreadsConfig {
            orchestrator: 1,
            service: 1,
            logging: 1,
            dns: 1,
            observability: 1,
            blocking: 8,
        };
        let rt = build_runtime(&cfg).unwrap();
        rt.block_on(async { 42 });
    }

    #[test]
    fn resolve_state_root_returns_explicit_override() {
        let explicit = std::path::PathBuf::from("/explicit/state");
        assert_eq!(resolve_state_root(Some(&explicit)), Some(explicit.clone()));
    }

    #[test]
    fn resolve_state_root_with_no_portable_returns_none() {
        // The OnceLock-backed portable context is process-global. In test
        // binaries that don't install one, the helper returns None and
        // callers fall back to BaseDirs resolution downstream.
        if spt_state::portable::current().is_some() {
            // Another test installed a context; honour it.
            return;
        }
        assert_eq!(resolve_state_root(None), None);
    }

    #[test]
    fn portable_log_file_consistent_with_portable_context() {
        let got = portable_log_file();
        let expected = spt_state::portable::current().map(|c| c.logs_dir().join("spt.log"));
        assert_eq!(got, expected);
    }

    #[test]
    fn is_portable_reflects_state_module() {
        assert_eq!(is_portable(), spt_state::portable::current().is_some());
    }

    #[test]
    fn build_runtime_clamps_workers_to_at_least_one() {
        let cfg = RuntimeThreadsConfig {
            orchestrator: 0,
            service: 0,
            logging: 0,
            dns: 0,
            observability: 0,
            blocking: 1,
        };
        // total_workers() returns 0; build_runtime clamps via max(1).
        let rt = build_runtime(&cfg).unwrap();
        rt.block_on(async { 1 + 1 });
    }
}
