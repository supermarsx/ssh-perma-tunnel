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
}
