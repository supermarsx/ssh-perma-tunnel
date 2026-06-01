//! Embedded auto-updater for spt.
//!
//! # Overview
//!
//! `spt-updater` is the single owner of the *update lifecycle*: poll a
//! release source, compare versions, optionally download + verify + install
//! a newer artifact, and notify the supervisor to restart.
//!
//! **Disabled by default.** A fresh config with no `[updater]` block (or an
//! empty one) produces zero update activity. The operator opts in via
//! `[updater].enabled = true` to spawn the background thread, and via
//! `[updater].mode = "auto"` for hands-off install. The `spt update *`
//! CLI surface works regardless — `enabled` only gates the *background*
//! polling thread.
//!
//! # Threading model
//!
//! The supervisor spawns the updater on a dedicated OS thread via
//! [`Updater::spawn`]. That thread owns a current-thread tokio runtime
//! (`tokio::runtime::Builder::new_current_thread`) so the updater's I/O
//! never competes with forward / tunnel handlers for the main runtime's
//! worker threads. The handle returned by `spawn` exposes:
//!
//! * [`UpdaterHandle::request_check`] — trigger an immediate check
//!   (used by `spt update check` / `spt update now` over MCP).
//! * [`UpdaterHandle::status`] — snapshot of the last poll.
//! * [`UpdaterHandle::shutdown`] — graceful stop, used by the supervisor's
//!   own shutdown path.
//!
//! # Modules
//!
//! * [`config`] — typed view over `[updater]` with all defaults applied.
//! * [`source`] — backends (`github`, `url`, `static`).
//! * [`version`] — semver parsing + comparison with the rolling
//!   `0.YY.N` scheme.
//! * [`verify`] — minisign / SHA256SUMS / GPG verification.
//! * [`schedule`] — cron / interval next-tick computation.
//! * [`install`] — platform-specific atomic swap of the running binary.

#![warn(missing_docs)]
// Scaffold-stage allows. Real impls land in subsequent commits; these
// lints will become applicable then.
#![allow(clippy::unused_async)]
#![allow(clippy::map_unwrap_or)]

pub mod config;
pub mod error;
pub mod install;
pub mod schedule;
pub mod source;
pub mod verify;
pub mod version;

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub use crate::config::{SourceKind, UpdateMode, UpdaterConfig};
pub use crate::error::{UpdaterError, UpdaterResult};
pub use crate::source::{ReleaseInfo, ReleaseSource};
pub use crate::version::{CurrentVersion, Version};

/// Public status snapshot exposed to the CLI / MCP surface.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UpdaterStatus {
    /// Whether the supervisor has the background thread running.
    pub enabled: bool,
    /// Configured mode at startup (`off|check|warn|auto`).
    pub mode: UpdateMode,
    /// Last successful check timestamp, ISO-8601 UTC.
    pub last_check: Option<String>,
    /// Latest known release version, if a check has run.
    pub latest_version: Option<String>,
    /// Currently-running spt version (from `CARGO_PKG_VERSION`).
    pub current_version: String,
    /// Whether `latest_version > current_version`.
    pub update_available: bool,
    /// Path to the most recently staged artifact, if any.
    pub staged_artifact: Option<String>,
    /// Next scheduled check time, ISO-8601 UTC.
    pub next_check: Option<String>,
    /// Last error message, if the last poll failed.
    pub last_error: Option<String>,
}

impl UpdaterStatus {
    fn initial(cfg: &UpdaterConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            mode: cfg.mode,
            last_check: None,
            latest_version: None,
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            update_available: false,
            staged_artifact: None,
            next_check: None,
            last_error: None,
        }
    }
}

/// Control commands sent from the supervisor / CLI into the updater thread.
#[derive(Debug)]
enum Control {
    /// Immediate one-shot check (no install). Used by `spt update check`.
    CheckNow,
    /// Graceful shutdown.
    Shutdown,
}

/// Handle returned by [`Updater::spawn`]. The supervisor stores this in its
/// shutdown registry. Cloneable so the CLI dispatcher can call into the
/// running updater via MCP.
#[derive(Debug, Clone)]
pub struct UpdaterHandle {
    tx: mpsc::Sender<Control>,
    status: Arc<RwLock<UpdaterStatus>>,
}

impl UpdaterHandle {
    /// Snapshot the current status. O(1) clone of an `Arc<RwLock<_>>`.
    #[must_use]
    pub fn status(&self) -> UpdaterStatus {
        self.status.read().clone()
    }

    /// Trigger an immediate check. Returns once the request is *queued* —
    /// the actual poll happens on the updater thread.
    pub async fn request_check(&self) -> UpdaterResult<()> {
        self.tx
            .send(Control::CheckNow)
            .await
            .map_err(|_| UpdaterError::ThreadGone)
    }

    /// Request graceful shutdown. The supervisor's `shutdown()` path
    /// awaits this before joining the OS thread.
    pub async fn shutdown(&self) -> UpdaterResult<()> {
        // Best-effort: if the channel is closed, the thread already exited.
        let _ = self.tx.send(Control::Shutdown).await;
        Ok(())
    }
}

/// Top-level updater driver. Owns the polling loop and the status mirror.
#[derive(Debug)]
pub struct Updater {
    cfg: UpdaterConfig,
}

impl Updater {
    /// Spawn the updater on a dedicated OS thread with its own
    /// current-thread tokio runtime. Returns immediately with a handle
    /// the supervisor can poll / shut down.
    ///
    /// Returns `Ok(None)` when `cfg.enabled = false` or `cfg.mode = Off` —
    /// the supervisor must skip the spawn in that case (manual
    /// `spt update *` paths still work because they don't need the
    /// background thread). This is the load-bearing "off by default"
    /// behaviour.
    pub fn spawn(cfg: UpdaterConfig) -> UpdaterResult<Option<UpdaterHandle>> {
        if !cfg.enabled || matches!(cfg.mode, UpdateMode::Off) {
            info!(
                target: "spt_updater",
                enabled = cfg.enabled,
                mode = ?cfg.mode,
                "updater thread NOT spawned — feature is opt-in"
            );
            return Ok(None);
        }

        let status = Arc::new(RwLock::new(UpdaterStatus::initial(&cfg)));
        let (tx, rx) = mpsc::channel::<Control>(8);
        let handle = UpdaterHandle {
            tx,
            status: Arc::clone(&status),
        };
        let driver = Updater { cfg };

        // Dedicated OS thread + current-thread tokio runtime. We don't
        // join the spawned runtime onto the main supervisor runtime
        // because (a) the user explicitly asked for a dedicated thread,
        // and (b) updater I/O can be long-blocking (large downloads), so
        // isolating it keeps it from starving forward handlers.
        let thread_status = Arc::clone(&status);
        std::thread::Builder::new()
            .name("spt-updater".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                let rt = match rt {
                    Ok(rt) => rt,
                    Err(e) => {
                        warn!(
                            target: "spt_updater",
                            error = %e,
                            "failed to start updater tokio runtime"
                        );
                        thread_status.write().last_error = Some(format!("rt: {e}"));
                        return;
                    }
                };
                rt.block_on(driver.run(rx, thread_status));
            })
            .map_err(|e| UpdaterError::SpawnFailed(format!("thread::spawn: {e}")))?;

        Ok(Some(handle))
    }

    /// Async event loop. Lives on the updater thread's current-thread
    /// runtime. Walks the scheduler tick-by-tick, processes [`Control`]
    /// messages on every iteration.
    async fn run(self, mut rx: mpsc::Receiver<Control>, status: Arc<RwLock<UpdaterStatus>>) {
        let sched = schedule::Scheduler::from_config(&self.cfg);
        loop {
            // Compute next sleep window. Cap each individual sleep at 60s
            // so the loop checks the control channel often enough that a
            // shutdown request doesn't block on a multi-hour cron tick.
            let sleep_for = sched.next_tick_within(Duration::from_secs(60));
            tokio::select! {
                () = tokio::time::sleep(sleep_for) => {
                    if sched.should_fire_now() {
                        self.run_check(&status).await;
                    }
                }
                msg = rx.recv() => {
                    match msg {
                        Some(Control::CheckNow) => self.run_check(&status).await,
                        Some(Control::Shutdown) | None => {
                            info!(target: "spt_updater", "shutdown signal received");
                            return;
                        }
                    }
                }
            }
        }
    }

    /// One iteration of the poll/install cycle. Skipped when the body of
    /// the loop is unreachable in `Off` mode (we never spawn in that
    /// case), so this function assumes `mode != Off`.
    async fn run_check(&self, status: &Arc<RwLock<UpdaterStatus>>) {
        match poll_once(&self.cfg).await {
            Ok(outcome) => {
                let mut s = status.write();
                s.last_check = Some(outcome.checked_at.clone());
                s.latest_version = Some(outcome.latest_tag.clone());
                s.update_available = outcome.update_available;
                s.last_error = None;

                if outcome.update_available {
                    match self.cfg.mode {
                        UpdateMode::Warn | UpdateMode::Auto => {
                            warn!(
                                target: "spt_updater",
                                latest = %outcome.latest_tag,
                                current = %s.current_version,
                                "spt: a newer release is available"
                            );
                        }
                        _ => {
                            info!(
                                target: "spt_updater",
                                latest = %outcome.latest_tag,
                                current = %s.current_version,
                                "spt update check: newer release detected"
                            );
                        }
                    }
                    if matches!(self.cfg.mode, UpdateMode::Auto) {
                        // Auto install lands in a subsequent commit.
                        info!(
                            target: "spt_updater",
                            "mode = auto but install path is scaffolded; \
                             skipping until atomic-swap commit lands"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    target: "spt_updater",
                    error = %e,
                    "updater poll failed"
                );
                status.write().last_error = Some(e.to_string());
            }
        }
    }
}

/// Outcome of a one-shot poll. Public so the `spt update check` CLI
/// dispatcher can call into the same path the background loop uses.
#[derive(Debug, Clone)]
pub struct CheckOutcome {
    /// ISO-8601 UTC timestamp.
    pub checked_at: String,
    /// Latest tag from the source.
    pub latest_tag: String,
    /// Current spt version (from `CARGO_PKG_VERSION`).
    pub current_version: String,
    /// Whether `latest_tag > current_version`.
    pub update_available: bool,
}

/// Poll the configured source once. Used by both the background loop and
/// the manual `spt update check` CLI command. Returns the outcome (does
/// not mutate global state); the caller writes to whichever status
/// mirror it owns.
pub async fn poll_once(cfg: &UpdaterConfig) -> UpdaterResult<CheckOutcome> {
    let backend = source::build_source(cfg)?;
    let release = backend.latest().await?;
    let latest = version::Version::parse_tag(&release.tag)?;
    let current = version::CurrentVersion::from_build();
    let update_available = latest.is_newer_than(&current.0);
    Ok(CheckOutcome {
        checked_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        latest_tag: latest.to_tag_string(),
        current_version: current.0.to_tag_string(),
        update_available,
    })
}
