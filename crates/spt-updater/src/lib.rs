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
//! * [`download`] — target selection + artifact/signature staging.
//! * [`version`] — semver parsing + comparison with the rolling
//!   `0.YY.N` scheme.
//! * [`verify`] — SHA256SUMS + minisign (ed25519) verification.
//! * [`schedule`] — cron / interval next-tick computation.
//! * [`install`] — platform-specific atomic swap of the running binary.

#![warn(missing_docs)]

pub mod config;
pub mod download;
pub mod error;
pub mod install;
pub mod schedule;
pub mod source;
#[cfg(feature = "testing")]
pub mod testing;
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
                // Update the status mirror in a tight scope so the lock is
                // never held across the `apply_update().await` below.
                {
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
                    }
                }

                if outcome.update_available && matches!(self.cfg.mode, UpdateMode::Auto) {
                    match apply_update(&self.cfg).await {
                        Ok(report) => {
                            info!(
                                target: "spt_updater",
                                version = %report.version,
                                artifact = %report.installed_from.display(),
                                "auto-update installed; supervisor restart {}",
                                if report.restart_requested {
                                    "requested"
                                } else {
                                    "skipped"
                                }
                            );
                            let mut s = status.write();
                            s.staged_artifact = Some(report.installed_from.display().to_string());
                            s.last_error = None;
                        }
                        Err(e) => {
                            warn!(
                                target: "spt_updater",
                                error = %e,
                                "auto-update install failed"
                            );
                            status.write().last_error = Some(e.to_string());
                        }
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

/// Result of a full download → verify → install cycle.
#[derive(Debug, Clone)]
pub struct ApplyReport {
    /// The version that was installed (bare tag form).
    pub version: String,
    /// Path the new binary was installed from (the staged artifact).
    pub installed_from: std::path::PathBuf,
    /// Whether `[updater.action].restart_supervisor` asked for a restart.
    pub restart_requested: bool,
}

/// Resolve the staging directory: the configured dir, else a temp-dir
/// fallback under the OS temp (used for one-shot `spt update download`).
fn staging_dir(cfg: &UpdaterConfig) -> std::path::PathBuf {
    cfg.staging
        .dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("spt-updates"))
}

/// Download the latest artifact for this build's target into the staging
/// directory and verify it. Does **not** install. Used by `spt update
/// download` and as the first half of [`apply_update`].
pub async fn download_and_verify(cfg: &UpdaterConfig) -> UpdaterResult<download::Staged> {
    let backend = source::build_source(cfg)?;
    let release = backend.latest().await?;
    let dir = staging_dir(cfg);
    let staged = download::download_release(&release, download::TARGET, &dir).await?;

    let inputs = verify::VerifyInputs {
        expected_sha256: staged.expected_sha256.clone(),
        sha256sums_body: staged.sha256sums.clone(),
        artifact_name: Some(staged.name.clone()),
    };
    verify::verify_artifact(
        &cfg.verify,
        &staged.artifact,
        staged.signature.as_deref(),
        &inputs,
    )?;
    Ok(staged)
}

/// Full update cycle: poll → download → verify → atomic install. Returns the
/// install report; the caller (supervisor / CLI) decides whether to act on
/// `restart_requested`. The actual supervisor restart is the caller's job —
/// this crate has no handle to the running supervisor.
pub async fn apply_update(cfg: &UpdaterConfig) -> UpdaterResult<ApplyReport> {
    let backend = source::build_source(cfg)?;
    let release = backend.latest().await?;
    let latest = version::Version::parse_tag(&release.tag)?;
    let current = version::CurrentVersion::from_build();
    if !latest.is_newer_than(&current.0) {
        return Err(UpdaterError::Install(format!(
            "no newer release to apply (current {} >= latest {})",
            current.0.to_tag_string(),
            latest.to_tag_string()
        )));
    }

    let dir = staging_dir(cfg);
    let staged = download::download_release(&release, download::TARGET, &dir).await?;
    let inputs = verify::VerifyInputs {
        expected_sha256: staged.expected_sha256.clone(),
        sha256sums_body: staged.sha256sums.clone(),
        artifact_name: Some(staged.name.clone()),
    };
    verify::verify_artifact(
        &cfg.verify,
        &staged.artifact,
        staged.signature.as_deref(),
        &inputs,
    )?;

    install::install_atomic(&staged.artifact).await?;

    Ok(ApplyReport {
        version: latest.to_tag_string(),
        installed_from: staged.artifact,
        restart_requested: cfg.action.restart_supervisor,
    })
}

#[cfg(test)]
mod apply_tests {
    use super::*;
    use crate::config::{
        ActionConfig, ReleaseChannel, ScheduleKind, SourceKind, StagingConfig, VerifyConfig,
    };

    /// Build a static-source config rooted at a local dist dir, with
    /// verification disabled (best-effort) so the test exercises the
    /// download → install wiring without needing signing material.
    fn static_cfg(
        dist: &std::path::Path,
        stage: &std::path::Path,
        mode: UpdateMode,
    ) -> UpdaterConfig {
        UpdaterConfig {
            enabled: true,
            mode,
            schedule: ScheduleKind::Interval(Duration::from_secs(60)),
            source: SourceKind::Static {
                dir: dist.to_path_buf(),
            },
            verify: VerifyConfig {
                require_minisign: false,
                minisign_pubkey: None,
                require_sha256sums: false,
                gpg_pubkey: None,
            },
            action: ActionConfig {
                restart_supervisor: true,
                notify_audit: false,
                post_install_hook: None,
            },
            staging: StagingConfig {
                dir: Some(stage.to_path_buf()),
                keep_last: 1,
            },
            window: None,
        }
    }

    /// Lay out a `dist/` dir with a manifest + one artifact whose name embeds
    /// the running build's target so `select_artifact` matches it.
    fn lay_out_dist(dist: &std::path::Path, tag: &str, body: &[u8]) -> String {
        let target = download::TARGET;
        let art_name = format!("spt-{tag}-{target}.tar.gz");
        std::fs::write(dist.join(&art_name), body).unwrap();
        let manifest = serde_json::json!({
            "tag": tag,
            "published_at": "2099-01-01T00:00:00Z",
            "artifacts": [ { "name": art_name } ],
            "signatures": []
        });
        std::fs::write(
            dist.join("release-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        art_name
    }

    #[tokio::test]
    async fn apply_update_downloads_verifies_installs() {
        let dist = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        // A far-future tag so it is unconditionally "newer" than the build.
        lay_out_dist(dist.path(), "99.0", b"NEW BINARY BYTES");
        let cfg = static_cfg(dist.path(), stage.path(), UpdateMode::Auto);

        // current_exe is the test runner; install over an explicit sham
        // target instead by routing through download_and_verify + install_over.
        let staged = download_and_verify(&cfg).await.unwrap();
        assert!(staged.artifact.exists());

        let target = stage.path().join("installed-spt");
        std::fs::write(&target, b"OLD").unwrap();
        install::install_over(&staged.artifact, &target)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"NEW BINARY BYTES");
    }

    #[tokio::test]
    async fn apply_update_refuses_when_not_newer() {
        let dist = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        // Tag 0.0 is older than any real build version.
        lay_out_dist(dist.path(), "0.0", b"x");
        let cfg = static_cfg(dist.path(), stage.path(), UpdateMode::Auto);
        let err = apply_update(&cfg).await.unwrap_err();
        assert_eq!(err.code(), "updater_install");
    }

    #[tokio::test]
    async fn download_and_verify_fails_closed_on_required_sha_without_material() {
        let dist = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        lay_out_dist(dist.path(), "99.0", b"bytes");
        let mut cfg = static_cfg(dist.path(), stage.path(), UpdateMode::Auto);
        cfg.verify.require_sha256sums = true; // strict, no digest published
        let err = download_and_verify(&cfg).await.unwrap_err();
        assert_eq!(err.code(), "updater_verify");
    }

    #[test]
    fn channel_enum_round_trips_for_completeness() {
        // Guards against accidental removal of the prerelease arm.
        assert_ne!(ReleaseChannel::Stable, ReleaseChannel::Prerelease);
    }
}
