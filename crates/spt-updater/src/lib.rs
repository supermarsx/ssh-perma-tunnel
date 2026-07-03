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

pub mod audit;
pub mod config;
pub mod download;
pub mod error;
pub mod install;
pub mod schedule;
pub mod source;
pub mod staging;
#[cfg(feature = "testing")]
pub mod testing;
pub mod verify;
pub mod version;
pub mod window;

use std::path::Path;
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

/// A callback the supervisor registers so the updater can request a process
/// restart after a successful **auto** install. The updater crate holds no
/// handle to the running supervisor, so the restart mechanism must be injected
/// from the outside (see [`Updater::spawn_with_restart`]). Invoked on the
/// updater thread; implementations should be cheap and non-blocking (e.g. set
/// an atomic flag / send on a channel the supervisor watches).
pub type RestartHook = Arc<dyn Fn() + Send + Sync>;

/// Top-level updater driver. Owns the polling loop and the status mirror.
#[derive(Clone)]
pub struct Updater {
    cfg: UpdaterConfig,
    /// Optional supervisor-restart trigger for the `auto` path. `None` means
    /// `restart_supervisor = true` is a no-op (logged at WARN) until a hook is
    /// wired via [`Updater::spawn_with_restart`].
    restart_hook: Option<RestartHook>,
}

impl std::fmt::Debug for Updater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Updater")
            .field("cfg", &self.cfg)
            .field("restart_hook", &self.restart_hook.is_some())
            .finish()
    }
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
    ///
    /// This overload registers **no** restart hook, so an `auto` install with
    /// `restart_supervisor = true` installs the new binary and then WARNs that
    /// the restart is a no-op. Use [`Updater::spawn_with_restart`] to wire an
    /// actual restart.
    pub fn spawn(cfg: UpdaterConfig) -> UpdaterResult<Option<UpdaterHandle>> {
        Self::spawn_inner(cfg, None)
    }

    /// Like [`Updater::spawn`] but registers a [`RestartHook`] the `auto` path
    /// invokes after a successful install when
    /// `[updater.action].restart_supervisor` is set.
    pub fn spawn_with_restart(
        cfg: UpdaterConfig,
        restart_hook: RestartHook,
    ) -> UpdaterResult<Option<UpdaterHandle>> {
        Self::spawn_inner(cfg, Some(restart_hook))
    }

    fn spawn_inner(
        cfg: UpdaterConfig,
        restart_hook: Option<RestartHook>,
    ) -> UpdaterResult<Option<UpdaterHandle>> {
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
        let driver = Updater { cfg, restart_hook };

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
                    // Finding 6: honor the maintenance window. An auto-install
                    // outside the configured window is DEFERRED (a later tick
                    // inside the window installs it) rather than firing anytime.
                    if !auto_install_allowed(&self.cfg, chrono::Utc::now()) {
                        if let Some(w) = &self.cfg.window {
                            info!(
                                target: "spt_updater",
                                latest = %outcome.latest_tag,
                                allow_from = %w.allow_from,
                                allow_to = %w.allow_to,
                                timezone = %w.timezone,
                                "auto-update deferred: current time is outside the maintenance window"
                            );
                        }
                        return;
                    }
                    match apply_update(&self.cfg).await {
                        Ok(report) => {
                            info!(
                                target: "spt_updater",
                                version = %report.version,
                                artifact = %report.installed_from.display(),
                                "auto-update installed"
                            );
                            {
                                let mut s = status.write();
                                s.staged_artifact =
                                    Some(report.installed_from.display().to_string());
                                s.last_error = None;
                            }
                            // Finding 8: actually trigger the supervisor restart
                            // when configured. The updater crate has no handle to
                            // the supervisor, so the restart is performed via an
                            // injected hook; without one we WARN that the new
                            // binary only takes effect on the next manual restart.
                            if report.restart_requested {
                                match &self.restart_hook {
                                    Some(hook) => {
                                        info!(
                                            target: "spt_updater",
                                            "auto-update: invoking supervisor restart hook"
                                        );
                                        hook();
                                    }
                                    None => warn!(
                                        target: "spt_updater",
                                        "auto-update installed and restart_supervisor = true, but no \
                                         restart hook is wired — the new binary takes effect only \
                                         after a manual supervisor restart/reload (wire \
                                         Updater::spawn_with_restart)"
                                    ),
                                }
                            }
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

/// Whether an **auto** install is permitted at `now`, given the configured
/// maintenance window. Returns `true` when no window is configured, or when
/// `now` (evaluated in UTC) falls inside it. Only the background `auto` path
/// consults this — manual `spt update apply` is never window-gated.
#[must_use]
pub fn auto_install_allowed(cfg: &UpdaterConfig, now: chrono::DateTime<chrono::Utc>) -> bool {
    match &cfg.window {
        Some(w) => window::is_within_window(w, now),
        None => true,
    }
}

/// Run the configured `[updater.action].post_install_hook` after a successful
/// install (finding 7).
///
/// **Argv-only, no shell** — the hook path is executed directly via
/// [`std::process::Command`] with no arguments and NO shell interpretation, so
/// a hook path can never be a shell-injection vector (matches the event-command
/// sink's safety posture). The install version and staged-artifact path are
/// passed through the `SPT_UPDATE_VERSION` / `SPT_UPDATE_ARTIFACT` environment
/// variables (as documented). Returns the child's exit status, or an error if
/// the hook could not be spawned.
fn run_post_install_hook(
    hook: &Path,
    version: &str,
    artifact: &Path,
) -> UpdaterResult<std::process::ExitStatus> {
    std::process::Command::new(hook)
        .env("SPT_UPDATE_VERSION", version)
        .env("SPT_UPDATE_ARTIFACT", artifact)
        .status()
        .map_err(|e| UpdaterError::Install(format!("post_install_hook {}: {e}", hook.display())))
}

/// Post-install side effects shared by `apply_update` and the auto path:
/// run the post-install hook, record the audit trail, and prune staging.
/// All are best-effort — a failure here does not undo a completed install.
async fn post_install(cfg: &UpdaterConfig, version: &str, artifact: &Path) {
    // Finding 7: run the post-install hook (argv-only) if configured.
    if let Some(hook) = &cfg.action.post_install_hook {
        let hook = hook.clone();
        let version_s = version.to_string();
        let artifact_c = artifact.to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            run_post_install_hook(&hook, &version_s, &artifact_c)
        })
        .await;
        match result {
            Ok(Ok(status)) if status.success() => info!(
                target: "spt_updater",
                hook = %cfg.action.post_install_hook.as_ref().unwrap().display(),
                "post-install hook completed successfully"
            ),
            Ok(Ok(status)) => warn!(
                target: "spt_updater",
                hook = %cfg.action.post_install_hook.as_ref().unwrap().display(),
                code = status.code().unwrap_or(-1),
                "post-install hook exited with a non-zero status"
            ),
            Ok(Err(e)) => {
                warn!(target: "spt_updater", error = %e, "post-install hook failed to run");
            }
            Err(e) => {
                warn!(target: "spt_updater", error = %e, "post-install hook task join failed");
            }
        }
    }

    // Finding 15: record the install in the audit trail when notify_audit is set
    // so `spt update history` has data.
    if cfg.action.notify_audit {
        audit::record_install(&staging_dir(cfg), version, artifact);
    }

    // Finding 14: bound staging-dir growth to keep_last.
    if let Err(e) = staging::prune(&staging_dir(cfg), cfg.staging.keep_last) {
        warn!(target: "spt_updater", error = %e, "failed to prune staging directory");
    }
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
    // Finding 14: even the download-only path stages artifacts; prune so a
    // repeated `spt update download` cannot leak disk.
    if let Err(e) = staging::prune(&staging_dir(cfg), cfg.staging.keep_last) {
        warn!(target: "spt_updater", error = %e, "failed to prune staging directory");
    }
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

    let version = latest.to_tag_string();
    // Post-install: run the hook (finding 7), record audit history (finding 15),
    // prune staging (finding 14). Best-effort — never undoes a done install.
    post_install(cfg, &version, &staged.artifact).await;

    Ok(ApplyReport {
        version,
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

    // Finding 6: an `auto` install must be gated on the maintenance window.
    // Pre-fix `auto_install_allowed` did not exist and the window was ignored.
    #[test]
    fn auto_install_respects_window() {
        use chrono::TimeZone;
        let dist = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        let mut cfg = static_cfg(dist.path(), stage.path(), UpdateMode::Auto);
        cfg.window = Some(crate::config::WindowConfig {
            allow_from: "02:00".into(),
            allow_to: "04:00".into(),
            timezone: "UTC".into(),
        });
        let inside = chrono::Utc.with_ymd_and_hms(2026, 6, 11, 3, 0, 0).unwrap();
        let outside = chrono::Utc.with_ymd_and_hms(2026, 6, 11, 12, 0, 0).unwrap();
        assert!(
            auto_install_allowed(&cfg, inside),
            "inside window must install"
        );
        assert!(
            !auto_install_allowed(&cfg, outside),
            "outside window must defer"
        );
        // No window configured → always allowed.
        cfg.window = None;
        assert!(auto_install_allowed(&cfg, outside));
    }

    // Finding 7: the post-install hook must actually run (argv-only, no shell),
    // receiving the version + artifact via the documented env vars.
    #[cfg(unix)]
    #[test]
    fn post_install_hook_runs_on_success() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("marker");
        let hook = tmp.path().join("hook.sh");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\nprintf '%s|%s' \"$SPT_UPDATE_VERSION\" \"$SPT_UPDATE_ARTIFACT\" > '{}'\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        let artifact = tmp.path().join("spt-99.0-target.tar.gz");
        let status = run_post_install_hook(&hook, "99.0", &artifact).unwrap();
        assert!(status.success());
        let got = std::fs::read_to_string(&marker).unwrap();
        assert_eq!(got, format!("99.0|{}", artifact.display()));
    }

    #[test]
    fn post_install_hook_missing_path_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("no-such-hook");
        let err = run_post_install_hook(&missing, "1.0", tmp.path()).unwrap_err();
        assert_eq!(err.code(), "updater_install");
    }

    // Findings 14 + 15: the post-install side-effects must record the audit
    // trail (gated on notify_audit) and prune staging to keep_last.
    #[tokio::test]
    async fn post_install_records_history_and_prunes() {
        use std::time::{Duration, SystemTime};
        let stage = tempfile::tempdir().unwrap();
        let mut cfg = static_cfg(stage.path(), stage.path(), UpdateMode::Auto);
        cfg.action.notify_audit = true;
        cfg.action.post_install_hook = None;
        cfg.staging.keep_last = 2;

        // Seed 4 staged archives with increasing mtimes.
        for i in 0..4u64 {
            let p = stage.path().join(format!("spt-{i}-target.tar.gz"));
            std::fs::write(&p, b"x").unwrap();
            std::fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(i * 100))
                .unwrap();
        }
        let artifact = stage.path().join("spt-3-target.tar.gz");
        post_install(&cfg, "99.3", &artifact).await;

        // notify_audit = true → history recorded.
        let hist = crate::audit::read_history(stage.path());
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].version, "99.3");

        // keep_last = 2 → only the two newest archives remain.
        let archives = std::fs::read_dir(stage.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tar.gz"))
            .count();
        assert_eq!(archives, 2, "staging must be pruned to keep_last");

        // notify_audit = false → no further history appended.
        cfg.action.notify_audit = false;
        post_install(&cfg, "99.4", &artifact).await;
        assert_eq!(
            crate::audit::read_history(stage.path()).len(),
            1,
            "notify_audit=false must not append history"
        );
    }
}
