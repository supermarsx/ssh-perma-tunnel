//! Windows SCM service-main entry point.
//!
//! When SCM starts the service, the `ImagePath` written by
//! `WindowsScmManager::install` includes `--scm-dispatch`. `main()` detects
//! that flag *before* clap parses `Cli` (since clap doesn't know about it)
//! and short-circuits into [`enter_scm_dispatch`].
//!
//! Inside, [`spt_service::windows_scm::run_as_service`] hands us a
//! [`spt_service::windows_scm::ScmHandles`] with two `tokio::sync::Notify`
//! channels (`shutdown` + `reload`). We build a tokio runtime, bring up the
//! `Orchestrator` exactly like `tunnel_run` does, then `select!` on the two
//! notifies — `shutdown` triggers `Orchestrator::shutdown`, `reload`
//! triggers a config re-read + `ReloadPlan::apply`.
//!
//! The closure runs on a `std::thread`-spawned worker (see
//! `spt-service/src/windows_scm.rs`), so we must own a freshly built tokio
//! runtime ourselves — we cannot reuse `main()`'s runtime (which is on a
//! different thread and is also short-lived in the dispatch path).
//!
//! # Note on duplication with `cli_dispatch::tunnel_run`
//!
//! The orchestrator-bringup + reload pump duplicates ~80 lines of
//! `cli_dispatch::tunnel_run`. The lock arrangement (this executor owns
//! `scm_dispatch.rs`; the parallel `f-live-bridge` executor owns
//! `cli_dispatch.rs`) prevents factoring it out today. Tracked in the
//! `f-scm-dispatch` log for a follow-up cleanup.

#[cfg(target_os = "windows")]
use std::path::PathBuf;

use spt_core::{Error, Result};

/// Sentinel argv flag that selects the SCM dispatch path. Detected in
/// `main()` before `Cli::parse_args` so clap never sees it.
pub const SCM_DISPATCH_FLAG: &str = "--scm-dispatch";

/// Detect the `--scm-dispatch` argv flag without consulting clap.
#[must_use]
pub fn is_scm_dispatch_invocation() -> bool {
    std::env::args().any(|a| a == SCM_DISPATCH_FLAG)
}

/// Enter the SCM service-main loop.
///
/// On Windows, hands control to `spt-service`'s `run_as_service`, which
/// blocks until SCM tells the service to stop. On non-Windows targets,
/// returns `UnsupportedPlatform` — `--scm-dispatch` is meaningless there.
///
/// `service_name` is passed to `service_dispatcher::start`. For
/// `SERVICE_WIN32_OWN_PROCESS` (which we use), Windows ignores the name and
/// the dispatcher always picks up the running service, so a fixed `"spt"`
/// is fine even though installed services may be named `spt-<config>`.
#[cfg(target_os = "windows")]
pub fn enter_scm_dispatch(service_name: &'static str) -> Result<()> {
    use spt_service::windows_scm;
    windows_scm::run_as_service(service_name, |scm_args, handles| {
        // SCM start arguments are `lpServiceArgVectors` — typically just the
        // service name itself. The real `--config <path>` lives on the
        // *process* argv (from ImagePath), which we re-parse below. Logging
        // this for diagnostic completeness.
        tracing::info!(
            scm_args = ?scm_args,
            "spt service-main entered; building tokio runtime"
        );

        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("spt-scm-worker")
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!(error = %e, "spt service-main: failed to build tokio runtime");
                return;
            }
        };

        if let Err(e) = rt.block_on(scm_main(handles)) {
            tracing::error!(error = %e, "spt service-main returned with error");
        }
        // Drop the runtime to flush any pending tasks.
        rt.shutdown_timeout(std::time::Duration::from_secs(5));
    })
}

/// Non-Windows stub. Always returns `UnsupportedPlatform`.
#[cfg(not(target_os = "windows"))]
pub fn enter_scm_dispatch(_service_name: &'static str) -> Result<()> {
    Err(Error::UnsupportedPlatform(
        "--scm-dispatch is Windows-only".into(),
    ))
}

// ============================================================================
// Windows-only orchestrator wiring.
// ============================================================================

#[cfg(target_os = "windows")]
async fn scm_main(handles: std::sync::Arc<spt_service::windows_scm::ScmHandles>) -> Result<()> {
    let (config, state_dir) = parse_scm_args();
    tracing::info!(
        ?config,
        ?state_dir,
        "spt service: parsed argv-derived options"
    );

    let path = config.ok_or_else(|| {
        Error::InvalidArgs(
            "no config path supplied to --scm-dispatch (set $SPT_CONFIG or pass --config)"
                .into(),
        )
    })?;

    run_orchestrator_under_scm(state_dir.as_deref(), &path, handles).await
}

/// Heart of SCM dispatch: bring up the orchestrator, then `select!` on
/// `handles.shutdown` and `handles.reload` until SCM tells us to stop.
///
/// Mirrors `cli_dispatch::tunnel_run` closely; see the duplication note in
/// the module-level rustdoc.
#[cfg(target_os = "windows")]
async fn run_orchestrator_under_scm(
    explicit_state_dir: Option<&std::path::Path>,
    config_path: &std::path::Path,
    handles: std::sync::Arc<spt_service::windows_scm::ScmHandles>,
) -> Result<()> {
    let (cfg, _w) = spt_config::load(config_path, false)
        .map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    let state_dir = resolve_scm_state_dir(explicit_state_dir, &cfg)?;
    let _lock = spt_state::StateLock::acquire(&state_dir)?;

    let writer_cfg = spt_state::StatusWriterConfig::default();
    let writer = spt_state::StatusWriter::new(state_dir.clone(), writer_cfg);
    writer
        .update(|s| {
            s.pid = std::process::id();
            s.version = env!("CARGO_PKG_VERSION").into();
            s.config_fingerprint_sha256 = spt_config::fingerprint::fingerprint_hex(&cfg);
            s.started_at = Some(chrono::Utc::now());
            s.profiles = cfg
                .profiles
                .iter()
                .map(|p| spt_state::status::ProfileStatus {
                    id: p.name.clone(),
                    state: "starting".into(),
                    ..Default::default()
                })
                .collect();
        })
        .await;
    let writer_handle = writer.clone().spawn();

    let resolver = crate::secrets_bridge::build_resolver(cfg.secrets.as_ref(), &state_dir)?;
    let orchestrator = std::sync::Arc::new(spt_supervisor::Orchestrator::new());
    for profile in &cfg.profiles {
        if profile.enabled == Some(false) {
            tracing::info!(profile = %profile.name, "profile disabled — skipping");
            continue;
        }
        match crate::profile_factory::build(profile, &resolver) {
            Ok(bundle) => {
                tracing::info!(
                    profile = %profile.name,
                    protocol = %profile.protocol,
                    endpoints = bundle.endpoints.len(),
                    "spt service: starting profile"
                );
                orchestrator.start_profile(
                    profile,
                    bundle.protocol,
                    bundle.auth,
                    bundle.endpoints,
                    bundle.supervisor_cfg,
                );
            }
            Err(e) => {
                tracing::error!(
                    profile = %profile.name,
                    error = %e,
                    "spt service: failed to build profile"
                );
                writer
                    .update(|s| {
                        if let Some(p) = s.profiles.iter_mut().find(|p| p.id == profile.name) {
                            p.state = "failed".into();
                            p.last_error_category = Some(format!("{:?}", e.exit_code()));
                        }
                    })
                    .await;
            }
        }
    }
    writer
        .update(|s| {
            for p in &mut s.profiles {
                if p.state == "starting" {
                    p.state = "running".into();
                }
            }
        })
        .await;
    writer.flush().await?;

    tracing::info!("spt service: orchestrator running; awaiting SCM signals");

    let mut current_cfg = cfg;
    loop {
        tokio::select! {
            () = handles.shutdown.notified() => {
                tracing::info!("spt service: shutdown signal received from SCM");
                break;
            }
            () = handles.reload.notified() => {
                tracing::info!("spt service: reload (PARAMCHANGE) requested — re-reading config");
                match scm_reload(config_path, &resolver, &orchestrator, &current_cfg).await {
                    Ok(new_cfg) => {
                        let fp = spt_config::fingerprint::fingerprint_hex(&new_cfg);
                        writer.update(|s| { s.config_fingerprint_sha256 = fp; }).await;
                        current_cfg = new_cfg;
                        tracing::info!("spt service: reload applied");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "spt service: reload failed; keeping previous config");
                    }
                }
            }
        }
    }

    tracing::info!("spt service: shutting down orchestrator");
    orchestrator.shutdown().await;
    writer.flush().await?;
    writer_handle.stop().await;
    tracing::info!("spt service: clean exit");
    Ok(())
}

/// Re-read config from disk and apply a [`spt_supervisor::ReloadPlan`] —
/// duplicated from `cli_dispatch::reload_orchestrator` because the latter
/// lives in a locked file.
#[cfg(target_os = "windows")]
async fn scm_reload(
    path: &std::path::Path,
    resolver: &spt_secrets::Resolver,
    orch: &spt_supervisor::Orchestrator,
    old_cfg: &spt_config::schema::Config,
) -> Result<spt_config::schema::Config> {
    let (new_cfg, _) = spt_config::load(path, false)
        .map_err(|e| Error::InvalidConfig(format!("reload load: {e}")))?;
    let diags = spt_config::validate(&new_cfg);
    if !diags.errors.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "reload validation failed ({} errors)",
            diags.errors.len()
        )));
    }
    let plan = spt_supervisor::ReloadPlan::compute(old_cfg, &new_cfg);
    let new_for_provider = new_cfg.clone();
    orch.apply(&plan, |name| {
        let p = new_for_provider
            .profiles
            .iter()
            .find(|p| p.name == name)?
            .clone();
        let bundle = crate::profile_factory::build(&p, resolver).ok()?;
        Some((
            p,
            bundle.protocol,
            bundle.auth,
            bundle.endpoints,
            bundle.supervisor_cfg,
        ))
    })
    .await;
    Ok(new_cfg)
}

/// Walk the **process** argv (not SCM args) for `--config <path>` and
/// `--state-dir <path>`, plus their env-var equivalents. We can't call
/// `Cli::parse_args` here because clap doesn't know about `--scm-dispatch`.
/// Any unrecognised flag is ignored — the SCM path only cares about
/// config + `state_dir`.
#[cfg(target_os = "windows")]
fn parse_scm_args() -> (Option<PathBuf>, Option<PathBuf>) {
    let mut config: Option<PathBuf> = std::env::var_os("SPT_CONFIG").map(PathBuf::from);
    let mut state_dir: Option<PathBuf> = std::env::var_os("SPT_STATE_DIR").map(PathBuf::from);

    let mut iter = std::env::args().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--config" | "-c" => {
                if let Some(v) = iter.next() {
                    config = Some(PathBuf::from(v));
                }
            }
            s if s.starts_with("--config=") => {
                config = Some(PathBuf::from(&s["--config=".len()..]));
            }
            "--state-dir" => {
                if let Some(v) = iter.next() {
                    state_dir = Some(PathBuf::from(v));
                }
            }
            s if s.starts_with("--state-dir=") => {
                state_dir = Some(PathBuf::from(&s["--state-dir=".len()..]));
            }
            _ => {}
        }
    }

    (config, state_dir)
}

#[cfg(target_os = "windows")]
fn resolve_scm_state_dir(
    explicit: Option<&std::path::Path>,
    cfg: &spt_config::schema::Config,
) -> Result<PathBuf> {
    let chosen: Option<PathBuf> = explicit
        .map(std::path::Path::to_path_buf)
        .or_else(|| {
            cfg.runtime
                .as_ref()
                .and_then(|r| r.state_dir.clone())
                .map(PathBuf::from)
        });
    spt_state::resolve_state_dir(chosen.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_constant_matches_install_path() {
        // Cross-checks the contract with `spt_service::windows_scm`'s
        // `scm_launch_arguments` helper: both must spell the flag the
        // same way.
        assert_eq!(SCM_DISPATCH_FLAG, "--scm-dispatch");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn enter_scm_dispatch_unsupported_off_windows() {
        let err = enter_scm_dispatch("spt").unwrap_err();
        match err {
            Error::UnsupportedPlatform(msg) => {
                assert!(msg.contains("Windows"));
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }
}
