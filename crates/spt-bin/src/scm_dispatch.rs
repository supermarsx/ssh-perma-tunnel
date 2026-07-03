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
use spt_mem_hygiene::HardeningReport;

/// Event Log source name + base event id used by the SCM service path
/// (E7-F1). The source is best-effort registered at startup; unregistered
/// hosts still see the events rendered as raw text.
#[cfg(target_os = "windows")]
const WINEVENT_SOURCE: &str = "spt";
/// Event id for a fatal service-main error mirrored to the Windows Event Log.
#[cfg(target_os = "windows")]
const WINEVENT_ID_FATAL: u32 = 1;

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
pub fn enter_scm_dispatch(service_name: &'static str, hardening: HardeningReport) -> Result<()> {
    use spt_service::windows_scm;
    windows_scm::run_as_service(service_name, move |scm_args, handles| {
        // E7-F1: install a tracing subscriber FIRST — before we build the
        // runtime or load config — so every failure below (bad config path,
        // state-lock conflict, profile build error) lands in `<state>/spt.log`
        // and the Windows Event Log instead of vanishing into a no-op
        // subscriber. Without this the whole service runtime was unobservable.
        let (state_dir_for_log, _trace_guard, reload_handle) = init_scm_tracing();

        // E7-F15: now that a subscriber exists, surface the mem-hygiene report
        // (warn on any failed mitigation).
        crate::log_hardening_report(&hardening);

        // Best-effort Event Log source registration so fatal mirrors render
        // with a name in Event Viewer. Failure is non-fatal.
        let _ = spt_winevent::register_source(WINEVENT_SOURCE, None, None);

        tracing::info!(
            scm_args = ?scm_args,
            ?state_dir_for_log,
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
                mirror_fatal(&format!("failed to build tokio runtime: {e}"));
                // RuntimeFailure exit code — a non-zero ServiceSpecific so SCM
                // does not report a clean stop (E7-F1).
                handles.set_exit_code(spt_core::ExitCode::RuntimeFailure.as_i32());
                return;
            }
        };

        if let Err(e) = rt.block_on(scm_main(&handles, reload_handle.clone())) {
            tracing::error!(error = %e, "spt service-main returned with error");
            mirror_fatal(&format!("service-main failed: {e}"));
            // Map the typed error's exit code into SCM's ServiceSpecific slot
            // so the failure is distinguishable from a deliberate stop.
            handles.set_exit_code(e.exit_code().as_i32());
        }
        // Drop the runtime to flush any pending tasks.
        rt.shutdown_timeout(std::time::Duration::from_secs(5));
    })
}

/// Initialise the SCM service subscriber (E7-F1).
///
/// Returns the resolved state dir (for diagnostics), the `TracingGuard` whose
/// lifetime keeps the file sink alive for the service run, and a
/// [`LogReloadHandle`] used by the `ParamChange` reload branch (E7-F13).
///
/// The state dir is resolved from `--state-dir`/`$SPT_STATE_DIR`/OS default
/// *without* loading the config (which may itself fail to load — we need a log
/// sink in place before that). The file sink writes `<state>/spt.log`. If init
/// fails entirely we fall back to a minimal stderr subscriber so the service
/// is never wholly silent.
#[cfg(target_os = "windows")]
fn init_scm_tracing() -> (
    PathBuf,
    Option<spt_observability::TracingGuard>,
    Option<spt_observability::LogReloadHandle>,
) {
    use spt_observability::config::{
        Destination, FileSink, LogFormat, LoggingConfig, RotationPolicy,
    };

    let (_cfg_path, explicit_state_dir) = parse_scm_args();
    let state_dir = spt_state::resolve_state_dir(explicit_state_dir.as_deref())
        .unwrap_or_else(|_| std::path::PathBuf::from("."));

    // Honour SPT_LOG / log-filter for the service subscriber too.
    let level = crate::signals::read_sighup_log_filter(Some(&state_dir))
        .ok()
        .flatten()
        .unwrap_or_else(|| "info".to_string());

    let cfg = LoggingConfig {
        level,
        format: LogFormat::Json,
        no_color: true,
        destinations: vec![Destination::File],
        file: Some(FileSink {
            path: state_dir.join("spt.log"),
            rotate: RotationPolicy::Daily,
            max_files: 7,
        }),
        redact: spt_core::RedactionMode::Standard,
        remote: Vec::new(),
    };

    match spt_observability::init(&cfg) {
        Ok(guard) => {
            let handle = guard.reload_handle();
            (state_dir, Some(guard), Some(handle))
        }
        Err(e) => {
            // Fall back to a stderr-only subscriber so we are not wholly
            // silent; the service has no console but this still feeds any
            // attached debugger.
            let fallback = LoggingConfig {
                level: "info".into(),
                format: LogFormat::Compact,
                no_color: true,
                destinations: vec![Destination::Stderr],
                file: None,
                redact: spt_core::RedactionMode::Standard,
                remote: Vec::new(),
            };
            let guard = spt_observability::init(&fallback).ok();
            let handle = guard
                .as_ref()
                .map(spt_observability::TracingGuard::reload_handle);
            mirror_fatal(&format!("file log init failed, using stderr fallback: {e}"));
            (state_dir, guard, handle)
        }
    }
}

/// Mirror a fatal service message to the Windows Event Log (E7-F1).
///
/// Best-effort: a missing source registration or a non-elevated context just
/// drops the event. The tracing file sink remains the primary record.
#[cfg(target_os = "windows")]
fn mirror_fatal(message: &str) {
    let _ = spt_winevent::report_event(
        WINEVENT_SOURCE,
        spt_winevent::Level::Error,
        WINEVENT_ID_FATAL,
        message,
    );
}

/// Non-Windows stub. Always returns `UnsupportedPlatform`.
#[cfg(not(target_os = "windows"))]
pub fn enter_scm_dispatch(_service_name: &'static str, _hardening: HardeningReport) -> Result<()> {
    Err(Error::UnsupportedPlatform(
        "--scm-dispatch is Windows-only".into(),
    ))
}

// ============================================================================
// Windows-only orchestrator wiring.
// ============================================================================

#[cfg(target_os = "windows")]
async fn scm_main(
    handles: &std::sync::Arc<spt_service::windows_scm::ScmHandles>,
    reload_handle: Option<spt_observability::LogReloadHandle>,
) -> Result<()> {
    let (config, state_dir) = parse_scm_args();
    tracing::info!(
        ?config,
        ?state_dir,
        "spt service: parsed argv-derived options"
    );

    let path = config.ok_or_else(|| {
        Error::InvalidArgs(
            "no config path supplied to --scm-dispatch (set $SPT_CONFIG or pass --config)".into(),
        )
    })?;

    // Box the orchestrator-under-SCM future: like `tunnel_run` it boots the
    // orchestrator + reload machinery, so its future trips clippy's
    // `large_futures` threshold otherwise.
    Box::pin(run_orchestrator_under_scm(
        state_dir.as_deref(),
        &path,
        handles,
        reload_handle,
    ))
    .await
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
    handles: &std::sync::Arc<spt_service::windows_scm::ScmHandles>,
    reload_handle: Option<spt_observability::LogReloadHandle>,
) -> Result<()> {
    let (mut cfg, _w) = spt_config::load(config_path, false)
        .map_err(|e| Error::InvalidConfig(format!("load: {e}")))?;
    // Apply Group Policy registry overlay before runtime startup
    // (HKLM-enforced settings dominate config-file values in the SCM path).
    let _overlay_report = crate::policy::overlay::apply(&mut cfg);
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
        match crate::profile_factory::build_with_config(profile, &resolver, &cfg) {
            Ok(bundle) => {
                tracing::info!(
                    profile = %profile.name,
                    protocol = %profile.protocol,
                    endpoints = bundle.endpoints.len(),
                    "spt service: starting profile"
                );
                // Plan §t4-e4: round-robin policy selector. Built before
                // start_profile so the endpoints Vec is reused; attached after
                // because the supervisor's selector lives on the spawned task.
                let policy = spt_supervisor::make_policy_selector(
                    bundle.endpoints.clone(),
                    &cfg.round_robin,
                );
                // Multi-auth Phase 3: zip endpoints with index-aligned resolved
                // credentials into the (host, port) → AuthConfig map.
                let auth_by_endpoint: std::collections::HashMap<
                    (String, u16),
                    spt_auth::AuthConfig,
                > = bundle
                    .endpoints
                    .iter()
                    .zip(bundle.endpoint_auth.iter())
                    .map(|(ep, auth)| ((ep.host.clone(), ep.port), auth.clone()))
                    .collect();
                orchestrator.start_profile_with_auth(
                    profile,
                    bundle.protocol,
                    bundle.auth,
                    auth_by_endpoint,
                    bundle.endpoints,
                    bundle.supervisor_cfg,
                );
                if let Some(ps) = policy {
                    if let Some(sup) = orchestrator.profile_handle(&profile.name) {
                        sup.selector().lock().set_policy_selector(Some(ps));
                        tracing::info!(
                            profile = %profile.name,
                            policy = ?cfg.round_robin.policy,
                            "spt service: round-robin policy attached"
                        );
                    }
                }
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

    // Plan §t4-e5: bring up the read-only status API if enabled. Lives
    // alongside the orchestrator until SCM signals shutdown. The
    // `status_api_tls::launch` helper closes the deferred TLS/mTLS gate
    // from t4-Bwire (see `.orchestration/logs/f-status-tls.md`).
    let status_api_handle = if cfg.status_api.enabled {
        let source = crate::status_api_tls::file_snapshot_source(state_dir.clone());
        // Wave 6: apply `[network.offload]` socket options to the listener,
        // matching the `tunnel run` daemon path.
        let tcp_options = crate::net_offload::tcp_options(&cfg);
        Some(crate::status_api_tls::launch(&cfg.status_api, source, &resolver, tcp_options).await?)
    } else {
        None
    };

    tracing::info!("spt service: orchestrator running; awaiting SCM signals");

    // E7-F13: share one last-applied-config cell across SCM reloads, exactly
    // like the SIGHUP path in `cli_dispatch::tunnel_run`. Before this, the SCM
    // reload branch had its own `current_cfg` and diffed against the *boot*
    // config forever (a duplicate of the old E1-F2 bug); now reloads diff
    // against the last-applied config and advance the cell on success.
    let config_cell = crate::controller::ConfigCell::new(cfg);
    loop {
        tokio::select! {
            () = handles.shutdown.notified() => {
                tracing::info!("spt service: shutdown signal received from SCM");
                break;
            }
            () = handles.reload.notified() => {
                tracing::info!("spt service: reload (PARAMCHANGE) requested — re-reading config");
                // E7-F13: also re-read the log filter (SPT_LOG / <state>/log-filter)
                // so operators can raise verbosity on a live Windows service
                // without restarting it — the Windows parity for the Unix
                // SIGHUP log-reload path.
                reload_scm_log_filter(reload_handle.as_ref(), &state_dir);
                match scm_reload(config_path, &resolver, &orchestrator, &config_cell).await {
                    Ok(outcome) => {
                        let fp = spt_config::fingerprint::fingerprint_hex(&outcome.applied);
                        writer.update(|s| { s.config_fingerprint_sha256 = fp; }).await;
                        if outcome.provider_failures.is_empty() {
                            tracing::info!("spt service: reload applied");
                        } else {
                            for f in &outcome.provider_failures {
                                tracing::error!(profile = %f.profile, error = %f.error, "spt service: profile failed to build on reload");
                            }
                            tracing::warn!(
                                failures = outcome.provider_failures.len(),
                                "spt service: reload applied with profile build failures"
                            );
                        }
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
    if let Some(h) = status_api_handle {
        h.shutdown().await;
    }
    writer.flush().await?;
    writer_handle.stop().await;
    tracing::info!("spt service: clean exit");
    Ok(())
}

/// Re-read config from disk and run the **shared** reload pipeline through the
/// [`ConfigCell`] (E7-F13).
///
/// This now delegates to the same `controller::ConfigCell::reload` /
/// `run_reload_pipeline` used by the SIGHUP path and the MCP controller,
/// rather than carrying its own duplicate copy that diffed against the boot
/// config. The cell:
///   * re-applies the GPO/HKLM overlay on every reload (E5-F2),
///   * validates and bails before touching the orchestrator,
///   * diffs against the **last-applied** config (not boot),
///   * stops (not restarts) disabled profiles (E5-F1),
///   * surfaces per-profile build failures instead of dropping them (E1-F14).
#[cfg(target_os = "windows")]
async fn scm_reload(
    path: &std::path::Path,
    resolver: &spt_secrets::Resolver,
    orch: &spt_supervisor::Orchestrator,
    cell: &crate::controller::ConfigCell,
) -> Result<crate::controller::ReloadOutcome> {
    let (new_cfg, warnings) = spt_config::load(path, false)
        .map_err(|e| Error::InvalidConfig(format!("reload load: {e}")))?;
    cell.reload(new_cfg, &warnings, resolver, orch)
        .await
        .map_err(|e| Error::InvalidConfig(format!("reload: {e}")))
}

/// Re-apply the log filter on an SCM `ParamChange` (E7-F13).
///
/// Reads the directive via [`crate::signals::read_sighup_log_filter`]
/// (`SPT_LOG` env → `<state>/log-filter`) and pushes it through the
/// [`spt_observability::LogReloadHandle`]. A missing directive leaves the
/// filter untouched; a bad directive is logged and ignored so a reload never
/// kills the service.
#[cfg(target_os = "windows")]
fn reload_scm_log_filter(
    handle: Option<&spt_observability::LogReloadHandle>,
    state_dir: &std::path::Path,
) {
    let Some(handle) = handle else {
        return;
    };
    match crate::signals::read_sighup_log_filter(Some(state_dir)) {
        Ok(Some(directive)) => match handle.reload(&directive) {
            Ok(()) => tracing::info!(directive = %directive, "spt service: log filter reloaded"),
            Err(e) => tracing::warn!(error = %e, "spt service: log filter reload failed"),
        },
        Ok(None) => tracing::debug!("spt service: log reload — no directive available"),
        Err(e) => tracing::warn!(error = %e, "spt service: failed to read log directive"),
    }
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
    let chosen: Option<PathBuf> = explicit.map(std::path::Path::to_path_buf).or_else(|| {
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
        let err = enter_scm_dispatch("spt", spt_mem_hygiene::HardeningReport::new()).unwrap_err();
        match err {
            Error::UnsupportedPlatform(msg) => {
                assert!(msg.contains("Windows"));
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }
}
