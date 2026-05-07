//! Windows Service Control Manager backend.
//!
//! Two distinct responsibilities live in this module:
//!
//! 1. The [`WindowsScmManager`] — the [`crate::ServiceManager`] impl that
//!    callers use to **install / uninstall / start / stop / restart / reload /
//!    query** an spt service. On Windows it talks to SCM directly via the
//!    `windows-service` crate; on every other target every method short-circuits
//!    to [`Error::UnsupportedPlatform`] so cross-compilation still produces
//!    the type.
//!
//! 2. [`run_as_service`] — the **service-main entry point** invoked from
//!    `spt-bin::main` when the binary is launched by SCM (the `ImagePath`
//!    written by `install` ends in `--scm-dispatch`). This wires the
//!    `windows-service` boilerplate that:
//!
//!    * registers a control handler (Stop / Shutdown / `ParamChange` /
//!      Interrogate),
//!    * reports `StartPending → Running → Stopped` with appropriate
//!      `wait_hint` and `checkpoint` increments,
//!    * exposes shutdown + reload signals to the supplied entry closure
//!      via [`ScmHandles`].
//!
//! `ParamChange` is mapped to a SIGHUP-equivalent reload signal per spec
//! §13.7; spt-bin's runtime is expected to wait on
//! [`ScmHandles::reload`] alongside its Unix `SIGHUP` handler.

use std::sync::Arc;

use spt_core::error::Result;

#[cfg(not(target_os = "windows"))]
use crate::unsupported;
use crate::{ServiceCapabilities, ServiceManager, ServiceSpec, ServiceStatus};

/// Stable backend name reported via [`ServiceManager::name`].
pub const BACKEND_NAME: &str = "windows-scm";

/// Capability matrix advertised by [`WindowsScmManager`].
///
/// Lifted into a `const` so [`run_as_service`]'s rustdoc can cross-reference
/// it without duplicating the bool list.
const CAPABILITIES: ServiceCapabilities = ServiceCapabilities {
    supports_install: true,
    supports_uninstall: true,
    supports_status: true,
    supports_start_stop: true,
    supports_restart: true,
    // `reload` is mapped to SCM's `SERVICE_CONTROL_PARAMCHANGE` and
    // surfaces inside the running service as a [`ScmHandles::reload`]
    // notification.
    supports_reload: true,
    // SCM is system-scope only; per-user services on Windows are Task
    // Scheduler's domain.
    supports_user_scope: false,
    supports_status_pid: true,
    supports_status_uptime: false,
    supports_restart_counter: false,
};

/// SCM-backed [`ServiceManager`].
///
/// Construct with [`WindowsScmManager::new`]; lifecycle methods proxy to
/// the `windows-service` crate on Windows and to
/// [`Error::UnsupportedPlatform`] on every other target.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsScmManager;

impl WindowsScmManager {
    /// Construct an SCM manager.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

// ============================================================================
// Cross-platform stubs (used everywhere except Windows so the type still
// compiles on Linux / macOS for cross-builds and shared workspace tests).
// ============================================================================

#[cfg(not(target_os = "windows"))]
#[async_trait::async_trait]
impl ServiceManager for WindowsScmManager {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }
    fn capabilities(&self) -> ServiceCapabilities {
        CAPABILITIES
    }
    async fn install(&self, _spec: &ServiceSpec) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "install"))
    }
    async fn uninstall(&self, _name: &str) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "uninstall"))
    }
    async fn status(&self, _name: &str) -> Result<ServiceStatus> {
        Err(unsupported(BACKEND_NAME, "status"))
    }
    async fn start(&self, _name: &str) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "start"))
    }
    async fn stop(&self, _name: &str) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "stop"))
    }
    async fn restart(&self, _name: &str) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "restart"))
    }
    async fn reload(&self, _name: &str) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "reload"))
    }
}

// ============================================================================
// Windows real implementation.
// ============================================================================

#[cfg(target_os = "windows")]
#[async_trait::async_trait]
impl ServiceManager for WindowsScmManager {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }

    fn capabilities(&self) -> ServiceCapabilities {
        CAPABILITIES
    }

    async fn install(&self, spec: &ServiceSpec) -> Result<()> {
        let spec = spec.clone();
        // The `windows-service` crate is synchronous and ultimately calls into
        // Win32 via FFI. Wrap in `spawn_blocking` so we don't stall the
        // tokio reactor on slow SCM calls.
        tokio::task::spawn_blocking(move || windows_impl::install(&spec))
            .await
            .map_err(|e| {
                spt_core::error::Error::ServiceManagerFailed(format!("join install task: {e}"))
            })?
    }

    async fn uninstall(&self, name: &str) -> Result<()> {
        let name = name.to_string();
        tokio::task::spawn_blocking(move || windows_impl::uninstall(&name))
            .await
            .map_err(|e| {
                spt_core::error::Error::ServiceManagerFailed(format!("join uninstall task: {e}"))
            })?
    }

    async fn status(&self, name: &str) -> Result<ServiceStatus> {
        let name = name.to_string();
        tokio::task::spawn_blocking(move || windows_impl::status(&name))
            .await
            .map_err(|e| {
                spt_core::error::Error::ServiceManagerFailed(format!("join status task: {e}"))
            })?
    }

    async fn start(&self, name: &str) -> Result<()> {
        let name = name.to_string();
        tokio::task::spawn_blocking(move || windows_impl::start(&name))
            .await
            .map_err(|e| {
                spt_core::error::Error::ServiceManagerFailed(format!("join start task: {e}"))
            })?
    }

    async fn stop(&self, name: &str) -> Result<()> {
        let name = name.to_string();
        tokio::task::spawn_blocking(move || windows_impl::stop(&name))
            .await
            .map_err(|e| {
                spt_core::error::Error::ServiceManagerFailed(format!("join stop task: {e}"))
            })?
    }

    async fn restart(&self, name: &str) -> Result<()> {
        // Best-effort stop, then start. SCM has no native atomic restart and
        // matches what `sc.exe` does internally.
        let _ = self.stop(name).await;
        self.start(name).await
    }

    async fn reload(&self, name: &str) -> Result<()> {
        let name = name.to_string();
        tokio::task::spawn_blocking(move || windows_impl::reload(&name))
            .await
            .map_err(|e| {
                spt_core::error::Error::ServiceManagerFailed(format!("join reload task: {e}"))
            })?
    }
}

// ----------------------------------------------------------------------------
// run_as_service + ScmHandles — used by spt-bin's `--scm-dispatch` mode.
// ----------------------------------------------------------------------------

/// Cross-thread signals exposed to the entry closure passed to
/// [`run_as_service`].
///
/// The control handler registered with SCM translates Windows service
/// controls into [`tokio::sync::Notify`] notifications:
///
/// | SCM control | `ScmHandles` field |
/// |---|---|
/// | `Stop`, `Shutdown` | [`ScmHandles::shutdown`] |
/// | `ParamChange` | [`ScmHandles::reload`] (SIGHUP-equivalent) |
/// | `Interrogate` | (handled internally; reports current status) |
///
/// The entry closure should `select!` on both notifies alongside its
/// usual work loop and shut down cleanly when `shutdown` fires.
#[derive(Debug, Default)]
pub struct ScmHandles {
    /// Signalled on `SERVICE_CONTROL_STOP` and `SERVICE_CONTROL_SHUTDOWN`.
    pub shutdown: tokio::sync::Notify,
    /// Signalled on `SERVICE_CONTROL_PARAMCHANGE` (parity with Unix SIGHUP).
    pub reload: tokio::sync::Notify,
}

impl ScmHandles {
    /// Construct an empty `ScmHandles`. Both notifies start un-signalled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Run the current process as a Windows service.
///
/// Hands control to SCM via `windows_service::service_dispatcher::start` and
/// blocks the calling thread until the service stops. Inside the dispatcher,
/// the service's main thread:
///
/// 1. registers a control handler accepting `Stop`, `Shutdown`,
///    `ParamChange`, and `Interrogate`;
/// 2. reports `StartPending` (`wait_hint = 30s`);
/// 3. spawns `entry` on a worker thread, passing the service start arguments
///    plus a shared [`Arc<ScmHandles>`];
/// 4. reports `Running` immediately (entry is responsible for its own
///    bring-up; SCM will not time out so long as we transitioned out of
///    `StartPending` before the wait hint elapses);
/// 5. on `Stop`/`Shutdown`: signals [`ScmHandles::shutdown`] and reports
///    `StopPending`. When the worker thread exits, reports `Stopped`.
/// 6. on `ParamChange`: signals [`ScmHandles::reload`].
///
/// If the worker thread panics, the service is reported as `Stopped` with
/// `ServiceExitCode::ServiceSpecific(99)`.
///
/// # Threading model
///
/// `entry` runs on its own `std::thread::spawn` worker. It is free to drive
/// a tokio runtime internally (recommended: spt-bin builds its own
/// `tokio::runtime::Runtime` and `block_on(real_main(args, handles))`). The
/// notifies in [`ScmHandles`] are tokio types and must be awaited from
/// within a tokio runtime; the control handler simply calls
/// `notify.notify_one()` which is sync-safe and contention-free.
///
/// # Example
///
/// ```ignore
/// // In spt-bin/src/main.rs:
/// fn main() -> spt_core::error::Result<()> {
///     if std::env::args().any(|a| a == "--scm-dispatch") {
///         spt_service::windows_scm::run_as_service(
///             "spt",
///             |args, handles| {
///                 let rt = tokio::runtime::Runtime::new().expect("tokio");
///                 rt.block_on(spt_runtime::main_with_handles(args, handles));
///             },
///         )
///     } else {
///         /* normal CLI path */
///         Ok(())
///     }
/// }
/// ```
///
/// # Errors
///
/// Returns [`Error::ServiceManagerFailed`] if the SCM dispatcher fails to
/// start (typically: not invoked by SCM, or another dispatcher already
/// running in this process). On non-Windows targets returns
/// [`Error::UnsupportedPlatform`].
///
/// [`Error::ServiceManagerFailed`]: spt_core::error::Error::ServiceManagerFailed
/// [`Error::UnsupportedPlatform`]: spt_core::error::Error::UnsupportedPlatform
#[cfg(target_os = "windows")]
pub fn run_as_service<F>(name: &'static str, entry: F) -> Result<()>
where
    F: FnOnce(Vec<std::ffi::OsString>, Arc<ScmHandles>) + Send + 'static,
{
    windows_impl::run_as_service(name, entry)
}

/// Non-Windows stub for [`run_as_service`]. Always returns
/// [`Error::UnsupportedPlatform`].
///
/// [`Error::UnsupportedPlatform`]: spt_core::error::Error::UnsupportedPlatform
#[cfg(not(target_os = "windows"))]
pub fn run_as_service<F>(_name: &'static str, _entry: F) -> Result<()>
where
    F: FnOnce(Vec<std::ffi::OsString>, Arc<ScmHandles>) + Send + 'static,
{
    Err(unsupported(BACKEND_NAME, "run_as_service"))
}

// ============================================================================
// Windows-only implementation module. Isolated so we can `use` Win32 types
// without polluting the cross-platform path.
// ============================================================================

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    use spt_core::error::{Error, Result};
    use windows_service::service::{
        Service, ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
        ServiceExitCode, ServiceInfo, ServiceStartType,
        ServiceState as WinServiceState, ServiceStatus as WinServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;
    use windows_service::service_manager::{ServiceManager as ScmHandle, ServiceManagerAccess};

    use crate::{ServiceSpec, ServiceState, ServiceStatus};

    use super::ScmHandles;

    /// Map a `windows-service` state into our cross-platform [`ServiceState`].
    ///
    /// Pure function so it can be unit-tested without touching SCM.
    pub(super) fn map_state(s: WinServiceState) -> ServiceState {
        match s {
            WinServiceState::Running | WinServiceState::ContinuePending => ServiceState::Running,
            WinServiceState::Stopped => ServiceState::Stopped,
            // Future-proof against new variants the crate may add.
            _ => ServiceState::Unknown,
        }
    }

    fn open_scm(access: ServiceManagerAccess) -> Result<ScmHandle> {
        ScmHandle::local_computer(None::<&str>, access)
            .map_err(|e| Error::ServiceManagerFailed(format!("open SCM: {e}")))
    }

    fn open_service_for(name: &str, access: ServiceAccess) -> Result<Service> {
        let scm = open_scm(ServiceManagerAccess::CONNECT)?;
        scm.open_service(name, access)
            .map_err(|e| Error::ServiceManagerFailed(format!("open_service({name}): {e}")))
    }

    pub(super) fn install(spec: &ServiceSpec) -> Result<()> {
        let scm = open_scm(ServiceManagerAccess::CREATE_SERVICE)?;
        let info = ServiceInfo {
            name: OsString::from(&spec.name),
            display_name: OsString::from(&spec.description),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: spec.exec_path.clone(),
            launch_arguments: spec.args.iter().map(OsString::from).collect(),
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        let svc = scm
            .create_service(&info, ServiceAccess::START | ServiceAccess::CHANGE_CONFIG)
            .map_err(|e| Error::ServiceManagerFailed(format!("create_service: {e}")))?;
        // Best-effort start; failure here is reported but the service is
        // still installed. Callers can retry via `start`.
        if let Err(e) = svc.start::<&str>(&[]) {
            tracing::warn!(error = %e, name = %spec.name, "post-install start failed");
        }
        Ok(())
    }

    pub(super) fn uninstall(name: &str) -> Result<()> {
        // Idempotent: missing service is success.
        let scm = open_scm(ServiceManagerAccess::CONNECT)?;
        let Ok(svc) = scm.open_service(name, ServiceAccess::STOP | ServiceAccess::DELETE) else {
            return Ok(());
        };
        let _ = svc.stop();
        svc.delete()
            .map_err(|e| Error::ServiceManagerFailed(format!("delete service: {e}")))?;
        Ok(())
    }

    pub(super) fn status(name: &str) -> Result<ServiceStatus> {
        let scm = open_scm(ServiceManagerAccess::CONNECT)?;
        let Ok(svc) = scm.open_service(name, ServiceAccess::QUERY_STATUS) else {
            return Ok(ServiceStatus::new(ServiceState::NotInstalled));
        };
        let st = svc
            .query_status()
            .map_err(|e| Error::ServiceManagerFailed(format!("query_status: {e}")))?;
        let exit_code = match st.exit_code {
            ServiceExitCode::Win32(0) => None,
            ServiceExitCode::Win32(c) | ServiceExitCode::ServiceSpecific(c) => {
                Some(i32::try_from(c).unwrap_or(i32::MAX))
            }
        };
        Ok(ServiceStatus {
            state: map_state(st.current_state),
            pid: st.process_id,
            exit_code,
            since: None,
            restart_count: None,
        })
    }

    pub(super) fn start(name: &str) -> Result<()> {
        let svc = open_service_for(name, ServiceAccess::START)?;
        svc.start::<&str>(&[])
            .map_err(|e| Error::ServiceManagerFailed(format!("start({name}): {e}")))?;
        Ok(())
    }

    pub(super) fn stop(name: &str) -> Result<()> {
        let svc = open_service_for(name, ServiceAccess::STOP)?;
        svc.stop()
            .map_err(|e| Error::ServiceManagerFailed(format!("stop({name}): {e}")))?;
        Ok(())
    }

    pub(super) fn reload(name: &str) -> Result<()> {
        // Pre-flight: refuse if the service isn't running (so the caller
        // gets a typed error instead of SCM silently dropping the
        // control).
        let svc = open_service_for(name, ServiceAccess::QUERY_STATUS)?;
        let st = svc
            .query_status()
            .map_err(|e| Error::ServiceManagerFailed(format!("query_status({name}): {e}")))?;
        if st.current_state != WinServiceState::Running {
            return Err(Error::ServiceManagerFailed(format!(
                "reload({name}): service is not running (state {:?})",
                st.current_state
            )));
        }
        // The `windows-service` crate (0.7) doesn't expose
        // `send_control_command(ParamChange)` publicly — only Stop /
        // Pause / Continue and user-defined `notify(code)` codes (which
        // map to SERVICE_CONTROL_USEREVENT, not PARAMCHANGE). Shell out
        // to `sc.exe control <name> paramchange` instead. `sc.exe` is
        // present on every supported Windows version and atomically
        // sends SERVICE_CONTROL_PARAMCHANGE.
        let output = std::process::Command::new("sc.exe")
            .args(["control", name, "paramchange"])
            .output()
            .map_err(|e| Error::ServiceManagerFailed(format!("spawn sc.exe: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(Error::ServiceManagerFailed(format!(
                "sc.exe control {name} paramchange exited {:?}: {stderr}{stdout}",
                output.status.code()
            )));
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // run_as_service plumbing
    //
    // The `define_windows_service!` macro generates a name-bound `extern
    // "system" fn`. It calls a *named* Rust fn — there's no closure slot.
    // To smuggle our caller's `entry` closure plus the `ScmHandles` arc
    // through to that fn we stash them in process-globals before invoking
    // `service_dispatcher::start`. The dispatcher only ever runs once per
    // process so this is safe; we still gate `ENTRY` behind a Mutex/Option
    // so a future caller would observe a clean `None`.
    // ------------------------------------------------------------------

    type EntryFn = Box<dyn FnOnce(Vec<OsString>, Arc<ScmHandles>) + Send>;

    static ENTRY: OnceLock<Mutex<Option<EntryFn>>> = OnceLock::new();
    static HANDLES: OnceLock<Arc<ScmHandles>> = OnceLock::new();
    static SERVICE_NAME: OnceLock<&'static str> = OnceLock::new();

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    windows_service::define_windows_service!(ffi_service_main, my_service_main);

    pub(super) fn run_as_service<F>(name: &'static str, entry: F) -> Result<()>
    where
        F: FnOnce(Vec<OsString>, Arc<ScmHandles>) + Send + 'static,
    {
        let _ = SERVICE_NAME.set(name);
        let _ = HANDLES.set(Arc::new(ScmHandles::new()));
        let slot = ENTRY.get_or_init(|| Mutex::new(None));
        {
            let mut guard = slot.lock().map_err(|_| {
                Error::ServiceManagerFailed("run_as_service: ENTRY mutex poisoned".into())
            })?;
            if guard.is_some() {
                return Err(Error::ServiceManagerFailed(
                    "run_as_service: a service dispatcher is already configured in this process"
                        .into(),
                ));
            }
            *guard = Some(Box::new(entry));
        }

        // Hands control to SCM. Returns when the service stops (or
        // immediately, with an error, if we weren't actually invoked by
        // SCM — e.g. when run from a console).
        service_dispatcher::start(name, ffi_service_main).map_err(|e| {
            Error::ServiceManagerFailed(format!("service_dispatcher::start failed: {e}"))
        })?;
        Ok(())
    }

    fn my_service_main(arguments: Vec<OsString>) {
        if let Err(e) = service_main_inner(arguments) {
            tracing::error!(error = %e, "windows service-main returned with error");
        }
    }

    fn service_main_inner(arguments: Vec<OsString>) -> windows_service::Result<()> {
        let name = SERVICE_NAME.get().copied().unwrap_or("spt");
        let handles = HANDLES
            .get()
            .cloned()
            .unwrap_or_else(|| Arc::new(ScmHandles::new()));

        // Control handler. Runs on a thread owned by the service control
        // dispatcher. We must NOT block here for any meaningful duration:
        // each `Notify::notify_one` is wait-free.
        let handler_handles = Arc::clone(&handles);
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    handler_handles.shutdown.notify_one();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::ParamChange => {
                    handler_handles.reload.notify_one();
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(name, event_handler)?;

        // Report StartPending with a generous wait_hint so SCM doesn't
        // declare the service hung while spt-bin builds its tokio runtime.
        status_handle.set_service_status(WinServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: WinServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        })?;

        // Pull the entry closure out of the global slot. If it's missing
        // we're being driven by a second dispatcher invocation in this
        // process, which is a programmer error.
        let entry: EntryFn = match ENTRY.get().and_then(|m| m.lock().ok().and_then(|mut g| g.take())) {
            Some(e) => e,
            None => {
                let _ = status_handle.set_service_status(WinServiceStatus {
                    service_type: SERVICE_TYPE,
                    current_state: WinServiceState::Stopped,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::ServiceSpecific(98),
                    checkpoint: 0,
                    wait_hint: Duration::default(),
                    process_id: None,
                });
                return Ok(());
            }
        };

        // Spawn entry on a worker thread so we can return to SCM with a
        // `Running` report immediately. Entry's panic is mapped to
        // `ServiceSpecific(99)`.
        let worker_handles = Arc::clone(&handles);
        let worker = std::thread::Builder::new()
            .name(format!("{name}-worker"))
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        entry(arguments, worker_handles);
                    }));
                result.is_ok()
            })
            .map_err(|e| {
                windows_service::Error::Winapi(std::io::Error::other(format!(
                    "spawn worker thread: {e}"
                )))
            })?;

        // Tell SCM we're up. From here on we accept Stop / Shutdown /
        // ParamChange. PARAM_CHANGE *must* be in `controls_accepted` or
        // SCM silently drops `ParamChange` requests sent from the outside.
        let accepted =
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN | ServiceControlAccept::PARAM_CHANGE;
        status_handle.set_service_status(WinServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: WinServiceState::Running,
            controls_accepted: accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        // Wait for entry to return. This thread is the service-main thread
        // and SCM is happy as long as we keep it alive while the service
        // is `Running`.
        let clean_exit = worker.join().unwrap_or(false);

        // Final status. `StopPending` first (best practice — gives SCM a
        // chance to update its UI) then `Stopped`.
        let _ = status_handle.set_service_status(WinServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: WinServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        });
        status_handle.set_service_status(WinServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: WinServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: if clean_exit {
                ServiceExitCode::Win32(0)
            } else {
                ServiceExitCode::ServiceSpecific(99)
            },
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        Ok(())
    }

    #[cfg(test)]
    mod inner_tests {
        use super::*;

        #[test]
        fn map_state_running_and_continue_pending_are_running() {
            assert_eq!(map_state(WinServiceState::Running), ServiceState::Running);
            assert_eq!(
                map_state(WinServiceState::ContinuePending),
                ServiceState::Running
            );
        }

        #[test]
        fn map_state_stopped_is_stopped() {
            assert_eq!(map_state(WinServiceState::Stopped), ServiceState::Stopped);
        }

        #[test]
        fn map_state_pending_states_are_unknown() {
            assert_eq!(
                map_state(WinServiceState::StartPending),
                ServiceState::Unknown
            );
            assert_eq!(
                map_state(WinServiceState::StopPending),
                ServiceState::Unknown
            );
            assert_eq!(map_state(WinServiceState::Paused), ServiceState::Unknown);
        }
    }
}

// ============================================================================
// Tests (cross-platform — exercise capabilities + non-Windows stub paths;
// real SCM round-trip lives in gated integration tests below).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_windows_scm() {
        let m = WindowsScmManager::new();
        assert_eq!(m.name(), "windows-scm");
    }

    #[test]
    fn capabilities_advertise_reload_and_pid_no_user_scope() {
        let caps = WindowsScmManager::new().capabilities();
        assert!(caps.supports_install);
        assert!(caps.supports_uninstall);
        assert!(caps.supports_status);
        assert!(caps.supports_start_stop);
        assert!(caps.supports_restart);
        assert!(caps.supports_reload);
        assert!(caps.supports_status_pid);
        assert!(!caps.supports_user_scope);
        assert!(!caps.supports_status_uptime);
        assert!(!caps.supports_restart_counter);
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn non_windows_methods_return_unsupported_platform() {
        use spt_core::error::Error;
        let m = WindowsScmManager::new();
        let err = m.start("svc").await.unwrap_err();
        match err {
            Error::UnsupportedPlatform(msg) => {
                assert!(msg.contains("start"));
                assert!(msg.contains("windows-scm"));
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
        let err = run_as_service("svc", |_, _| {}).unwrap_err();
        match err {
            Error::UnsupportedPlatform(_) => {}
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    #[test]
    fn scm_handles_default_constructs() {
        let h = ScmHandles::new();
        // Notify has no observable un-signalled state; just confirm the
        // type is constructible without a runtime.
        let _ = format!("{h:?}");
    }
}

// ============================================================================
// Gated integration tests — admin required, manual smoke test only.
// Run with: `cargo test -p spt-service --test ... -- --ignored`
// ============================================================================

#[cfg(all(test, target_os = "windows"))]
mod integration_tests {
    use super::*;
    use std::path::PathBuf;

    fn unique_name() -> String {
        // Lightweight uniqueness: nanos timestamp. Avoids pulling uuid in
        // for tests only.
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("spt-test-svc-{ns}")
    }

    fn cmd_exe_path() -> PathBuf {
        // System cmd.exe is a stable, always-present executable that
        // exits immediately under `/c exit 0`.
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        PathBuf::from(format!("{root}\\System32\\cmd.exe"))
    }

    /// Round-trip install / status / uninstall against a temp service.
    /// Requires Administrator.
    #[tokio::test]
    #[ignore = "requires admin and a real Windows session"]
    async fn install_status_uninstall_roundtrip() {
        let mgr = WindowsScmManager::new();
        let name = unique_name();
        let spec = ServiceSpec {
            name: name.clone(),
            description: "spt integration test".into(),
            exec_path: cmd_exe_path(),
            args: vec!["/c".into(), "exit".into(), "0".into()],
            ..Default::default()
        };

        mgr.install(&spec).await.expect("install");
        let st = mgr.status(&name).await.expect("status");
        // Either Running, Stopped, or Unknown (transient pending) — but
        // not NotInstalled.
        assert_ne!(st.state, crate::ServiceState::NotInstalled);
        mgr.uninstall(&name).await.expect("uninstall");
        // Idempotent re-uninstall.
        mgr.uninstall(&name).await.expect("uninstall idempotent");
    }

    /// Reload on a non-running service must produce a typed error.
    #[tokio::test]
    #[ignore = "requires admin and a real Windows session"]
    async fn reload_on_stopped_service_errors() {
        let mgr = WindowsScmManager::new();
        let name = unique_name();
        let spec = ServiceSpec {
            name: name.clone(),
            description: "spt integration test (reload)".into(),
            exec_path: cmd_exe_path(),
            args: vec!["/c".into(), "exit".into(), "0".into()],
            ..Default::default()
        };
        mgr.install(&spec).await.expect("install");
        // cmd.exe /c exit 0 returns immediately; service ends up Stopped.
        // Give SCM a moment.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let _ = mgr.stop(&name).await;
        let err = mgr.reload(&name).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not running") || msg.contains("reload"),
            "unexpected error: {msg}"
        );
        mgr.uninstall(&name).await.expect("uninstall");
    }
}
