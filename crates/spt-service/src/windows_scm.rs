//! Windows Service Control Manager backend.
//!
//! Two distinct responsibilities live in this module:
//!
//! 1. The [`WindowsScmManager`] — the [`crate::ServiceManager`] impl that
//!    callers use to **install / uninstall / start / stop / restart / reload /
//!    query** an spt service. On Windows it talks to SCM directly via the
//!    `windows-service` crate; on every other target every method short-circuits
//!    to [`spt_core::Error::UnsupportedPlatform`] so cross-compilation still produces
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
//!
//! # Internal architecture
//!
//! The lifecycle paths route through a private [`ScmBackend`] trait so the
//! SCM-facing logic (exit-code decoding, "service not installed" branch,
//! `reload` precheck, `sc.exe` shell-out) can be exercised by an in-memory
//! `MockScmBackend` without touching real Win32 handles. The production
//! impl ([`WindowsServiceCrateBackend`]) wraps `windows-service 0.7`. The
//! public [`WindowsScmManager`] type stays `#[derive(Debug, Default, Clone,
//! Copy)]` and routes calls through `WindowsServiceCrateBackend` on Windows,
//! preserving byte-identical public API.

use std::sync::Arc;

use spt_core::error::Result;

#[cfg(not(target_os = "windows"))]
use crate::unsupported;
use crate::{ServiceCapabilities, ServiceManager, ServiceSpec, ServiceState, ServiceStatus};

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
/// [`spt_core::Error::UnsupportedPlatform`] on every other target.
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
// ScmBackend trait — internal indirection so the SCM-facing decision logic
// can be exercised by an in-memory mock. Operation-level methods so the mock
// never has to mint a real `windows-service::Service` handle (which wraps a
// raw Win32 HSERVICE and cannot be synthesised outside the crate).
// ============================================================================

/// Outcome of a `windows-service` query, decoded into a portable form.
///
/// Mirrors the relevant fields of `windows_service::service::ServiceStatus`
/// minus the foreign enums; constructed by [`ScmBackend::query_status`] and
/// re-decoded by [`ScmManagerImpl::status`] into a [`ServiceStatus`].
///
/// Visibility: `pub` so `crate::testing` (gated behind `feature = "testing"`)
/// can re-export it for external integration tests. Under default features
/// the type lives in a `pub(crate)`-cfg-gated path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendStatus {
    /// Mapped lifecycle state (already normalised to our enum).
    pub state: ServiceState,
    /// Win32 PID reported by SCM, if any.
    pub pid: Option<u32>,
    /// Exit code reported by SCM. `None` for `Win32(0)`; otherwise the raw
    /// value from `ServiceExitCode::Win32` or `ServiceExitCode::ServiceSpecific`.
    pub exit_code: Option<i32>,
}

/// Outcome of `ScmBackend::reload` precheck — separates "service is not
/// running" from "send the SCM control" so the test mock can drive either
/// branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReloadPrecheck {
    /// Service is currently `Running`; safe to dispatch `paramchange`.
    Running,
    /// Service is not `Running`; caller should fail with a typed error.
    NotRunning(ServiceState),
}

/// Internal trait abstracting the SCM operations used by [`WindowsScmManager`].
///
/// One implementation: [`WindowsServiceCrateBackend`] (Windows only, wraps
/// `windows-service 0.7`). A second `MockScmBackend` sits behind
/// `feature = "testing"` and records every call into a `Mutex<Vec<ScmCall>>`
/// for inline coverage tests.
///
/// Method shapes deliberately avoid leaking `windows-service` types so the
/// trait is implementable on any platform.
///
/// Visibility: `pub` so `crate::testing` can re-export the mock; the trait
/// is not part of `spt-service`'s public *stable* contract — its API may
/// shift between crate versions.
pub trait ScmBackend: Send + Sync {
    /// Pre-check whether SCM is reachable. Called by [`ScmManagerImpl::install`]
    /// before constructing the `ServiceInfo`. Returns `Err` if the SCM cannot
    /// be opened with `CREATE_SERVICE` rights (typically: not running as
    /// Administrator).
    fn open_scm(&self) -> Result<()>;

    /// Pre-check whether `name` exists with the given access mask. Returns
    /// `Ok(true)` if open succeeded, `Ok(false)` if the service does not
    /// exist (so the caller can short-circuit to "`NotInstalled`" / "idempotent
    /// uninstall"), `Err` for any other failure.
    fn open_service_for(&self, name: &str, access: ScmAccess) -> Result<bool>;

    /// Create the service. The caller has already rendered the
    /// `launch_arguments` array (see `scm_launch_arguments`).
    fn create_service(&self, spec: &ServiceSpec) -> Result<()>;

    /// Start `name`. Returns `Err(...)` if SCM refuses (already-running is
    /// not an error — backends decide).
    fn start_service(&self, name: &str) -> Result<()>;

    /// Stop `name`. Errors propagate; "already stopped" is **not** mapped
    /// here — the SCM crate returns a typed error and we surface it.
    fn stop_service(&self, name: &str) -> Result<()>;

    /// Delete `name`. Caller has already ensured the service exists.
    fn delete_service(&self, name: &str) -> Result<()>;

    /// Query the live status of `name`. Returns `Ok(None)` if the service
    /// does not exist (caller maps to `NotInstalled`).
    fn query_status(&self, name: &str) -> Result<Option<BackendStatus>>;

    /// Send `SERVICE_CONTROL_PARAMCHANGE` to `name`. The implementation
    /// shells out to `sc.exe` on Windows because the `windows-service` 0.7
    /// crate does not expose this control publicly.
    fn send_paramchange(&self, name: &str) -> Result<()>;
}

/// Subset of `windows_service::service::ServiceAccess` rights used by
/// [`ScmBackend::open_service_for`]. Defined here so the trait is
/// implementable on non-Windows targets (the foreign type is gated to
/// `target_os = "windows"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScmAccess {
    /// `QUERY_STATUS` — what `status` / `reload` pre-checks ask for.
    QueryStatus,
    /// `STOP | DELETE` — what `uninstall` asks for.
    StopAndDelete,
    /// `START` — what `start` asks for.
    Start,
    /// `STOP` — what `stop` asks for.
    Stop,
}

// ============================================================================
// WindowsServiceCrateBackend — real impl. Windows-only methods on Windows;
// the type still exists on non-Windows so the trait surface is referenceable
// (its methods return `unsupported` on non-Windows so the type still compiles).
// ============================================================================

/// Real SCM backend. Wraps `windows-service 0.7` calls.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsServiceCrateBackend;

#[cfg(target_os = "windows")]
impl ScmBackend for WindowsServiceCrateBackend {
    fn open_scm(&self) -> Result<()> {
        windows_impl::open_scm_for_create().map(|_| ())
    }

    fn open_service_for(&self, name: &str, access: ScmAccess) -> Result<bool> {
        windows_impl::open_service_exists(name, access)
    }

    fn create_service(&self, spec: &ServiceSpec) -> Result<()> {
        windows_impl::do_create_service(spec)
    }

    fn start_service(&self, name: &str) -> Result<()> {
        windows_impl::do_start_service(name)
    }

    fn stop_service(&self, name: &str) -> Result<()> {
        windows_impl::do_stop_service(name)
    }

    fn delete_service(&self, name: &str) -> Result<()> {
        windows_impl::do_delete_service(name)
    }

    fn query_status(&self, name: &str) -> Result<Option<BackendStatus>> {
        windows_impl::do_query_status(name)
    }

    fn send_paramchange(&self, name: &str) -> Result<()> {
        windows_impl::do_send_paramchange(name)
    }
}

#[cfg(not(target_os = "windows"))]
impl ScmBackend for WindowsServiceCrateBackend {
    fn open_scm(&self) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "open_scm"))
    }
    fn open_service_for(&self, _name: &str, _access: ScmAccess) -> Result<bool> {
        Err(unsupported(BACKEND_NAME, "open_service"))
    }
    fn create_service(&self, _spec: &ServiceSpec) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "create_service"))
    }
    fn start_service(&self, _name: &str) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "start_service"))
    }
    fn stop_service(&self, _name: &str) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "stop_service"))
    }
    fn delete_service(&self, _name: &str) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "delete_service"))
    }
    fn query_status(&self, _name: &str) -> Result<Option<BackendStatus>> {
        Err(unsupported(BACKEND_NAME, "query_status"))
    }
    fn send_paramchange(&self, _name: &str) -> Result<()> {
        Err(unsupported(BACKEND_NAME, "send_paramchange"))
    }
}

// ============================================================================
// ScmManagerImpl — the business-logic newtype carrying an
// `Arc<dyn ScmBackend>`. Public `WindowsScmManager` stays `Copy` and
// constructs a fresh `ScmManagerImpl` per call (cheap; called inside a
// `spawn_blocking` anyway).
// ============================================================================

/// Business-logic newtype carrying a backend handle.
///
/// All decision logic (exit-code mapping, `not running` precheck on reload,
/// "`open_service` failed → `NotInstalled`" branches) lives here so it can be
/// exercised by `MockScmBackend`.
///
/// Visibility: `pub` so external tests can construct `ScmManagerImpl::new(
/// Arc::new(MockScmBackend::new()))` and drive the lifecycle methods.
pub struct ScmManagerImpl {
    backend: Arc<dyn ScmBackend>,
}

impl ScmManagerImpl {
    /// Construct a manager around the supplied backend.
    pub fn new(backend: Arc<dyn ScmBackend>) -> Self {
        Self { backend }
    }

    /// Install + best-effort start. See module docs for sequencing.
    pub fn install(&self, spec: &ServiceSpec) -> Result<()> {
        // Cheap pre-flight so an immediately-following `create_service` call
        // doesn't blow up with a noisier error if SCM isn't reachable.
        self.backend.open_scm()?;
        self.backend.create_service(spec)?;
        // Best-effort start; post-install start failure is logged but does
        // not fail the install — callers can retry via `start`.
        if let Err(e) = self.backend.start_service(&spec.name) {
            tracing::warn!(error = %e, name = %spec.name, "post-install start failed");
        }
        Ok(())
    }

    /// Idempotent uninstall — unknown services succeed.
    pub fn uninstall(&self, name: &str) -> Result<()> {
        // Idempotent: missing service is success.
        let exists = self
            .backend
            .open_service_for(name, ScmAccess::StopAndDelete)?;
        if !exists {
            return Ok(());
        }
        // Best-effort stop before delete; stop errors are swallowed so we
        // always reach the delete path.
        let _ = self.backend.stop_service(name);
        self.backend.delete_service(name)
    }

    /// Query lifecycle state.
    pub fn status(&self, name: &str) -> Result<ServiceStatus> {
        match self.backend.query_status(name)? {
            None => Ok(ServiceStatus::new(ServiceState::NotInstalled)),
            Some(bs) => Ok(ServiceStatus {
                state: bs.state,
                pid: bs.pid,
                exit_code: bs.exit_code,
                since: None,
                restart_count: None,
            }),
        }
    }

    /// Start the service.
    pub fn start(&self, name: &str) -> Result<()> {
        self.backend.start_service(name)
    }

    /// Stop the service.
    pub fn stop(&self, name: &str) -> Result<()> {
        self.backend.stop_service(name)
    }

    /// Reload (paramchange) — refuses if the service is not running.
    pub fn reload(&self, name: &str) -> Result<()> {
        // Pre-flight: refuse if the service isn't running (so the caller
        // gets a typed error instead of SCM silently dropping the control).
        let precheck = match self.backend.query_status(name)? {
            None => {
                return Err(spt_core::error::Error::ServiceManagerFailed(format!(
                    "reload({name}): service is not installed"
                )));
            }
            Some(bs) if bs.state == ServiceState::Running => ReloadPrecheck::Running,
            Some(bs) => ReloadPrecheck::NotRunning(bs.state),
        };
        match precheck {
            ReloadPrecheck::Running => self.backend.send_paramchange(name),
            ReloadPrecheck::NotRunning(state) => Err(spt_core::error::Error::ServiceManagerFailed(
                format!("reload({name}): service is not running (state {state:?})"),
            )),
        }
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
    /// Service-specific exit code the entry closure wants SCM to report
    /// (E7-F1). Default `0` ⇒ clean exit (`ServiceExitCode::Win32(0)`). A
    /// non-zero value set via [`ScmHandles::set_exit_code`] is reported as
    /// `ServiceExitCode::ServiceSpecific(code)` so a startup/runtime failure
    /// surfaces in SCM and the Event Log instead of looking like a clean stop.
    exit_code: std::sync::atomic::AtomicI32,
}

impl ScmHandles {
    /// Construct an empty `ScmHandles`. Both notifies start un-signalled and
    /// the exit code is `0` (clean).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the service-specific exit code the closure wants SCM to report
    /// (E7-F1). `0` keeps the default clean (`Win32(0)`) mapping; any other
    /// value is reported as `ServiceSpecific(code)`.
    pub fn set_exit_code(&self, code: i32) {
        self.exit_code
            .store(code, std::sync::atomic::Ordering::SeqCst);
    }

    /// The exit code recorded by the entry closure (`0` if none was set).
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(std::sync::atomic::Ordering::SeqCst)
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
// scm_launch_arguments — pure helper, no Win32 reach, cross-platform.
// Exposed (crate-private) so tests can exercise it on every host.
// ============================================================================

/// Render the `launch_arguments` array we hand to SCM.
///
/// Prepends `--scm-dispatch` (idempotent) so the spt-bin entry point can
/// detect SCM-driven invocation before clap parses `Cli`. Cross-platform
/// `ServiceSpec` consumers (systemd / launchd / sysv / openrc render
/// snapshots) do **not** use this helper; they keep `spec.args` verbatim.
///
/// Pure / sync so it's unit-testable without round-tripping SCM.
///
/// Only the Windows SCM registration path (`super::scm_launch_arguments`
/// caller, gated on `cfg(windows)`) consumes this in non-test builds; the
/// cross-platform unit tests below also exercise it. Hence it reads as dead
/// code in a non-Windows, non-test `lib` build.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn scm_launch_arguments(spec_args: &[String]) -> Vec<std::ffi::OsString> {
    const SCM_DISPATCH_FLAG: &str = "--scm-dispatch";
    let mut out: Vec<std::ffi::OsString> = Vec::with_capacity(spec_args.len() + 1);
    if !spec_args.iter().any(|a| a == SCM_DISPATCH_FLAG) {
        out.push(std::ffi::OsString::from(SCM_DISPATCH_FLAG));
    }
    out.extend(spec_args.iter().map(std::ffi::OsString::from));
    out
}

/// Render the full `launch_arguments` array from a [`ServiceSpec`] (E7-F5).
///
/// SCM's `ImagePath` is a flat command line — it carries **no** environment
/// block, so `spec.env` (which on Unix backends propagates `SPT_STATE_DIR`)
/// would otherwise be silently dropped: the `LocalSystem` service would resolve
/// its state dir from `C:\Windows\System32\config\systemprofile\...` while an
/// operator's interactive `spt tunnel status` reads *their* `%LOCALAPPDATA%`,
/// so the two never see the same status/pid/log files.
///
/// To make service and CLI agree we re-materialise `SPT_STATE_DIR` from
/// `spec.env` as an explicit `--state-dir <path>` argument (the SCM dispatch
/// arg parser honours both `--state-dir` and `$SPT_STATE_DIR`). The flag is
/// only appended when the spec actually carries a state dir and the args don't
/// already specify one, so installs that embed `--state-dir` in `spec.args`
/// stay idempotent.
///
/// Pure / sync so it's unit-testable without round-tripping SCM.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn scm_launch_arguments_for_spec(spec: &ServiceSpec) -> Vec<std::ffi::OsString> {
    let mut out = scm_launch_arguments(&spec.args);
    let already_has_state_dir = spec
        .args
        .iter()
        .any(|a| a == "--state-dir" || a.starts_with("--state-dir="));
    if !already_has_state_dir {
        if let Some(state_dir) = spec.env.get("SPT_STATE_DIR") {
            if !state_dir.is_empty() {
                out.push(std::ffi::OsString::from("--state-dir"));
                out.push(std::ffi::OsString::from(state_dir));
            }
        }
    }
    out
}

/// Map a [`RestartPolicy`] onto the SCM failure-actions plan (E7-F5).
///
/// SCM only restarts on **failure** (it has no "always" notion distinct from
/// failure recovery and never re-runs a cleanly-exited service), so both
/// `Always` and `OnFailure` map to a single `Restart` action; `Never` maps to
/// an empty action list (no auto-restart). Returns the typed
/// `(reset_period_secs, restart_delay_secs)` decision so the pure mapping is
/// unit-testable on any host without minting a real `Service` handle.
///
/// `Some((reset_secs, delay_secs))` ⇒ install a single `Restart` action with
/// the given per-attempt delay and failure-count reset window.
/// `None` ⇒ no failure actions (policy `Never`).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn scm_failure_action_plan(policy: crate::RestartPolicy) -> Option<(u64, u64)> {
    match policy {
        // 24h reset window, 5s restart delay — matches the systemd/launchd
        // default crash-recovery cadence closely enough for parity.
        crate::RestartPolicy::Always | crate::RestartPolicy::OnFailure => Some((86_400, 5)),
        crate::RestartPolicy::Never => None,
    }
}

// ============================================================================
// MockScmBackend — records every backend call into a `Mutex<Vec<ScmCall>>`
// and returns programmable canned responses. Available cross-platform behind
// `feature = "testing"` (and for inline `#[cfg(test)]` builds).
// ============================================================================

/// One observed call against a `MockScmBackend`.
// 1.88 lint: large_enum_variant — `CreateService(ServiceSpec)` dwarfs the
// string-only arms. Test-support record type, not a hot path; boxing would
// churn every construction/match site for no runtime benefit.
#[cfg(any(test, feature = "testing"))]
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScmCall {
    /// `open_scm()` — pre-flight before install.
    OpenScm,
    /// `open_service_for(name, access)`.
    OpenServiceFor(String, ScmAccess),
    /// `create_service(spec)`.
    CreateService(ServiceSpec),
    /// `start_service(name)`.
    StartService(String),
    /// `stop_service(name)`.
    StopService(String),
    /// `delete_service(name)`.
    DeleteService(String),
    /// `query_status(name)`.
    QueryStatus(String),
    /// `send_paramchange(name)` — the `sc.exe control paramchange` path.
    SendParamchange(String),
}

/// In-memory recording [`ScmBackend`] for hermetic tests.
///
/// Every call against the trait is recorded into a
/// `parking_lot::Mutex<Vec<ScmCall>>`. Canned responses are configured up
/// front via the `set_*` helpers; any unset response defaults to "success".
///
/// All response handles are cheap clones; the type itself is `Clone` so it
/// can be shared between the test harness and the `Arc<dyn ScmBackend>`
/// view handed to [`ScmManagerImpl::new`].
///
/// ```
/// # use std::sync::Arc;
/// # use spt_service::windows_scm::MockScmBackend;
/// let mock = MockScmBackend::new();
/// let _arc: Arc<dyn spt_service::windows_scm::ScmBackend> = Arc::new(mock.clone());
/// assert_eq!(mock.calls().len(), 0);
/// ```
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone, Default)]
pub struct MockScmBackend {
    inner: Arc<MockInner>,
}

#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
struct MockInner {
    calls: parking_lot::Mutex<Vec<ScmCall>>,
    state: parking_lot::Mutex<MockState>,
}

#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
struct MockState {
    open_scm_err: Option<String>,
    open_service_exists: std::collections::HashMap<String, bool>,
    open_service_err: Option<String>,
    create_service_err: Option<String>,
    start_service_err: Option<String>,
    stop_service_err: Option<String>,
    delete_service_err: Option<String>,
    query_status_results: std::collections::HashMap<String, Option<BackendStatus>>,
    query_status_err: Option<String>,
    send_paramchange_err: Option<String>,
}

#[cfg(any(test, feature = "testing"))]
impl MockScmBackend {
    /// New mock with no programmed responses. All calls succeed; status
    /// queries return `None` (i.e. `NotInstalled`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every recorded call in chronological order.
    #[must_use]
    pub fn calls(&self) -> Vec<ScmCall> {
        self.inner.calls.lock().clone()
    }

    /// Number of calls observed so far.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.inner.calls.lock().len()
    }

    /// Programme [`ScmBackend::open_scm`] to fail with `msg`.
    pub fn set_open_scm_error(&self, msg: impl Into<String>) {
        self.inner.state.lock().open_scm_err = Some(msg.into());
    }

    /// Programme whether `name` is reported as existing by
    /// [`ScmBackend::open_service_for`].
    pub fn set_service_exists(&self, name: impl Into<String>, exists: bool) {
        self.inner
            .state
            .lock()
            .open_service_exists
            .insert(name.into(), exists);
    }

    /// Programme [`ScmBackend::open_service_for`] to fail (used by tests
    /// that want to exercise the SCM-not-reachable error path).
    pub fn set_open_service_error(&self, msg: impl Into<String>) {
        self.inner.state.lock().open_service_err = Some(msg.into());
    }

    /// Programme [`ScmBackend::create_service`] to fail.
    pub fn set_create_service_error(&self, msg: impl Into<String>) {
        self.inner.state.lock().create_service_err = Some(msg.into());
    }

    /// Programme [`ScmBackend::start_service`] to fail.
    pub fn set_start_service_error(&self, msg: impl Into<String>) {
        self.inner.state.lock().start_service_err = Some(msg.into());
    }

    /// Programme [`ScmBackend::stop_service`] to fail.
    pub fn set_stop_service_error(&self, msg: impl Into<String>) {
        self.inner.state.lock().stop_service_err = Some(msg.into());
    }

    /// Programme [`ScmBackend::delete_service`] to fail.
    pub fn set_delete_service_error(&self, msg: impl Into<String>) {
        self.inner.state.lock().delete_service_err = Some(msg.into());
    }

    /// Programme the response to [`ScmBackend::query_status`] for `name`.
    ///
    /// `None` means "service does not exist"; `Some(status)` is returned
    /// verbatim.
    pub fn set_query_status(&self, name: impl Into<String>, result: Option<BackendStatus>) {
        self.inner
            .state
            .lock()
            .query_status_results
            .insert(name.into(), result);
    }

    /// Programme [`ScmBackend::query_status`] to fail.
    pub fn set_query_status_error(&self, msg: impl Into<String>) {
        self.inner.state.lock().query_status_err = Some(msg.into());
    }

    /// Programme [`ScmBackend::send_paramchange`] to fail.
    pub fn set_send_paramchange_error(&self, msg: impl Into<String>) {
        self.inner.state.lock().send_paramchange_err = Some(msg.into());
    }

    fn record(&self, call: ScmCall) {
        self.inner.calls.lock().push(call);
    }
}

#[cfg(any(test, feature = "testing"))]
impl ScmBackend for MockScmBackend {
    fn open_scm(&self) -> Result<()> {
        self.record(ScmCall::OpenScm);
        if let Some(msg) = self.inner.state.lock().open_scm_err.clone() {
            return Err(spt_core::error::Error::ServiceManagerFailed(msg));
        }
        Ok(())
    }

    fn open_service_for(&self, name: &str, access: ScmAccess) -> Result<bool> {
        self.record(ScmCall::OpenServiceFor(name.to_string(), access));
        let st = self.inner.state.lock();
        if let Some(msg) = st.open_service_err.clone() {
            return Err(spt_core::error::Error::ServiceManagerFailed(msg));
        }
        // Default: exists = false (matches "uninstall of an unknown svc is a
        // no-op" semantics).
        Ok(st.open_service_exists.get(name).copied().unwrap_or(false))
    }

    fn create_service(&self, spec: &ServiceSpec) -> Result<()> {
        self.record(ScmCall::CreateService(spec.clone()));
        if let Some(msg) = self.inner.state.lock().create_service_err.clone() {
            return Err(spt_core::error::Error::ServiceManagerFailed(msg));
        }
        Ok(())
    }

    fn start_service(&self, name: &str) -> Result<()> {
        self.record(ScmCall::StartService(name.to_string()));
        if let Some(msg) = self.inner.state.lock().start_service_err.clone() {
            return Err(spt_core::error::Error::ServiceManagerFailed(msg));
        }
        Ok(())
    }

    fn stop_service(&self, name: &str) -> Result<()> {
        self.record(ScmCall::StopService(name.to_string()));
        if let Some(msg) = self.inner.state.lock().stop_service_err.clone() {
            return Err(spt_core::error::Error::ServiceManagerFailed(msg));
        }
        Ok(())
    }

    fn delete_service(&self, name: &str) -> Result<()> {
        self.record(ScmCall::DeleteService(name.to_string()));
        if let Some(msg) = self.inner.state.lock().delete_service_err.clone() {
            return Err(spt_core::error::Error::ServiceManagerFailed(msg));
        }
        Ok(())
    }

    fn query_status(&self, name: &str) -> Result<Option<BackendStatus>> {
        self.record(ScmCall::QueryStatus(name.to_string()));
        let st = self.inner.state.lock();
        if let Some(msg) = st.query_status_err.clone() {
            return Err(spt_core::error::Error::ServiceManagerFailed(msg));
        }
        Ok(st.query_status_results.get(name).copied().unwrap_or(None))
    }

    fn send_paramchange(&self, name: &str) -> Result<()> {
        self.record(ScmCall::SendParamchange(name.to_string()));
        if let Some(msg) = self.inner.state.lock().send_paramchange_err.clone() {
            return Err(spt_core::error::Error::ServiceManagerFailed(msg));
        }
        Ok(())
    }
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
        Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl,
        ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState as WinServiceState,
        ServiceStatus as WinServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;
    use windows_service::service_manager::{ServiceManager as ScmHandle, ServiceManagerAccess};

    use crate::{ServiceSpec, ServiceState, ServiceStatus};

    use super::{BackendStatus, ScmAccess, ScmHandles, ScmManagerImpl, WindowsServiceCrateBackend};

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

    /// Decode `windows_service::ServiceAccess` from our portable enum.
    fn map_access(a: ScmAccess) -> ServiceAccess {
        match a {
            ScmAccess::QueryStatus => ServiceAccess::QUERY_STATUS,
            ScmAccess::StopAndDelete => ServiceAccess::STOP | ServiceAccess::DELETE,
            ScmAccess::Start => ServiceAccess::START,
            ScmAccess::Stop => ServiceAccess::STOP,
        }
    }

    fn open_scm(access: ServiceManagerAccess) -> Result<ScmHandle> {
        ScmHandle::local_computer(None::<&str>, access)
            .map_err(|e| Error::ServiceManagerFailed(format!("open SCM: {e}")))
    }

    /// Pre-flight: open SCM with `CREATE_SERVICE` rights. Used by
    /// [`WindowsServiceCrateBackend::open_scm`] as an installable-check.
    pub(super) fn open_scm_for_create() -> Result<ScmHandle> {
        open_scm(ServiceManagerAccess::CREATE_SERVICE)
    }

    fn open_service_for(name: &str, access: ServiceAccess) -> Result<Service> {
        let scm = open_scm(ServiceManagerAccess::CONNECT)?;
        scm.open_service(name, access)
            .map_err(|e| Error::ServiceManagerFailed(format!("open_service({name}): {e}")))
    }

    /// Open `name` with `access` and report whether the open succeeded.
    ///
    /// Returns `Ok(false)` when the service does not exist — `open_service`
    /// returning an error is the SCM-native idiom for "doesn't exist", but
    /// we cannot inspect the error variant generically because
    /// `windows-service` 0.7 wraps Win32 errors opaquely. Any error here
    /// surfaces as `Ok(false)` to match the original behaviour of
    /// `uninstall` / `status` (which short-circuit on open failure).
    pub(super) fn open_service_exists(name: &str, access: ScmAccess) -> Result<bool> {
        let scm = open_scm(ServiceManagerAccess::CONNECT)?;
        match scm.open_service(name, map_access(access)) {
            Ok(_svc) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Real `create_service` impl.
    pub(super) fn do_create_service(spec: &ServiceSpec) -> Result<()> {
        let scm = open_scm(ServiceManagerAccess::CREATE_SERVICE)?;
        let info = ServiceInfo {
            name: OsString::from(&spec.name),
            display_name: OsString::from(&spec.description),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: spec.exec_path.clone(),
            // E7-F5: embed `--state-dir <resolved>` (from spec.env's
            // SPT_STATE_DIR) into the ImagePath so the LocalSystem service and
            // an operator's CLI resolve the *same* state dir. SCM ImagePaths
            // carry no environment block, so this is the only channel.
            launch_arguments: super::scm_launch_arguments_for_spec(spec),
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        let service = scm
            .create_service(&info, ServiceAccess::START | ServiceAccess::CHANGE_CONFIG)
            .map_err(|e| Error::ServiceManagerFailed(format!("create_service: {e}")))?;

        // E7-F5: apply the restart policy via SERVICE_CONFIG_FAILURE_ACTIONS.
        // Without this, `RestartPolicy::Always`/`OnFailure` has no effect on
        // Windows (SCM never auto-restarts a crashed service), diverging from
        // systemd/launchd/openrc which all restart. Best-effort: a failure here
        // is logged but does not fail the whole install (the service is already
        // created and startable).
        apply_failure_actions(&service, spec.restart_policy);
        Ok(())
    }

    /// Configure SCM crash-recovery for a freshly created service (E7-F5).
    ///
    /// Translates the spec's [`crate::RestartPolicy`] into a
    /// `SERVICE_CONFIG_FAILURE_ACTIONS` plan via
    /// [`super::scm_failure_action_plan`] and pushes it with
    /// `Service::update_failure_actions`. `RestartPolicy::Never` clears the
    /// action list (no auto-restart).
    fn apply_failure_actions(service: &Service, policy: crate::RestartPolicy) {
        let (reset_secs, actions) = match super::scm_failure_action_plan(policy) {
            Some((reset_secs, delay_secs)) => (
                reset_secs,
                Some(vec![ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(delay_secs),
                }]),
            ),
            None => (0, Some(Vec::new())),
        };
        let failure_actions = ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(reset_secs)),
            reboot_msg: None,
            command: None,
            actions,
        };
        if let Err(e) = service.update_failure_actions(failure_actions) {
            tracing::warn!(error = %e, "create_service: failed to apply restart policy (failure actions)");
        }
    }

    pub(super) fn do_start_service(name: &str) -> Result<()> {
        let svc = open_service_for(name, ServiceAccess::START)?;
        svc.start::<&str>(&[])
            .map_err(|e| Error::ServiceManagerFailed(format!("start({name}): {e}")))?;
        Ok(())
    }

    pub(super) fn do_stop_service(name: &str) -> Result<()> {
        let svc = open_service_for(name, ServiceAccess::STOP)?;
        svc.stop()
            .map_err(|e| Error::ServiceManagerFailed(format!("stop({name}): {e}")))?;
        Ok(())
    }

    pub(super) fn do_delete_service(name: &str) -> Result<()> {
        let svc = open_service_for(name, ServiceAccess::STOP | ServiceAccess::DELETE)?;
        let _ = svc.stop();
        svc.delete()
            .map_err(|e| Error::ServiceManagerFailed(format!("delete service: {e}")))?;
        Ok(())
    }

    pub(super) fn do_query_status(name: &str) -> Result<Option<BackendStatus>> {
        let scm = open_scm(ServiceManagerAccess::CONNECT)?;
        let Ok(svc) = scm.open_service(name, ServiceAccess::QUERY_STATUS) else {
            return Ok(None);
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
        Ok(Some(BackendStatus {
            state: map_state(st.current_state),
            pid: st.process_id,
            exit_code,
        }))
    }

    pub(super) fn do_send_paramchange(name: &str) -> Result<()> {
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

    // --- Thin wrappers used by the async `impl ServiceManager for
    // WindowsScmManager` above. Each one builds a fresh ScmManagerImpl
    // around the real backend and forwards. Keeping the free fns at
    // module level lets us reuse the existing spawn_blocking call sites
    // without changing the public surface.

    fn manager() -> ScmManagerImpl {
        ScmManagerImpl::new(Arc::new(WindowsServiceCrateBackend))
    }

    pub(super) fn install(spec: &ServiceSpec) -> Result<()> {
        manager().install(spec)
    }

    pub(super) fn uninstall(name: &str) -> Result<()> {
        manager().uninstall(name)
    }

    pub(super) fn status(name: &str) -> Result<ServiceStatus> {
        manager().status(name)
    }

    pub(super) fn start(name: &str) -> Result<()> {
        manager().start(name)
    }

    pub(super) fn stop(name: &str) -> Result<()> {
        manager().stop(name)
    }

    pub(super) fn reload(name: &str) -> Result<()> {
        manager().reload(name)
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
        let entry: EntryFn = match ENTRY
            .get()
            .and_then(|m| m.lock().ok().and_then(|mut g| g.take()))
        {
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
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
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
        let accepted = ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN
            | ServiceControlAccept::PARAM_CHANGE;
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
        let no_panic = worker.join().unwrap_or(false);

        // Decide the exit code reported to SCM (E7-F1):
        //   * worker panicked            → ServiceSpecific(99)
        //   * worker set a non-zero code → ServiceSpecific(code) (startup or
        //                                  runtime failure — visible, NOT a
        //                                  clean stop)
        //   * otherwise                  → Win32(0) (clean stop)
        let exit_code = if no_panic {
            let code = handles.exit_code();
            if code == 0 {
                ServiceExitCode::Win32(0)
            } else {
                ServiceExitCode::ServiceSpecific(u32::from_ne_bytes(code.to_ne_bytes()))
            }
        } else {
            ServiceExitCode::ServiceSpecific(99)
        };

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
            exit_code,
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

        #[test]
        fn map_access_round_trips_each_variant() {
            assert_eq!(
                map_access(ScmAccess::QueryStatus),
                ServiceAccess::QUERY_STATUS
            );
            assert_eq!(
                map_access(ScmAccess::StopAndDelete),
                ServiceAccess::STOP | ServiceAccess::DELETE
            );
            assert_eq!(map_access(ScmAccess::Start), ServiceAccess::START);
            assert_eq!(map_access(ScmAccess::Stop), ServiceAccess::STOP);
        }
    }
}

// ============================================================================
// Tests (cross-platform — exercise ScmManagerImpl via MockScmBackend, plus
// capabilities + non-Windows stub paths; real SCM round-trip lives in gated
// integration tests below).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServiceSpec;

    fn sample_spec(name: &str) -> ServiceSpec {
        ServiceSpec {
            name: name.to_string(),
            description: format!("spt — test svc {name}"),
            ..Default::default()
        }
    }

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

    fn pick_default<T: Default>() -> T {
        T::default()
    }

    #[test]
    fn windows_scm_manager_is_copy_and_default_constructible() {
        // Trips the compiler if anyone removes Copy/Default/Clone from the
        // public type. `pick_default::<T>` exercises the `Default` impl
        // without triggering clippy's "default_constructed_unit_structs".
        let a = WindowsScmManager;
        let b: WindowsScmManager = a;
        let _c: WindowsScmManager = pick_default();
        assert_eq!(a.name(), b.name());
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
        let _ = format!("{h:?}");
    }

    #[test]
    fn scm_handles_exit_code_defaults_zero_and_round_trips() {
        let h = ScmHandles::new();
        assert_eq!(h.exit_code(), 0);
        h.set_exit_code(7);
        assert_eq!(h.exit_code(), 7);
        // Last writer wins.
        h.set_exit_code(0);
        assert_eq!(h.exit_code(), 0);
    }

    // ------------------------------------------------------------------
    // scm_launch_arguments — pure helper, cross-platform.
    // ------------------------------------------------------------------

    #[test]
    fn scm_launch_arguments_prepends_scm_dispatch_flag() {
        let args = vec![
            "tunnel".to_string(),
            "run".to_string(),
            "--foreground".to_string(),
            "--config".to_string(),
            "/etc/spt/spt.toml".to_string(),
        ];
        let rendered = scm_launch_arguments(&args);
        assert_eq!(
            rendered.first().and_then(|s| s.to_str()),
            Some("--scm-dispatch")
        );
        assert_eq!(rendered.len(), args.len() + 1);
        for (i, a) in args.iter().enumerate() {
            assert_eq!(rendered[i + 1].to_str(), Some(a.as_str()));
        }
    }

    #[test]
    fn scm_launch_arguments_is_idempotent() {
        let args = vec![
            "--scm-dispatch".to_string(),
            "tunnel".to_string(),
            "run".to_string(),
        ];
        let rendered = scm_launch_arguments(&args);
        assert_eq!(rendered.len(), args.len());
        let count = rendered
            .iter()
            .filter(|a| a.to_str() == Some("--scm-dispatch"))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn scm_launch_arguments_empty_input_yields_just_the_flag() {
        let rendered = scm_launch_arguments(&[]);
        assert_eq!(rendered.len(), 1);
        assert_eq!(rendered[0].to_str(), Some("--scm-dispatch"));
    }

    // ------------------------------------------------------------------
    // E7-F5: state-dir injection + failure-action plan (pure, cross-platform).
    // ------------------------------------------------------------------

    #[test]
    fn launch_arguments_for_spec_injects_state_dir_from_env() {
        let mut spec = sample_spec("svc");
        spec.args = vec!["tunnel".into(), "run".into()];
        spec.env
            .insert("SPT_STATE_DIR".into(), "C:\\spt\\state".into());
        let rendered: Vec<String> = scm_launch_arguments_for_spec(&spec)
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(rendered[0], "--scm-dispatch");
        // The state dir must be present as an explicit flag + value pair.
        let idx = rendered
            .iter()
            .position(|a| a == "--state-dir")
            .expect("--state-dir flag injected");
        assert_eq!(rendered[idx + 1], "C:\\spt\\state");
    }

    #[test]
    fn launch_arguments_for_spec_no_state_dir_when_env_absent() {
        let mut spec = sample_spec("svc");
        spec.args = vec!["tunnel".into(), "run".into()];
        let rendered: Vec<String> = scm_launch_arguments_for_spec(&spec)
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(!rendered.iter().any(|a| a == "--state-dir"));
    }

    #[test]
    fn launch_arguments_for_spec_does_not_double_state_dir() {
        let mut spec = sample_spec("svc");
        spec.args = vec![
            "tunnel".into(),
            "run".into(),
            "--state-dir".into(),
            "C:\\explicit".into(),
        ];
        spec.env
            .insert("SPT_STATE_DIR".into(), "C:\\from-env".into());
        let rendered: Vec<String> = scm_launch_arguments_for_spec(&spec)
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        let count = rendered.iter().filter(|a| *a == "--state-dir").count();
        assert_eq!(count, 1, "must not duplicate an explicit --state-dir");
        assert!(rendered.iter().any(|a| a == "C:\\explicit"));
        assert!(!rendered.iter().any(|a| a == "C:\\from-env"));
    }

    #[test]
    fn failure_action_plan_restarts_on_failure_and_always() {
        use crate::RestartPolicy;
        assert_eq!(
            scm_failure_action_plan(RestartPolicy::OnFailure),
            Some((86_400, 5))
        );
        assert_eq!(
            scm_failure_action_plan(RestartPolicy::Always),
            Some((86_400, 5))
        );
    }

    #[test]
    fn failure_action_plan_never_has_no_actions() {
        use crate::RestartPolicy;
        assert_eq!(scm_failure_action_plan(RestartPolicy::Never), None);
    }

    // ------------------------------------------------------------------
    // Mock + ScmManagerImpl — happy paths.
    // ------------------------------------------------------------------

    #[test]
    fn install_records_open_scm_create_and_start_in_order() {
        let mock = MockScmBackend::new();
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        let spec = sample_spec("svc-install");
        mgr.install(&spec).unwrap();
        let calls = mock.calls();
        assert!(matches!(calls[0], ScmCall::OpenScm));
        assert!(matches!(&calls[1], ScmCall::CreateService(s) if s.name == "svc-install"));
        assert!(matches!(&calls[2], ScmCall::StartService(n) if n == "svc-install"));
        assert_eq!(calls.len(), 3);
    }

    #[test]
    fn install_open_scm_failure_short_circuits() {
        let mock = MockScmBackend::new();
        mock.set_open_scm_error("access denied");
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        let err = mgr.install(&sample_spec("svc-x")).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("access denied"), "got: {msg}");
        // create_service must NOT have been called.
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], ScmCall::OpenScm));
    }

    #[test]
    fn install_create_failure_propagates_without_start() {
        let mock = MockScmBackend::new();
        mock.set_create_service_error("dupe name");
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        let err = mgr.install(&sample_spec("svc-dupe")).unwrap_err();
        assert!(format!("{err}").contains("dupe name"));
        let calls = mock.calls();
        // OpenScm + CreateService, no Start.
        assert_eq!(calls.len(), 2);
        assert!(!calls.iter().any(|c| matches!(c, ScmCall::StartService(_))));
    }

    #[test]
    fn install_start_failure_does_not_fail_install() {
        let mock = MockScmBackend::new();
        mock.set_start_service_error("start failed");
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        mgr.install(&sample_spec("svc-warn")).unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 3);
        assert!(matches!(calls[2], ScmCall::StartService(_)));
    }

    #[test]
    fn uninstall_unknown_service_is_no_op() {
        let mock = MockScmBackend::new();
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        mgr.uninstall("ghost").unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            matches!(&calls[0], ScmCall::OpenServiceFor(n, ScmAccess::StopAndDelete) if n == "ghost")
        );
    }

    #[test]
    fn uninstall_existing_service_stops_then_deletes() {
        let mock = MockScmBackend::new();
        mock.set_service_exists("svc-real", true);
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        mgr.uninstall("svc-real").unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 3);
        assert!(matches!(&calls[0], ScmCall::OpenServiceFor(n, _) if n == "svc-real"));
        assert!(matches!(&calls[1], ScmCall::StopService(n) if n == "svc-real"));
        assert!(matches!(&calls[2], ScmCall::DeleteService(n) if n == "svc-real"));
    }

    #[test]
    fn uninstall_swallows_stop_error_and_still_deletes() {
        let mock = MockScmBackend::new();
        mock.set_service_exists("svc-locked", true);
        mock.set_stop_service_error("service won't stop");
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        mgr.uninstall("svc-locked").unwrap();
        let calls = mock.calls();
        // Stop attempted, but Delete still called and succeeded.
        assert!(calls.iter().any(|c| matches!(c, ScmCall::StopService(_))));
        assert!(calls.iter().any(|c| matches!(c, ScmCall::DeleteService(_))));
    }

    #[test]
    fn uninstall_delete_error_propagates() {
        let mock = MockScmBackend::new();
        mock.set_service_exists("svc", true);
        mock.set_delete_service_error("delete forbidden");
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        let err = mgr.uninstall("svc").unwrap_err();
        assert!(format!("{err}").contains("delete forbidden"));
    }

    #[test]
    fn uninstall_open_service_error_propagates() {
        let mock = MockScmBackend::new();
        mock.set_open_service_error("rpc unavailable");
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        let err = mgr.uninstall("svc").unwrap_err();
        assert!(format!("{err}").contains("rpc unavailable"));
    }

    // ------------------------------------------------------------------
    // Status
    // ------------------------------------------------------------------

    #[test]
    fn status_missing_service_yields_not_installed() {
        let mock = MockScmBackend::new();
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        let st = mgr.status("ghost").unwrap();
        assert_eq!(st.state, ServiceState::NotInstalled);
        assert!(st.pid.is_none());
        assert!(st.exit_code.is_none());
        // QueryStatus call was recorded.
        assert!(matches!(&mock.calls()[0], ScmCall::QueryStatus(n) if n == "ghost"));
    }

    #[test]
    fn status_running_propagates_pid_and_state() {
        let mock = MockScmBackend::new();
        mock.set_query_status(
            "svc-up",
            Some(BackendStatus {
                state: ServiceState::Running,
                pid: Some(1234),
                exit_code: None,
            }),
        );
        let mgr = ScmManagerImpl::new(Arc::new(mock));
        let st = mgr.status("svc-up").unwrap();
        assert_eq!(st.state, ServiceState::Running);
        assert_eq!(st.pid, Some(1234));
        assert!(st.exit_code.is_none());
        assert!(st.since.is_none());
        assert!(st.restart_count.is_none());
    }

    #[test]
    fn status_stopped_with_exit_code_propagates() {
        let mock = MockScmBackend::new();
        mock.set_query_status(
            "svc-fail",
            Some(BackendStatus {
                state: ServiceState::Stopped,
                pid: None,
                exit_code: Some(42),
            }),
        );
        let mgr = ScmManagerImpl::new(Arc::new(mock));
        let st = mgr.status("svc-fail").unwrap();
        assert_eq!(st.state, ServiceState::Stopped);
        assert_eq!(st.exit_code, Some(42));
    }

    #[test]
    fn status_backend_error_propagates() {
        let mock = MockScmBackend::new();
        mock.set_query_status_error("scm down");
        let mgr = ScmManagerImpl::new(Arc::new(mock));
        let err = mgr.status("svc").unwrap_err();
        assert!(format!("{err}").contains("scm down"));
    }

    // ------------------------------------------------------------------
    // Start / Stop pass-through
    // ------------------------------------------------------------------

    #[test]
    fn start_passes_through_to_backend() {
        let mock = MockScmBackend::new();
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        mgr.start("svc").unwrap();
        assert!(matches!(&mock.calls()[0], ScmCall::StartService(n) if n == "svc"));
    }

    #[test]
    fn start_error_propagates() {
        let mock = MockScmBackend::new();
        mock.set_start_service_error("boom");
        let mgr = ScmManagerImpl::new(Arc::new(mock));
        let err = mgr.start("svc").unwrap_err();
        assert!(format!("{err}").contains("boom"));
    }

    #[test]
    fn stop_passes_through_to_backend() {
        let mock = MockScmBackend::new();
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        mgr.stop("svc").unwrap();
        assert!(matches!(&mock.calls()[0], ScmCall::StopService(n) if n == "svc"));
    }

    #[test]
    fn stop_error_propagates() {
        let mock = MockScmBackend::new();
        mock.set_stop_service_error("nope");
        let mgr = ScmManagerImpl::new(Arc::new(mock));
        let err = mgr.stop("svc").unwrap_err();
        assert!(format!("{err}").contains("nope"));
    }

    // ------------------------------------------------------------------
    // Reload
    // ------------------------------------------------------------------

    #[test]
    fn reload_on_running_service_sends_paramchange() {
        let mock = MockScmBackend::new();
        mock.set_query_status(
            "svc-up",
            Some(BackendStatus {
                state: ServiceState::Running,
                pid: Some(1),
                exit_code: None,
            }),
        );
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        mgr.reload("svc-up").unwrap();
        let calls = mock.calls();
        assert!(matches!(&calls[0], ScmCall::QueryStatus(n) if n == "svc-up"));
        assert!(matches!(&calls[1], ScmCall::SendParamchange(n) if n == "svc-up"));
    }

    #[test]
    fn reload_on_stopped_service_errors_without_paramchange() {
        let mock = MockScmBackend::new();
        mock.set_query_status(
            "svc-down",
            Some(BackendStatus {
                state: ServiceState::Stopped,
                pid: None,
                exit_code: None,
            }),
        );
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        let err = mgr.reload("svc-down").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not running"), "got: {msg}");
        // No paramchange sent.
        assert!(!mock
            .calls()
            .iter()
            .any(|c| matches!(c, ScmCall::SendParamchange(_))));
    }

    #[test]
    fn reload_on_unknown_state_errors_without_paramchange() {
        let mock = MockScmBackend::new();
        mock.set_query_status(
            "svc-pend",
            Some(BackendStatus {
                state: ServiceState::Unknown,
                pid: None,
                exit_code: None,
            }),
        );
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        let err = mgr.reload("svc-pend").unwrap_err();
        assert!(format!("{err}").contains("not running"));
    }

    #[test]
    fn reload_on_missing_service_errors_with_typed_message() {
        let mock = MockScmBackend::new();
        let mgr = ScmManagerImpl::new(Arc::new(mock.clone()));
        let err = mgr.reload("ghost").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not installed"), "got: {msg}");
    }

    #[test]
    fn reload_query_status_error_propagates() {
        let mock = MockScmBackend::new();
        mock.set_query_status_error("scm error");
        let mgr = ScmManagerImpl::new(Arc::new(mock));
        let err = mgr.reload("svc").unwrap_err();
        assert!(format!("{err}").contains("scm error"));
    }

    #[test]
    fn reload_paramchange_failure_propagates() {
        let mock = MockScmBackend::new();
        mock.set_query_status(
            "svc",
            Some(BackendStatus {
                state: ServiceState::Running,
                pid: Some(1),
                exit_code: None,
            }),
        );
        mock.set_send_paramchange_error("sc.exe exit 5");
        let mgr = ScmManagerImpl::new(Arc::new(mock));
        let err = mgr.reload("svc").unwrap_err();
        assert!(format!("{err}").contains("sc.exe exit 5"));
    }

    // ------------------------------------------------------------------
    // ScmCall + BackendStatus + ScmAccess derives
    // ------------------------------------------------------------------

    #[test]
    fn scm_call_derives_debug_clone_eq() {
        let c = ScmCall::StartService("svc".into());
        let c2 = c.clone();
        assert_eq!(c, c2);
        let _ = format!("{c:?}");
    }

    #[test]
    fn scm_access_round_trip_via_clone() {
        for a in [
            ScmAccess::QueryStatus,
            ScmAccess::StopAndDelete,
            ScmAccess::Start,
            ScmAccess::Stop,
        ] {
            assert_eq!(a, a);
            let _ = format!("{a:?}");
        }
    }

    #[test]
    fn backend_status_eq_and_debug() {
        let a = BackendStatus {
            state: ServiceState::Running,
            pid: Some(1),
            exit_code: None,
        };
        let b = a;
        assert_eq!(a, b);
        let _ = format!("{a:?}");
    }

    #[test]
    fn mock_default_yields_empty_call_log() {
        let m: MockScmBackend = MockScmBackend::default();
        assert_eq!(m.calls().len(), 0);
        assert_eq!(m.call_count(), 0);
    }

    // ------------------------------------------------------------------
    // WindowsServiceCrateBackend non-Windows stubs (cross-platform sanity).
    //
    // These only execute on non-Windows targets. On Windows the real impl
    // would touch SCM and must NOT run from unit tests.
    // ------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn real_backend_stubs_return_unsupported_on_non_windows() {
        use spt_core::error::Error;
        let be = WindowsServiceCrateBackend;
        for err in [
            be.open_scm().unwrap_err(),
            be.open_service_for("x", ScmAccess::Start).unwrap_err(),
            be.create_service(&ServiceSpec::default()).unwrap_err(),
            be.start_service("x").unwrap_err(),
            be.stop_service("x").unwrap_err(),
            be.delete_service("x").unwrap_err(),
            be.send_paramchange("x").unwrap_err(),
        ] {
            assert!(matches!(err, Error::UnsupportedPlatform(_)));
        }
        // query_status returns Result<Option<_>>; check separately.
        assert!(matches!(
            be.query_status("x").unwrap_err(),
            Error::UnsupportedPlatform(_)
        ));
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

    /// Drive the real `WindowsServiceCrateBackend` through the full
    /// install/start/status/stop/uninstall cycle. Requires Administrator.
    ///
    /// This is the only test that exercises the real backend's
    /// `windows-service`-crate calls — every other test uses
    /// `MockScmBackend`.
    #[tokio::test]
    #[ignore = "requires admin and a real Windows session"]
    async fn real_backend_full_lifecycle() {
        use std::sync::Arc;
        let backend = Arc::new(WindowsServiceCrateBackend);
        let mgr = ScmManagerImpl::new(backend);
        let name = unique_name();
        let spec = ServiceSpec {
            name: name.clone(),
            description: "spt — real backend lifecycle".into(),
            exec_path: cmd_exe_path(),
            args: vec!["/c".into(), "exit".into(), "0".into()],
            ..Default::default()
        };
        mgr.install(&spec).expect("install");
        let st = mgr.status(&name).expect("status");
        assert_ne!(st.state, crate::ServiceState::NotInstalled);
        mgr.uninstall(&name).expect("uninstall");
        let st2 = mgr.status(&name).expect("status post-uninstall");
        assert_eq!(st2.state, crate::ServiceState::NotInstalled);
    }
}
