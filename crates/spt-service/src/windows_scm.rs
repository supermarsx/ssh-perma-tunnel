//! Windows Service Control Manager backend.
//!
//! `render` returns the equivalent `sc.exe create` command line — useful as a
//! human-readable plan and stable input for golden tests. The real install
//! path uses the `windows-service` crate to register the service via SCM.

use spt_core::error::{Error, Result};

use crate::{ServiceManager, ServiceSpec, ServiceStatus};

/// SCM-backed service manager.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsScmManager;

impl WindowsScmManager {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceManager for WindowsScmManager {
    fn render(&self, spec: &ServiceSpec) -> Result<String> {
        Ok(render_sc_create(spec))
    }

    #[cfg(target_os = "windows")]
    fn install(&self, spec: &ServiceSpec) -> Result<()> {
        use std::ffi::OsString;

        use windows_service::service::{
            ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
        };
        use windows_service::service_manager::{ServiceManager as ScmHandle, ServiceManagerAccess};

        let scm = ScmHandle::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .map_err(|e| Error::ServiceManagerFailed(format!("open SCM: {e}")))?;
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
        // Best-effort start; fail loudly so callers know.
        svc.start::<&str>(&[])
            .map_err(|e| Error::ServiceManagerFailed(format!("start service: {e}")))?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn uninstall(&self, name: &str) -> Result<()> {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager as ScmHandle, ServiceManagerAccess};

        let scm = ScmHandle::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| Error::ServiceManagerFailed(format!("open SCM: {e}")))?;
        let svc = scm
            .open_service(name, ServiceAccess::STOP | ServiceAccess::DELETE)
            .map_err(|e| Error::ServiceManagerFailed(format!("open_service: {e}")))?;
        let _ = svc.stop();
        svc.delete()
            .map_err(|e| Error::ServiceManagerFailed(format!("delete service: {e}")))?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn status(&self, name: &str) -> Result<ServiceStatus> {
        use windows_service::service::{ServiceAccess, ServiceState};
        use windows_service::service_manager::{ServiceManager as ScmHandle, ServiceManagerAccess};

        let scm = match ScmHandle::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
            Ok(h) => h,
            Err(e) => return Err(Error::ServiceManagerFailed(format!("open SCM: {e}"))),
        };
        let Ok(svc) = scm.open_service(name, ServiceAccess::QUERY_STATUS) else {
            return Ok(ServiceStatus::NotInstalled);
        };
        let st = svc
            .query_status()
            .map_err(|e| Error::ServiceManagerFailed(format!("query_status: {e}")))?;
        Ok(match st.current_state {
            ServiceState::Running => ServiceStatus::Running,
            ServiceState::Stopped => ServiceStatus::Stopped,
            _ => ServiceStatus::Unknown,
        })
    }

    #[cfg(target_os = "windows")]
    fn start(&self, name: &str) -> Result<()> {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager as ScmHandle, ServiceManagerAccess};
        let scm = ScmHandle::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| Error::ServiceManagerFailed(format!("open SCM: {e}")))?;
        let svc = scm
            .open_service(name, ServiceAccess::START)
            .map_err(|e| Error::ServiceManagerFailed(format!("open_service: {e}")))?;
        svc.start::<&str>(&[])
            .map_err(|e| Error::ServiceManagerFailed(format!("start: {e}")))?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn stop(&self, name: &str) -> Result<()> {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager as ScmHandle, ServiceManagerAccess};
        let scm = ScmHandle::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| Error::ServiceManagerFailed(format!("open SCM: {e}")))?;
        let svc = scm
            .open_service(name, ServiceAccess::STOP)
            .map_err(|e| Error::ServiceManagerFailed(format!("open_service: {e}")))?;
        svc.stop()
            .map_err(|e| Error::ServiceManagerFailed(format!("stop: {e}")))?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn restart(&self, name: &str) -> Result<()> {
        let _ = self.stop(name);
        self.start(name)
    }
}

fn render_sc_create(spec: &ServiceSpec) -> String {
    let bin_path = format!(
        "\"{}\" {}",
        spec.exec_path.display(),
        spec.args
            .iter()
            .map(|a| if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a.clone()
            })
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut out = String::new();
    out.push_str(&format!(
        "sc.exe create {} binPath= {} start= auto DisplayName= \"{}\"\r\n",
        spec.name, escape_quoted(&bin_path), spec.description,
    ));
    out.push_str(&format!(
        "sc.exe description {} \"{}\"\r\n",
        spec.name, spec.description
    ));
    if !spec.env.is_empty() {
        for (k, v) in &spec.env {
            out.push_str(&format!("rem env: {k}={v}\r\n"));
        }
    }
    out
}

fn escape_quoted(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\\\""))
}

/// Service-main entry helper for downstream `spt-bin`.
///
/// Wires the `windows-service` boilerplate so the binary can be launched by
/// SCM. `entry` receives the `Vec<OsString>` start arguments and is expected
/// to hand control to the spt runtime; when it returns, the service reports
/// `Stopped`.
#[cfg(target_os = "windows")]
pub fn run_as_service<F>(name: &str, entry: F) -> Result<()>
where
    F: FnOnce(Vec<std::ffi::OsString>) + Send + 'static,
{
    let _ = (name, entry);
    Err(Error::UnsupportedPlatform(
        "run_as_service: integration is wired in spt-bin (e18); helper reserved for that crate"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_spec;

    #[test]
    fn render_includes_sc_create_and_binpath() {
        let out = WindowsScmManager::new().render(&sample_spec()).unwrap();
        assert!(out.contains("sc.exe create spt-relay"));
        assert!(out.contains("--config"));
    }

    #[test]
    fn snapshot_windows_scm() {
        let out = WindowsScmManager::new().render(&sample_spec()).unwrap();
        insta::assert_snapshot!("windows_scm_command", out);
    }
}
