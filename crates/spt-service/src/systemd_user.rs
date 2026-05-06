//! systemd user-scope service manager.
//!
//! Renders to `~/.config/systemd/user/<name>.service` and uses
//! `systemctl --user`. `User=`/`Group=` are dropped because the unit runs as
//! the invoking user.

#[cfg(target_os = "linux")]
use spt_core::error::Error;
use spt_core::error::Result;

use crate::{systemd_system, ServiceManager, ServiceSpec};
#[cfg(target_os = "linux")]
use crate::ServiceStatus;

/// Manager for systemd in **user** scope.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemdUserManager;

impl SystemdUserManager {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceManager for SystemdUserManager {
    fn render(&self, spec: &ServiceSpec) -> Result<String> {
        Ok(systemd_system::render_unit(spec, /* user_scope */ true))
    }

    #[cfg(target_os = "linux")]
    fn install(&self, spec: &ServiceSpec) -> Result<()> {
        let unit = systemd_system::render_unit(spec, true);
        let dir = dirs_user_systemd()?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::ServiceManagerFailed(format!("mkdir {dir:?}: {e}")))?;
        let path = dir.join(format!("{}.service", spec.name));
        std::fs::write(&path, unit)
            .map_err(|e| Error::ServiceManagerFailed(format!("write {path:?}: {e}")))?;
        run_user(&["daemon-reload"])?;
        run_user(&["enable", &spec.name])?;
        run_user(&["start", &spec.name])?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn uninstall(&self, name: &str) -> Result<()> {
        let _ = run_user(&["stop", name]);
        let _ = run_user(&["disable", name]);
        let dir = dirs_user_systemd()?;
        let path = dir.join(format!("{name}.service"));
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| Error::ServiceManagerFailed(format!("remove {path:?}: {e}")))?;
        }
        let _ = run_user(&["daemon-reload"]);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn status(&self, name: &str) -> Result<ServiceStatus> {
        let out = std::process::Command::new("systemctl")
            .args(["--user", "is-active", name])
            .output()
            .map_err(|e| Error::ServiceManagerFailed(format!("systemctl --user: {e}")))?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Ok(match s.as_str() {
            "active" => ServiceStatus::Running,
            "inactive" | "failed" => ServiceStatus::Stopped,
            "" => ServiceStatus::NotInstalled,
            _ => ServiceStatus::Unknown,
        })
    }

    #[cfg(target_os = "linux")]
    fn start(&self, name: &str) -> Result<()> {
        run_user(&["start", name])
    }
    #[cfg(target_os = "linux")]
    fn stop(&self, name: &str) -> Result<()> {
        run_user(&["stop", name])
    }
    #[cfg(target_os = "linux")]
    fn restart(&self, name: &str) -> Result<()> {
        run_user(&["restart", name])
    }
    #[cfg(target_os = "linux")]
    fn reload(&self, name: &str) -> Result<()> {
        run_user(&["reload-or-restart", name])
    }
}

#[cfg(target_os = "linux")]
fn dirs_user_systemd() -> Result<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| Error::ServiceManagerFailed("HOME not set".into()))?;
    Ok(std::path::PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user"))
}

#[cfg(target_os = "linux")]
fn run_user(args: &[&str]) -> Result<()> {
    let mut full = vec!["--user"];
    full.extend(args);
    let st = std::process::Command::new("systemctl")
        .args(&full)
        .status()
        .map_err(|e| Error::ServiceManagerFailed(format!("systemctl --user: {e}")))?;
    if st.success() {
        Ok(())
    } else {
        Err(Error::ServiceManagerFailed(format!(
            "systemctl --user {args:?} exited {st}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_spec;

    #[test]
    fn user_unit_drops_user_group_and_targets_default() {
        let mgr = SystemdUserManager::new();
        let out = mgr.render(&sample_spec()).unwrap();
        assert!(!out.contains("User=spt"));
        assert!(!out.contains("Group=spt"));
        assert!(out.contains("WantedBy=default.target"));
    }

    #[test]
    fn snapshot_systemd_user() {
        let mgr = SystemdUserManager::new();
        let out = mgr.render(&sample_spec()).unwrap();
        insta::assert_snapshot!("systemd_user_unit", out);
    }
}
