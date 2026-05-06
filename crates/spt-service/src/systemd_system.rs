//! systemd system-scope service manager.
//!
//! Renders a unit at `/etc/systemd/system/<name>.service` from
//! `/packaging/systemd/spt.service.tmpl`. `install` runs
//! `systemctl daemon-reload && systemctl enable && systemctl start` — only
//! on Linux, only when explicitly invoked.

use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
use spt_core::error::Error;
use spt_core::error::Result;

use crate::{template, ServiceManager, ServiceSpec};
#[cfg(target_os = "linux")]
use crate::ServiceStatus;

/// Embedded template — canonical source is `/packaging/systemd/spt.service.tmpl`.
const TEMPLATE: &str = include_str!("../../../packaging/systemd/spt.service.tmpl");

/// Manager for systemd in **system** scope.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemdSystemManager;

impl SystemdSystemManager {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceManager for SystemdSystemManager {
    fn render(&self, spec: &ServiceSpec) -> Result<String> {
        Ok(render_unit(spec, /* user_scope */ false))
    }

    #[cfg(target_os = "linux")]
    fn install(&self, spec: &ServiceSpec) -> Result<()> {
        let unit = render_unit(spec, false);
        let path = format!("/etc/systemd/system/{}.service", spec.name);
        std::fs::write(&path, unit)
            .map_err(|e| Error::ServiceManagerFailed(format!("write {path}: {e}")))?;
        run_systemctl(&["daemon-reload"])?;
        run_systemctl(&["enable", &spec.name])?;
        run_systemctl(&["start", &spec.name])?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn uninstall(&self, name: &str) -> Result<()> {
        // Best-effort stop+disable, then remove file. Each step's failure is
        // non-fatal except the final unlink.
        let _ = run_systemctl(&["stop", name]);
        let _ = run_systemctl(&["disable", name]);
        let path = format!("/etc/systemd/system/{name}.service");
        if std::path::Path::new(&path).exists() {
            std::fs::remove_file(&path)
                .map_err(|e| Error::ServiceManagerFailed(format!("remove {path}: {e}")))?;
        }
        let _ = run_systemctl(&["daemon-reload"]);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn status(&self, name: &str) -> Result<ServiceStatus> {
        let out = std::process::Command::new("systemctl")
            .args(["is-active", name])
            .output()
            .map_err(|e| Error::ServiceManagerFailed(format!("systemctl is-active: {e}")))?;
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
        run_systemctl(&["start", name])
    }
    #[cfg(target_os = "linux")]
    fn stop(&self, name: &str) -> Result<()> {
        run_systemctl(&["stop", name])
    }
    #[cfg(target_os = "linux")]
    fn restart(&self, name: &str) -> Result<()> {
        run_systemctl(&["restart", name])
    }
    #[cfg(target_os = "linux")]
    fn reload(&self, name: &str) -> Result<()> {
        run_systemctl(&["reload-or-restart", name])
    }
}

#[cfg(target_os = "linux")]
fn run_systemctl(args: &[&str]) -> Result<()> {
    let st = std::process::Command::new("systemctl")
        .args(args)
        .status()
        .map_err(|e| Error::ServiceManagerFailed(format!("systemctl: {e}")))?;
    if st.success() {
        Ok(())
    } else {
        Err(Error::ServiceManagerFailed(format!(
            "systemctl {args:?} exited with {st}"
        )))
    }
}

/// Render the unit file. `user_scope` flips the `[Install]` `WantedBy=`.
pub(crate) fn render_unit(spec: &ServiceSpec, user_scope: bool) -> String {
    let args = spec
        .args
        .iter()
        .map(|a| shell_escape(a))
        .collect::<Vec<_>>()
        .join(" ");
    let env_lines = spec
        .env
        .iter()
        .map(|(k, v)| format!("Environment=\"{k}={v}\""))
        .collect::<Vec<_>>()
        .join("\n");
    let user_line = spec
        .user
        .as_ref()
        .filter(|_| !user_scope)
        .map_or(String::new(), |u| format!("User={u}"));
    let group_line = spec
        .group
        .as_ref()
        .filter(|_| !user_scope)
        .map_or(String::new(), |g| format!("Group={g}"));
    let svc_type = if spec.sd_notify { "notify" } else { "simple" };
    let wanted_by = if user_scope {
        "default.target"
    } else {
        "multi-user.target"
    };

    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("description", spec.description.clone());
    vars.insert("service_type", svc_type.to_string());
    vars.insert("exec_path", spec.exec_path.display().to_string());
    vars.insert("args", args);
    vars.insert("working_dir", spec.working_dir.display().to_string());
    vars.insert("env_lines", env_lines);
    vars.insert("user_line", user_line);
    vars.insert("group_line", group_line);
    vars.insert("restart_policy", spec.restart_policy.as_systemd().into());
    vars.insert("wanted_by", wanted_by.into());

    template::render(TEMPLATE, &vars)
}

fn shell_escape(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:".contains(c)) {
        s.to_string()
    } else {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_spec;

    #[test]
    fn render_includes_exec_and_user() {
        let mgr = SystemdSystemManager::new();
        let out = mgr.render(&sample_spec()).unwrap();
        assert!(out.contains("ExecStart=/usr/local/bin/spt"));
        assert!(out.contains("User=spt"));
        assert!(out.contains("Group=spt"));
        assert!(out.contains("Type=notify"));
        assert!(out.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn snapshot_systemd_system() {
        let mgr = SystemdSystemManager::new();
        let out = mgr.render(&sample_spec()).unwrap();
        insta::assert_snapshot!("systemd_system_unit", out);
    }
}
