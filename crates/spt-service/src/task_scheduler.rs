//! Task Scheduler fallback for Windows.
//!
//! Renders a `schtasks.exe /Create` command line; install/uninstall shell
//! out to `schtasks.exe`. This is the fallback path for hosts where SCM
//! registration isn't desired (e.g. user-scope tasks, logon triggers).

use spt_core::error::{Error, Result};

use crate::{ServiceManager, ServiceSpec};

/// Trigger to attach to the scheduled task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Run at system startup.
    AtStartup,
    /// Run when the current user logs on.
    AtLogon,
}

/// Task Scheduler manager.
#[derive(Debug, Clone, Copy)]
pub struct TaskSchedulerManager {
    /// Trigger applied to created tasks.
    pub trigger: Trigger,
}

impl TaskSchedulerManager {
    /// Construct with `Trigger::AtStartup` (the most common default).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            trigger: Trigger::AtStartup,
        }
    }
}

impl Default for TaskSchedulerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager for TaskSchedulerManager {
    fn render(&self, spec: &ServiceSpec) -> Result<String> {
        Ok(render_schtasks(spec, self.trigger))
    }

    #[cfg(target_os = "windows")]
    fn install(&self, spec: &ServiceSpec) -> Result<()> {
        let cmd = render_schtasks(spec, self.trigger);
        // schtasks doesn't accept a script — replay the args we generated.
        let st = std::process::Command::new("schtasks.exe")
            .args(schtasks_args(spec, self.trigger))
            .status()
            .map_err(|e| Error::ServiceManagerFailed(format!("schtasks: {e}")))?;
        if !st.success() {
            return Err(Error::ServiceManagerFailed(format!(
                "schtasks /Create exited {st}; rendered: {cmd}"
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn uninstall(&self, name: &str) -> Result<()> {
        let st = std::process::Command::new("schtasks.exe")
            .args(["/Delete", "/TN", name, "/F"])
            .status()
            .map_err(|e| Error::ServiceManagerFailed(format!("schtasks /Delete: {e}")))?;
        if !st.success() {
            return Err(Error::ServiceManagerFailed(format!(
                "schtasks /Delete {name} exited {st}"
            )));
        }
        Ok(())
    }
}

fn render_schtasks(spec: &ServiceSpec, trigger: Trigger) -> String {
    let args = schtasks_args(spec, trigger);
    args.iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn schtasks_args(spec: &ServiceSpec, trigger: Trigger) -> Vec<String> {
    let tr = match trigger {
        Trigger::AtStartup => "ONSTART",
        Trigger::AtLogon => "ONLOGON",
    };
    let bin_with_args = format!(
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
    let mut a: Vec<String> = vec![
        "/Create".into(),
        "/TN".into(),
        spec.name.clone(),
        "/TR".into(),
        bin_with_args,
        "/SC".into(),
        tr.into(),
        "/RL".into(),
        "HIGHEST".into(),
        "/F".into(),
    ];
    if let Some(u) = &spec.user {
        a.push("/RU".into());
        a.push(u.clone());
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_spec;

    #[test]
    fn render_contains_create_and_trigger() {
        let out = TaskSchedulerManager::new().render(&sample_spec()).unwrap();
        assert!(out.contains("/Create"));
        assert!(out.contains("/SC ONSTART"));
        assert!(out.contains("/TN spt-relay"));
    }

    #[test]
    fn snapshot_task_scheduler() {
        let out = TaskSchedulerManager::new().render(&sample_spec()).unwrap();
        insta::assert_snapshot!("task_scheduler_cmd", out);
    }
}
