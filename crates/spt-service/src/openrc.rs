//! `OpenRC` init script manager.

use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
use spt_core::error::Error;
use spt_core::error::Result;

use crate::{template, ServiceManager, ServiceSpec};

const TEMPLATE: &str = include_str!("../../../packaging/openrc/spt.tmpl");

/// Manager for `OpenRC`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenRcManager;

impl OpenRcManager {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceManager for OpenRcManager {
    fn render(&self, spec: &ServiceSpec) -> Result<String> {
        Ok(render_script(spec))
    }

    #[cfg(target_os = "linux")]
    fn install(&self, spec: &ServiceSpec) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let script = render_script(spec);
        let path = format!("/etc/init.d/{}", spec.name);
        std::fs::write(&path, script)
            .map_err(|e| Error::ServiceManagerFailed(format!("write {path}: {e}")))?;
        let mut perms = std::fs::metadata(&path)
            .map_err(|e| Error::ServiceManagerFailed(format!("metadata {path}: {e}")))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| Error::ServiceManagerFailed(format!("chmod {path}: {e}")))?;
        let st = std::process::Command::new("rc-update")
            .args(["add", &spec.name, "default"])
            .status()
            .map_err(|e| Error::ServiceManagerFailed(format!("rc-update: {e}")))?;
        if !st.success() {
            return Err(Error::ServiceManagerFailed(format!(
                "rc-update add {} exited {st}",
                spec.name
            )));
        }
        Ok(())
    }
}

fn render_script(spec: &ServiceSpec) -> String {
    let args = spec.args.join(" ");
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("name", spec.name.clone());
    vars.insert("description", spec.description.clone());
    vars.insert("exec_path", spec.exec_path.display().to_string());
    vars.insert("args", args);
    vars.insert("user", spec.user.clone().unwrap_or_else(|| "root".into()));
    vars.insert("group", spec.group.clone().unwrap_or_else(|| "root".into()));
    vars.insert("working_dir", spec.working_dir.display().to_string());
    template::render(TEMPLATE, &vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_spec;

    #[test]
    fn includes_command_and_user() {
        let out = OpenRcManager::new().render(&sample_spec()).unwrap();
        assert!(out.contains("command=\"/usr/local/bin/spt\""));
        assert!(out.contains("command_user=\"spt:spt\""));
    }

    #[test]
    fn snapshot_openrc() {
        let out = OpenRcManager::new().render(&sample_spec()).unwrap();
        insta::assert_snapshot!("openrc_init", out);
    }
}
