//! SysV-init script manager (LSB-style).

use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
use spt_core::error::Error;
use spt_core::error::Result;

use crate::{template, ServiceManager, ServiceSpec};

const TEMPLATE: &str = include_str!("../../../packaging/sysv/spt.tmpl");

/// Manager for `SysV` init.
#[derive(Debug, Default, Clone, Copy)]
pub struct SysVManager;

impl SysVManager {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceManager for SysVManager {
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
        // Try update-rc.d (Debian) then chkconfig (RHEL); ignore "not found".
        let _ = std::process::Command::new("update-rc.d")
            .args([&spec.name, "defaults"])
            .status();
        let _ = std::process::Command::new("chkconfig")
            .args(["--add", &spec.name])
            .status();
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
    vars.insert("working_dir", spec.working_dir.display().to_string());
    template::render(TEMPLATE, &vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_spec;

    #[test]
    fn snapshot_sysv() {
        let out = SysVManager::new().render(&sample_spec()).unwrap();
        insta::assert_snapshot!("sysv_init", out);
    }
}
