//! launchd plist manager (macOS Agents and Daemons).
//!
//! `Scope::User` writes to `~/Library/LaunchAgents/<label>.plist`,
//! `Scope::System` writes to `/Library/LaunchDaemons/<label>.plist`. Apply via
//! `launchctl load` / `launchctl unload`.

use std::collections::BTreeMap;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
use spt_core::error::Error;
use spt_core::error::Result;

use crate::{template, Scope, ServiceManager, ServiceSpec};

const TEMPLATE: &str = include_str!("../../../packaging/launchd/spt.plist.tmpl");

/// Reverse-DNS prefix for plist labels. Spec doesn't pin one, so use the
/// project repo namespace.
pub const LABEL_PREFIX: &str = "io.spt";

/// launchd manager for both Agents and Daemons.
#[derive(Debug, Default, Clone, Copy)]
pub struct LaunchdManager;

impl LaunchdManager {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute the full plist path for a spec.
    #[must_use]
    pub fn plist_path(spec: &ServiceSpec) -> PathBuf {
        let label = format!("{LABEL_PREFIX}.{}", spec.name);
        match spec.scope {
            Scope::User => {
                let home = std::env::var_os("HOME")
                    .map_or_else(|| PathBuf::from("~"), PathBuf::from);
                home.join("Library").join("LaunchAgents").join(format!("{label}.plist"))
            }
            Scope::System => PathBuf::from("/Library/LaunchDaemons").join(format!("{label}.plist")),
        }
    }
}

impl ServiceManager for LaunchdManager {
    fn render(&self, spec: &ServiceSpec) -> Result<String> {
        Ok(render_plist(spec))
    }

    #[cfg(target_os = "macos")]
    fn install(&self, spec: &ServiceSpec) -> Result<()> {
        let plist = render_plist(spec);
        let path = Self::plist_path(spec);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::ServiceManagerFailed(format!("mkdir {parent:?}: {e}")))?;
        }
        std::fs::write(&path, plist)
            .map_err(|e| Error::ServiceManagerFailed(format!("write {path:?}: {e}")))?;
        let st = std::process::Command::new("launchctl")
            .args(["load", "-w", &path.display().to_string()])
            .status()
            .map_err(|e| Error::ServiceManagerFailed(format!("launchctl: {e}")))?;
        if !st.success() {
            return Err(Error::ServiceManagerFailed(format!(
                "launchctl load exited {st}"
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn uninstall(&self, name: &str) -> Result<()> {
        let label = format!("{LABEL_PREFIX}.{name}");
        // Try both system and user paths.
        for base in ["/Library/LaunchDaemons", "~/Library/LaunchAgents"] {
            let expanded = if base.starts_with('~') {
                let home = std::env::var_os("HOME").map(PathBuf::from);
                home.map(|h| h.join("Library").join("LaunchAgents"))
            } else {
                Some(PathBuf::from(base))
            };
            if let Some(dir) = expanded {
                let path = dir.join(format!("{label}.plist"));
                if path.exists() {
                    let _ = std::process::Command::new("launchctl")
                        .args(["unload", &path.display().to_string()])
                        .status();
                    std::fs::remove_file(&path)
                        .map_err(|e| Error::ServiceManagerFailed(format!("remove {path:?}: {e}")))?;
                }
            }
        }
        Ok(())
    }
}

fn render_plist(spec: &ServiceSpec) -> String {
    let label = format!("{LABEL_PREFIX}.{}", spec.name);
    let args_array = spec
        .args
        .iter()
        .map(|a| format!("        <string>{}</string>", xml_escape(a)))
        .collect::<Vec<_>>()
        .join("\n");
    let env_dict = spec
        .env
        .iter()
        .map(|(k, v)| {
            format!(
                "        <key>{}</key>\n        <string>{}</string>",
                xml_escape(k),
                xml_escape(v)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let keep_alive = match spec.restart_policy {
        crate::RestartPolicy::Always | crate::RestartPolicy::OnFailure => "true",
        crate::RestartPolicy::Never => "false",
    };
    let user_keys = match (&spec.user, spec.scope) {
        (Some(u), Scope::System) => {
            let mut s = format!("    <key>UserName</key>\n    <string>{}</string>", xml_escape(u));
            if let Some(g) = &spec.group {
                s.push_str(&format!(
                    "\n    <key>GroupName</key>\n    <string>{}</string>",
                    xml_escape(g)
                ));
            }
            s
        }
        _ => String::new(),
    };
    let stdout_path = spec
        .stdout_path
        .as_ref()
        .map_or_else(|| "/dev/null".to_string(), |p| p.display().to_string());
    let stderr_path = spec
        .stderr_path
        .as_ref()
        .map_or_else(|| "/dev/null".to_string(), |p| p.display().to_string());

    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("label", label);
    vars.insert("exec_path", spec.exec_path.display().to_string());
    vars.insert("args_array", args_array);
    vars.insert("working_dir", spec.working_dir.display().to_string());
    vars.insert("keep_alive", keep_alive.to_string());
    vars.insert("stdout_path", stdout_path);
    vars.insert("stderr_path", stderr_path);
    vars.insert("env_dict", env_dict);
    vars.insert("user_keys", user_keys);
    template::render(TEMPLATE, &vars)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_spec;

    #[test]
    fn plist_contains_label_and_args() {
        let mut s = sample_spec();
        s.scope = Scope::System;
        let out = LaunchdManager::new().render(&s).unwrap();
        assert!(out.contains("<string>io.spt.spt-relay</string>"));
        assert!(out.contains("<string>--config</string>"));
        assert!(out.contains("<key>UserName</key>"));
    }

    #[test]
    fn snapshot_launchd_daemon() {
        let mut s = sample_spec();
        s.scope = Scope::System;
        let out = LaunchdManager::new().render(&s).unwrap();
        insta::assert_snapshot!("launchd_daemon_plist", out);
    }

    #[test]
    fn snapshot_launchd_agent() {
        let mut s = sample_spec();
        s.scope = Scope::User;
        s.user = None;
        s.group = None;
        let out = LaunchdManager::new().render(&s).unwrap();
        insta::assert_snapshot!("launchd_agent_plist", out);
    }
}
