//! `spt_mcp::Controller` implementation backed by the orchestrator.
//!
//! This is the production wire-up for mutating MCP tools. The controller
//! holds the same handles `tunnel run` does: an [`Orchestrator`], a secrets
//! [`Resolver`], the on-disk config path, and the last applied [`Config`].
//!
//! # Reload pipeline
//!
//! `Orchestrator` deliberately exposes only `apply(&ReloadPlan, provider)`
//! rather than a high-level `reload(new_config)` — the binary owns the
//! per-profile factory wiring (`spt_bin::profile_factory`) so the MCP
//! controller does the same. `Controller::reload` re-reads the config from
//! disk, validates it, computes a [`ReloadPlan`] against the cached
//! "last applied" config, calls `Orchestrator::apply`, and finally swaps
//! the cached config under a `Mutex`. Failures leave the cached config
//! untouched.
//!
//! `forward_add` / `forward_remove` mutate the on-disk TOML through
//! [`spt_config::mutate::Document`], then trigger the same reload pipeline.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use spt_config::schema::{Config, Forward};
use spt_mcp::{Controller, Error as McpError, Result as McpResult};
use spt_secrets::Resolver;
use spt_supervisor::{Orchestrator, ReloadPlan};

use crate::profile_factory;

/// Controller backed by an [`Orchestrator`] handle plus the binary's reload
/// inputs (config path, resolver, cached last-applied config).
pub struct OrchestratorController {
    orchestrator: Arc<Orchestrator>,
    resolver: Arc<Resolver>,
    config_path: PathBuf,
    last_config: Arc<Mutex<Config>>,
}

impl OrchestratorController {
    /// Build a controller wired to the running orchestrator. `last_config`
    /// must mirror what the orchestrator was last asked to apply (typically
    /// the boot-time config); it is updated atomically on every successful
    /// reload.
    #[must_use]
    pub fn new(
        orchestrator: Arc<Orchestrator>,
        resolver: Arc<Resolver>,
        config_path: PathBuf,
        last_config: Config,
    ) -> Self {
        Self {
            orchestrator,
            resolver,
            config_path,
            last_config: Arc::new(Mutex::new(last_config)),
        }
    }

    /// Shared handle to the cached "last applied" config. Useful for callers
    /// that want to observe reload-induced changes without owning the
    /// controller.
    #[must_use]
    pub fn last_config(&self) -> Arc<Mutex<Config>> {
        self.last_config.clone()
    }

    async fn reload_with(&self, new_cfg: Config) -> McpResult<()> {
        let diags = spt_config::validate(&new_cfg);
        if !diags.errors.is_empty() {
            let msg = diags
                .errors
                .iter()
                .map(|d| format!("[{}] {}", d.code, d.message))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(McpError::InvalidParams(format!(
                "config validation failed: {msg}"
            )));
        }
        let old = { self.last_config.lock().clone() };
        let plan = ReloadPlan::compute(&old, &new_cfg);
        let resolver = self.resolver.clone();
        let new_for_provider = new_cfg.clone();
        self.orchestrator
            .apply(&plan, |name| {
                let p = new_for_provider
                    .profiles
                    .iter()
                    .find(|p| p.name == name)?
                    .clone();
                let bundle = profile_factory::build(&p, &resolver).ok()?;
                Some((
                    p,
                    bundle.protocol,
                    bundle.auth,
                    bundle.endpoints,
                    bundle.supervisor_cfg,
                ))
            })
            .await;
        *self.last_config.lock() = new_cfg;
        Ok(())
    }

    fn read_disk_config(&self) -> McpResult<Config> {
        let (cfg, _w) = spt_config::load(&self.config_path, false)
            .map_err(|e| McpError::Internal(format!("config load: {e}")))?;
        Ok(cfg)
    }

    fn mutate_doc<F>(&self, f: F) -> McpResult<()>
    where
        F: FnOnce(&mut spt_config::mutate::Document) -> McpResult<()>,
    {
        let mut doc = spt_config::mutate::Document::read(&self.config_path)
            .map_err(|e| McpError::Internal(format!("config read: {e}")))?;
        f(&mut doc)?;
        doc.write_atomic(&self.config_path)
            .map_err(|e| McpError::Internal(format!("config write: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl Controller for OrchestratorController {
    async fn reload(&self) -> McpResult<()> {
        let new_cfg = self.read_disk_config()?;
        self.reload_with(new_cfg).await
    }

    async fn failover(&self, profile: &str, endpoint: Option<&str>) -> McpResult<()> {
        // Now that `Orchestrator::failover` exists (f-sup-api), drive it
        // directly. Surface supervisor errors as InvalidParams (bad endpoint
        // key / unknown profile) since both are caller-facing.
        self.orchestrator
            .failover(profile, endpoint)
            .await
            .map_err(|e| McpError::InvalidParams(format!("failover: {e}")))
    }

    async fn profile_start(&self, profile: &str) -> McpResult<()> {
        // Re-start uses the cached config: build the bundle, ask the
        // orchestrator to start the profile. If the profile isn't in the
        // cached config, surface InvalidParams.
        let cfg = self.last_config.lock().clone();
        let p = cfg
            .profiles
            .iter()
            .find(|p| p.name == profile)
            .cloned()
            .ok_or_else(|| McpError::InvalidParams(format!("no such profile `{profile}`")))?;
        let bundle = profile_factory::build(&p, &self.resolver)
            .map_err(|e| McpError::Internal(format!("build profile: {e}")))?;
        self.orchestrator.start_profile(
            &p,
            bundle.protocol,
            bundle.auth,
            bundle.endpoints,
            bundle.supervisor_cfg,
        );
        Ok(())
    }

    async fn profile_stop(&self, profile: &str) -> McpResult<()> {
        self.orchestrator.stop_profile(profile).await;
        Ok(())
    }

    async fn forward_add(&self, profile: &str, forward: &Forward) -> McpResult<()> {
        let kind = forward.kind.as_str();
        let transport = forward.transport.as_str();
        let bind = forward.bind.as_deref().unwrap_or("");
        let target = forward.target.as_deref().unwrap_or("");
        let name = forward.name.as_str();
        self.mutate_doc(|doc| {
            doc.add_forward(profile, name, kind, transport, bind, target)
                .map_err(|e| McpError::Internal(format!("add_forward: {e}")))
        })?;
        let new_cfg = self.read_disk_config()?;
        self.reload_with(new_cfg).await
    }

    async fn forward_remove(&self, profile: &str, forward_id: &str) -> McpResult<()> {
        self.mutate_doc(|doc| {
            let removed = doc
                .remove_forward(profile, forward_id)
                .map_err(|e| McpError::Internal(format!("remove_forward: {e}")))?;
            if !removed {
                return Err(McpError::InvalidParams(format!(
                    "no forward `{forward_id}` in profile `{profile}`"
                )));
            }
            Ok(())
        })?;
        let new_cfg = self.read_disk_config()?;
        self.reload_with(new_cfg).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_config::load::load_str;

    fn write_cfg(dir: &std::path::Path, body: &str) -> PathBuf {
        let p = dir.join("config.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    fn boot_cfg() -> &'static str {
        r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
"#
    }

    fn fixture(dir: &std::path::Path) -> OrchestratorController {
        let path = write_cfg(dir, boot_cfg());
        let (cfg, _) = load_str(boot_cfg(), false).unwrap();
        let orch = Arc::new(Orchestrator::new());
        let resolver = Arc::new(spt_secrets::Resolver::new(vec![]));
        OrchestratorController::new(orch, resolver, path, cfg)
    }

    #[tokio::test]
    async fn reload_loads_disk_config_and_updates_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        // Write a new config with a renamed profile
        std::fs::write(
            tmp.path().join("config.toml"),
            r#"
version = 1
[[profiles]]
name = "q"
protocol = "ssh2"
host = "h2"
"#,
        )
        .unwrap();
        ctl.reload().await.unwrap();
        let cached = ctl.last_config.lock().clone();
        assert_eq!(cached.profiles.len(), 1);
        assert_eq!(cached.profiles[0].name, "q");
    }

    #[tokio::test]
    async fn forward_add_writes_disk_and_reloads() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let f = Forward {
            name: "db".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            bind: Some("127.0.0.1:5432".into()),
            target: Some("db.internal:5432".into()),
            ..Default::default()
        };
        ctl.forward_add("p", &f).await.unwrap();
        let raw = std::fs::read_to_string(tmp.path().join("config.toml")).unwrap();
        assert!(raw.contains("name = \"db\""));
        let cached = ctl.last_config.lock().clone();
        assert_eq!(cached.profiles[0].forwards.len(), 1);
        assert_eq!(cached.profiles[0].forwards[0].name, "db");
    }

    #[tokio::test]
    async fn forward_remove_errors_if_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let err = ctl.forward_remove("p", "nope").await.unwrap_err();
        assert!(matches!(err, McpError::InvalidParams(_)));
    }

    #[tokio::test]
    async fn failover_unknown_profile_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let err = ctl.failover("ghost", None).await.unwrap_err();
        assert!(matches!(err, McpError::InvalidParams(_)));
    }

    #[tokio::test]
    async fn profile_stop_is_idempotent_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        // No profile started; stopping a missing profile is a no-op for the
        // orchestrator.
        ctl.profile_stop("ghost").await.unwrap();
    }
}
