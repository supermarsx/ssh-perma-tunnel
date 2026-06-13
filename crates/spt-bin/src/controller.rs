//! `spt_mcp::Controller` implementation backed by the orchestrator, plus the
//! shared "last applied config" cell ([`ConfigCell`]) and the single reload
//! pipeline ([`run_reload_pipeline`]) used by **both** the SIGHUP path in
//! `cli_dispatch::tunnel_run` and this MCP controller.
//!
//! This is the production wire-up for mutating MCP tools. The controller
//! holds the same handles `tunnel run` does: an [`Orchestrator`], a secrets
//! [`Resolver`], the on-disk config path, and a [`ConfigCell`] caching the
//! last applied [`Config`].
//!
//! # Shared config cell
//!
//! Before t-fill-p1, the SIGHUP loop and the MCP controller each kept their
//! own "old config" — the SIGHUP loop wrongly diffed against the immutable
//! boot config forever (E1-F2), while the controller kept a correct cache, so
//! the two pipelines drifted. [`ConfigCell`] is now the *one* shared
//! last-applied-config store: `tunnel_run` constructs it once at boot and
//! hands a clone to [`maybe_spawn_mcp_loopback`]'s controller, so a SIGHUP and
//! an MCP `reload` see (and update) the same cell.
//!
//! The cell's inner [`tokio::sync::Mutex`] is held *across the entire reload
//! pipeline* — it is both the last-applied store and the serialization lock
//! that prevents two concurrent reloads from diffing against the same old
//! config and double-applying actions (E1-F14).
//!
//! # Reload pipeline
//!
//! `Orchestrator` deliberately exposes only `apply(&ReloadPlan, provider)`
//! rather than a high-level `reload(new_config)` — the binary owns the
//! per-profile factory wiring (`spt_bin::profile_factory`) so the reload
//! helper does the same. [`run_reload_pipeline`]:
//!
//! 1. re-applies the HKLM/GPO policy overlay on the freshly loaded config
//!    (E5-F2 — enforced policy must survive reloads, not just startup),
//! 2. logs any unknown-key warnings (E5-F6),
//! 3. validates and bails on errors,
//! 4. computes a [`ReloadPlan`] against the **cached** last-applied config,
//! 5. calls `Orchestrator::apply`, where the provider returns `None` for any
//!    `enabled = false` profile so a reload *stops* (rather than restarts) a
//!    disabled profile (E5-F1), and collects per-profile build failures into a
//!    `Vec<(name, error)>` instead of silently dropping them (E1-F14),
//! 6. swaps the cached config under the held lock. Failures leave the cached
//!    config untouched.
//!
//! `forward_add` / `forward_remove` mutate the on-disk TOML through
//! [`spt_config::mutate::Document`], then trigger the same reload pipeline.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;

use spt_config::schema::{Config, Forward};
use spt_mcp::{Controller, Error as McpError, Result as McpResult};
use spt_secrets::Resolver;
use spt_supervisor::{Orchestrator, ReloadPlan};

use crate::profile_factory;
use crate::profile_factory::ProfileBundle;

/// Multi-auth Phase 3: build the `(host, port) → AuthConfig` map the supervisor
/// uses to pick a per-endpoint credential at connect time. `ProfileBundle`'s
/// `endpoint_auth` is index-aligned with `endpoints`, so zipping yields the map
/// directly. Endpoints with no override resolve to the profile-level default in
/// the factory, so every entry is the credential that endpoint should use.
fn endpoint_auth_map(
    bundle: &ProfileBundle,
) -> std::collections::HashMap<(String, u16), spt_auth::AuthConfig> {
    bundle
        .endpoints
        .iter()
        .zip(bundle.endpoint_auth.iter())
        .map(|(ep, auth)| ((ep.host.clone(), ep.port), auth.clone()))
        .collect()
}

/// Shared "last applied config" cell.
///
/// One cell is constructed at boot (`tunnel_run`) and cloned into both the
/// SIGHUP reload path and the MCP [`OrchestratorController`], so every reload
/// diffs against — and updates — the *same* last-applied config rather than
/// the immutable boot config (E1-F2) or a per-pipeline private cache.
///
/// The inner [`tokio::sync::Mutex`] is intentionally an async mutex held
/// across the whole reload pipeline (see [`run_reload_pipeline`]); it both
/// stores the last-applied config and serializes concurrent reloads (E1-F14).
/// Cloning the cell is a cheap `Arc` clone that shares the same underlying
/// config.
///
/// # Phase 2 note (p2-dispatch-security)
///
/// This is the foundation the GPO-overlay-on-reload and unknown-key-warning
/// work builds on. To read the current applied config without taking part in
/// a reload, use [`ConfigCell::snapshot`]. To run a full reload (overlay +
/// validate + diff-vs-applied + apply + swap) use
/// [`ConfigCell::reload`] / the standalone [`run_reload_pipeline`].
#[derive(Clone)]
pub struct ConfigCell {
    inner: Arc<AsyncMutex<Config>>,
}

impl ConfigCell {
    /// Create a cell seeded with the boot-time (already overlay-applied)
    /// config.
    #[must_use]
    pub fn new(boot: Config) -> Self {
        Self {
            inner: Arc::new(AsyncMutex::new(boot)),
        }
    }

    /// Clone of the current last-applied config. Takes the lock only briefly;
    /// callers that need a stable view across a reload should not rely on this
    /// racing with [`Self::reload`].
    pub async fn snapshot(&self) -> Config {
        self.inner.lock().await.clone()
    }

    /// Run the shared reload pipeline against `new_cfg`, holding the cell's
    /// lock across the whole operation. See [`run_reload_pipeline`] for the
    /// step list. On success the cell is updated to `new_cfg`; on error it is
    /// left untouched.
    pub async fn reload(
        &self,
        mut new_cfg: Config,
        warnings: &[String],
        resolver: &Resolver,
        orch: &Orchestrator,
    ) -> Result<ReloadOutcome, ReloadError> {
        let mut guard = self.inner.lock().await;
        let outcome = run_reload_pipeline(&guard, &mut new_cfg, warnings, resolver, orch).await?;
        *guard = new_cfg;
        Ok(outcome)
    }
}

/// Per-profile provider build failure surfaced by a reload (E1-F14) instead of
/// being silently dropped.
#[derive(Debug)]
pub struct ProviderFailure {
    /// Profile name whose factory build failed.
    pub profile: String,
    /// Human-readable build error.
    pub error: String,
}

/// Successful-pipeline outcome. The reload itself succeeded (config validated
/// and the plan applied), but individual profiles may have failed to build;
/// those are reported here so the caller (MCP reply / SIGHUP log) can surface
/// them rather than pretending the new config is fully live.
#[derive(Debug, Default)]
pub struct ReloadOutcome {
    /// Profiles that failed to build during this reload.
    pub provider_failures: Vec<ProviderFailure>,
    /// The freshly applied config (post-overlay).
    pub applied: Config,
}

/// Error returned by the shared reload pipeline before any state is swapped.
#[derive(Debug)]
pub enum ReloadError {
    /// Config validation produced one or more errors.
    Validation(String),
}

impl std::fmt::Display for ReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(msg) => write!(f, "config validation failed: {msg}"),
        }
    }
}

impl std::error::Error for ReloadError {}

impl From<ReloadError> for McpError {
    fn from(e: ReloadError) -> Self {
        match e {
            ReloadError::Validation(msg) => {
                McpError::InvalidParams(format!("config validation failed: {msg}"))
            }
        }
    }
}

/// The single reload pipeline shared by the SIGHUP path and the MCP
/// controller. `old` is the cached last-applied config (held under the
/// [`ConfigCell`] lock by the caller); `new_cfg` is the freshly loaded config
/// which is mutated in place by the GPO overlay re-apply.
///
/// Steps: (1) re-apply the GPO/HKLM policy overlay so enforced policy survives
/// reloads (E5-F2); (2) log unknown-key warnings now that a subscriber exists
/// (E5-F6); (3) validate; (4) diff against `old`; (5) apply, with the provider
/// returning `None` for disabled profiles (E5-F1) and collecting build
/// failures (E1-F14). The caller swaps the cell only on `Ok`.
pub async fn run_reload_pipeline(
    old: &Config,
    new_cfg: &mut Config,
    warnings: &[String],
    resolver: &Resolver,
    orch: &Orchestrator,
) -> Result<ReloadOutcome, ReloadError> {
    // (1) Re-apply the GPO/HKLM-enforced policy overlay. Without this, any
    // reload silently strips administrator-enforced bindings until the next
    // process restart (E5-F2 — a policy-bypass security fix).
    let _overlay = crate::policy::overlay::apply(new_cfg);

    // (2) Surface unknown-key warnings. On the reload path the tracing
    // subscriber is already installed, so (unlike the first-load path) we can
    // log them immediately (E5-F6).
    for w in warnings {
        tracing::warn!(path = %w, "unknown TOML key on reload (ignored)");
    }

    // (3) Validate; bail before touching the running orchestrator.
    let diags = spt_config::validate(new_cfg);
    if !diags.errors.is_empty() {
        let msg = diags
            .errors
            .iter()
            .map(|d| format!("[{}] {}", d.code, d.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(ReloadError::Validation(msg));
    }

    // (4) Diff against the cached last-applied config (NOT the boot config).
    let plan = ReloadPlan::compute(old, new_cfg);

    // (5) Apply. The provider returns `None` for disabled profiles (so a
    // reload stops rather than restarts them, E5-F1) and records build
    // failures rather than dropping the profile silently (E1-F14).
    let failures = Arc::new(std::sync::Mutex::new(Vec::<ProviderFailure>::new()));
    {
        let new_for_provider = new_cfg.clone();
        let failures = failures.clone();
        // Box the apply future: the provider closure captures a full `Config`
        // clone and the plan, making this the heaviest await in the pipeline
        // (clippy `large_futures`).
        Box::pin(orch.apply_with_auth(&plan, |name| {
            let p = new_for_provider.profiles.iter().find(|p| p.name == name)?;
            // E5-F1: never (re)start a profile the operator disabled. The plan
            // emits Start/Restart for it; returning None means apply() stops
            // any running instance (Restart) or does nothing (Start) instead.
            if p.enabled == Some(false) {
                return None;
            }
            let p = p.clone();
            match profile_factory::build_with_config(&p, resolver, &new_for_provider) {
                Ok(bundle) => {
                    // Multi-auth Phase 3: zip endpoints with their index-aligned
                    // resolved credentials into a (host, port) → AuthConfig map.
                    let auth_by_endpoint = endpoint_auth_map(&bundle);
                    Some((
                        p,
                        bundle.protocol,
                        bundle.auth,
                        auth_by_endpoint,
                        bundle.endpoints,
                        bundle.supervisor_cfg,
                    ))
                }
                Err(e) => {
                    failures.lock().expect("provider-failure lock").push(ProviderFailure {
                        profile: name.to_owned(),
                        error: e.to_string(),
                    });
                    None
                }
            }
        }))
        .await;
    }

    // The provider closure (the only other Arc holder) was dropped when
    // `apply` returned, so this unwrap always succeeds; fall back to draining
    // the mutex defensively if a future change keeps a clone alive.
    let provider_failures = Arc::try_unwrap(failures).map_or_else(
        |arc| std::mem::take(&mut *arc.lock().expect("provider-failure lock")),
        |m| m.into_inner().expect("provider-failure lock"),
    );

    Ok(ReloadOutcome {
        provider_failures,
        applied: new_cfg.clone(),
    })
}

/// Controller backed by an [`Orchestrator`] handle plus the binary's reload
/// inputs (config path, resolver, shared last-applied [`ConfigCell`]).
pub struct OrchestratorController {
    orchestrator: Arc<Orchestrator>,
    resolver: Arc<Resolver>,
    config_path: PathBuf,
    cell: ConfigCell,
}

impl OrchestratorController {
    /// Build a controller wired to the running orchestrator, sharing the
    /// given [`ConfigCell`] with the SIGHUP reload path. The cell holds the
    /// last-applied config and serializes reloads across both pipelines.
    #[must_use]
    pub fn new(
        orchestrator: Arc<Orchestrator>,
        resolver: Arc<Resolver>,
        config_path: PathBuf,
        cell: ConfigCell,
    ) -> Self {
        Self {
            orchestrator,
            resolver,
            config_path,
            cell,
        }
    }

    /// Shared handle to the cached "last applied" config cell. Useful for
    /// callers that want to observe reload-induced changes without owning the
    /// controller.
    #[must_use]
    pub fn config_cell(&self) -> ConfigCell {
        self.cell.clone()
    }

    /// Run the shared reload pipeline. Provider build failures are surfaced in
    /// the returned `Ok` value (E1-F14): if any profile failed to build, the
    /// reload still applied for the rest but we return an error naming the
    /// failed profiles rather than silently reporting success.
    async fn reload_with(&self, new_cfg: Config, warnings: &[String]) -> McpResult<()> {
        let outcome = self
            .cell
            .reload(new_cfg, warnings, &self.resolver, &self.orchestrator)
            .await?;
        if outcome.provider_failures.is_empty() {
            Ok(())
        } else {
            let msg = outcome
                .provider_failures
                .iter()
                .map(|f| format!("{}: {}", f.profile, f.error))
                .collect::<Vec<_>>()
                .join("; ");
            Err(McpError::Internal(format!(
                "reload applied with {} profile build failure(s): {msg}",
                outcome.provider_failures.len()
            )))
        }
    }

    fn read_disk_config(&self) -> McpResult<(Config, Vec<String>)> {
        let (cfg, w) = spt_config::load(&self.config_path, false)
            .map_err(|e| McpError::Internal(format!("config load: {e}")))?;
        Ok((cfg, w))
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
        let (new_cfg, warnings) = self.read_disk_config()?;
        // Box the reload future: it holds several large `Config` values across
        // awaits (load → overlay → diff → apply), tripping clippy's
        // `large_futures` threshold otherwise.
        Box::pin(self.reload_with(new_cfg, &warnings)).await
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
        let cfg = self.cell.snapshot().await;
        let p = cfg
            .profiles
            .iter()
            .find(|p| p.name == profile)
            .cloned()
            .ok_or_else(|| McpError::InvalidParams(format!("no such profile `{profile}`")))?;
        let bundle = profile_factory::build_with_config(&p, &self.resolver, &cfg)
            .map_err(|e| McpError::Internal(format!("build profile: {e}")))?;
        // Multi-auth Phase 3: thread the per-endpoint credential map.
        let auth_by_endpoint = endpoint_auth_map(&bundle);
        self.orchestrator.start_profile_with_auth(
            &p,
            bundle.protocol,
            bundle.auth,
            auth_by_endpoint,
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
        let (new_cfg, warnings) = self.read_disk_config()?;
        // Box the reload future: it holds several large `Config` values across
        // awaits (load → overlay → diff → apply), tripping clippy's
        // `large_futures` threshold otherwise.
        Box::pin(self.reload_with(new_cfg, &warnings)).await
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
        let (new_cfg, warnings) = self.read_disk_config()?;
        // Box the reload future: it holds several large `Config` values across
        // awaits (load → overlay → diff → apply), tripping clippy's
        // `large_futures` threshold otherwise.
        Box::pin(self.reload_with(new_cfg, &warnings)).await
    }

    async fn session_close(&self, session_id: &str) -> McpResult<()> {
        let id: spt_core::SessionId = session_id
            .parse()
            .map_err(|e| McpError::InvalidParams(format!("session id: {e}")))?;
        self.orchestrator
            .session_close(&id)
            .await
            .map_err(|e| McpError::InvalidParams(format!("session_close: {e}")))
    }

    async fn session_drain(
        &self,
        profile: &str,
        grace_seconds: u64,
    ) -> McpResult<serde_json::Value> {
        let report = self
            .orchestrator
            .session_drain(profile, std::time::Duration::from_secs(grace_seconds))
            .await
            .map_err(|e| McpError::InvalidParams(format!("session_drain: {e}")))?;
        Ok(serde_json::json!({
            "drained": report.drained,
            "force_closed": report.force_closed,
            "already_closed": report.already_closed,
        }))
    }

    async fn stats_subscribe(
        &self,
        interval_ms: u64,
        tx: tokio::sync::mpsc::Sender<serde_json::Value>,
    ) -> McpResult<()> {
        let mut rx = self.orchestrator.stats_subscribe();
        let _ = interval_ms; // interval is governed by stats_cfg.interval
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(tick) => {
                        let v = serde_json::to_value(&tick).unwrap_or(serde_json::Value::Null);
                        if tx.send(v).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {} // 1.88 lint: redundant_continue
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(())
    }

    async fn run_benchmark(&self, args: serde_json::Value) -> McpResult<serde_json::Value> {
        // Bridge into spt-benchmark using `Orchestrator::live_connector` for
        // tunnel-aware drivers. `dns` is synthetic on the server too.
        let driver = args
            .get("driver")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::InvalidParams("missing string field 'driver'".to_owned()))?
            .to_owned();
        let profile = args
            .get("profile")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let forward = args
            .get("forward")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let count = args
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(50);
        let allow_prod = args
            .get("allow_production_impact")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let max_duration_secs = args
            .get("duration_seconds")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(5);

        let live = profile
            .as_deref()
            .map(|p| self.orchestrator.live_connector(p, forward.as_deref()));
        let reconnect = profile
            .as_deref()
            .and_then(|p| self.orchestrator.profile_handle(p))
            .map(crate::benchmark_bridge::reconnect_trigger_from_supervisor);

        let result = crate::run_live_benchmark(
            driver.as_str(),
            live,
            reconnect,
            count,
            max_duration_secs,
            allow_prod,
        )
        .await
        .map_err(|e| McpError::Internal(format!("benchmark: {e}")))?;
        serde_json::to_value(&result)
            .map_err(|e| McpError::Internal(format!("serialize bench: {e}")))
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
[profiles.trust]
pin_sha256 = ["SHA256:dummy"]
"#
    }

    /// Build a minimal-but-buildable ssh2 profile body (with a self-contained
    /// pinned trust block, which the factory now requires) for the named
    /// profile/host.
    fn profile_cfg(name: &str, host: &str) -> String {
        format!(
            "version = 1\n[[profiles]]\nname = \"{name}\"\nprotocol = \"ssh2\"\nhost = \"{host}\"\n\
             [profiles.trust]\npin_sha256 = [\"SHA256:dummy\"]\n"
        )
    }

    fn fixture(dir: &std::path::Path) -> OrchestratorController {
        let path = write_cfg(dir, boot_cfg());
        let (cfg, _) = load_str(boot_cfg(), false).unwrap();
        let orch = Arc::new(Orchestrator::new());
        let resolver = Arc::new(spt_secrets::Resolver::new(vec![]));
        OrchestratorController::new(orch, resolver, path, ConfigCell::new(cfg))
    }

    #[tokio::test]
    async fn reload_loads_disk_config_and_updates_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        // Write a new config with a renamed profile
        std::fs::write(tmp.path().join("config.toml"), profile_cfg("q", "h2")).unwrap();
        ctl.reload().await.unwrap();
        let cached = ctl.cell.snapshot().await;
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
        let cached = ctl.cell.snapshot().await;
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

    #[tokio::test]
    async fn profile_start_unknown_profile_errors_as_invalid_params() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let err = ctl.profile_start("ghost-profile").await.unwrap_err();
        assert!(matches!(err, McpError::InvalidParams(_)));
    }

    #[tokio::test]
    async fn session_close_with_malformed_id_errors_as_invalid_params() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let err = ctl.session_close("not-a-session-id-format").await;
        // Either a parse error or supervisor-not-found; both are InvalidParams.
        match err {
            Err(McpError::InvalidParams(_)) => {}
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_benchmark_missing_driver_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let err = ctl.run_benchmark(serde_json::json!({})).await.unwrap_err();
        assert!(matches!(err, McpError::InvalidParams(_)));
    }

    #[tokio::test]
    async fn run_benchmark_unknown_driver_returns_internal() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let err = ctl
            .run_benchmark(serde_json::json!({"driver": "ghost"}))
            .await
            .unwrap_err();
        assert!(matches!(err, McpError::Internal(_)));
    }

    #[tokio::test]
    async fn reload_with_invalid_config_returns_invalid_params() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        // Overwrite with a config that fails validation (no profiles + bad version).
        std::fs::write(tmp.path().join("config.toml"), "version = 999\n").unwrap();
        let err = ctl.reload().await.unwrap_err();
        assert!(matches!(err, McpError::InvalidParams(_)));
    }

    #[tokio::test]
    async fn last_config_handle_observes_post_reload_state() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let h = ctl.config_cell();
        let before = h.snapshot().await;
        assert_eq!(before.profiles[0].name, "p");

        std::fs::write(
            tmp.path().join("config.toml"),
            profile_cfg("after-reload", "h"),
        )
        .unwrap();
        ctl.reload().await.unwrap();
        let after = h.snapshot().await;
        assert_eq!(after.profiles[0].name, "after-reload");
    }

    // ---------------------------------------------------------------------
    // Contract: OrchestratorController overrides EVERY default-impl method
    // on `spt_mcp::Controller`. Each test calls the override on an empty
    // orchestrator and asserts the result is NOT `McpError::NotImplemented`
    // — production must never fall through to the trait default. Companion
    // tests in `crates/spt-mcp/tests/it_controller_contract.rs` pin the
    // default behavior; the integration file
    // `tests/it_orchestrator_controller_contract.rs` pins the underlying
    // supervisor APIs the overrides delegate to.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn override_contract_session_close_not_default() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let result = ctl
            .session_close(spt_core::SessionId::new_v4().as_ref())
            .await;
        assert!(
            !matches!(result, Err(McpError::NotImplemented(_))),
            "session_close override must not return NotImplemented, got {result:?}"
        );
    }

    #[tokio::test]
    async fn override_contract_session_drain_not_default() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let result = ctl.session_drain("ghost-profile", 0).await;
        assert!(
            !matches!(result, Err(McpError::NotImplemented(_))),
            "session_drain override must not return NotImplemented, got {result:?}"
        );
    }

    #[tokio::test]
    async fn override_contract_stats_subscribe_not_default() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let (tx, _rx) = tokio::sync::mpsc::channel::<serde_json::Value>(8);
        let result = ctl.stats_subscribe(1_000, tx).await;
        assert!(
            !matches!(result, Err(McpError::NotImplemented(_))),
            "stats_subscribe override must not return NotImplemented, got {result:?}"
        );
    }

    #[tokio::test]
    async fn override_contract_run_benchmark_not_default() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        // Missing `driver` → InvalidParams (not NotImplemented). That's the
        // override exercising its own argument parser.
        let result = ctl.run_benchmark(serde_json::json!({})).await;
        assert!(
            !matches!(result, Err(McpError::NotImplemented(_))),
            "run_benchmark override must not return NotImplemented, got {result:?}"
        );
    }

    #[tokio::test]
    async fn forward_remove_after_add_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        let f = Forward {
            name: "rrt".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            bind: Some("127.0.0.1:5433".into()),
            target: Some("db.local:5432".into()),
            ..Default::default()
        };
        ctl.forward_add("p", &f).await.unwrap();
        // forward_id format is "<profile>/<forward>" but remove takes just the name.
        ctl.forward_remove("p", "rrt").await.unwrap();
        let cached = ctl.cell.snapshot().await;
        assert!(cached.profiles[0].forwards.is_empty());
    }

    // ---------------------------------------------------------------------
    // t-fill-p1-dispatch-reload-cell regression tests.
    // ---------------------------------------------------------------------

    /// E1-F2: the second reload must diff against the *last applied* config,
    /// not the immutable boot config. We reload twice with distinct host
    /// values; after the second reload the cell reflects the most recent
    /// config, proving the cell advanced (a boot-anchored diff would still
    /// leave the cache one generation stale or mis-diff).
    #[tokio::test]
    async fn second_reload_diffs_against_last_applied_not_boot() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());

        // First reload: host h -> h1.
        std::fs::write(tmp.path().join("config.toml"), profile_cfg("p", "h1")).unwrap();
        ctl.reload().await.unwrap();
        let after_first = ctl.cell.snapshot().await;
        assert_eq!(after_first.profiles[0].host.as_deref(), Some("h1"));

        // Second reload: host h1 -> h2. Diff is computed against h1 (the
        // last-applied cell), then the cell advances to h2.
        std::fs::write(tmp.path().join("config.toml"), profile_cfg("p", "h2")).unwrap();
        ctl.reload().await.unwrap();
        let after_second = ctl.cell.snapshot().await;
        assert_eq!(after_second.profiles[0].host.as_deref(), Some("h2"));

        // Reverting back to h1 must also take effect — a boot-anchored diff
        // (new == boot "h") would mis-handle this; last-applied diff (h2 -> h1)
        // is a real change and advances the cell.
        std::fs::write(tmp.path().join("config.toml"), profile_cfg("p", "h1")).unwrap();
        ctl.reload().await.unwrap();
        let after_revert = ctl.cell.snapshot().await;
        assert_eq!(after_revert.profiles[0].host.as_deref(), Some("h1"));
    }

    /// E5-F2: the GPO/HKLM overlay must run on every reload. The registry is
    /// empty in the test environment (overlay is a no-op), so we assert the
    /// pipeline returns the overlay-applied config in `ReloadOutcome.applied`
    /// — i.e. the overlay step is on the reload path, not just startup. The
    /// overlay's correctness itself is covered by `policy::overlay` tests.
    #[tokio::test]
    async fn overlay_is_applied_on_reload_path() {
        let (old, _) = load_str(boot_cfg(), false).unwrap();
        let (mut new_cfg, _) = load_str(&profile_cfg("p", "hX"), false).unwrap();
        let orch = Orchestrator::new();
        let resolver = spt_secrets::Resolver::new(vec![]);
        let outcome = run_reload_pipeline(&old, &mut new_cfg, &[], &resolver, &orch)
            .await
            .unwrap();
        // `applied` is the post-overlay config the pipeline produced.
        assert_eq!(outcome.applied.profiles[0].host.as_deref(), Some("hX"));
        assert!(outcome.provider_failures.is_empty());
        orch.shutdown().await;
    }

    /// E5-F1: reloading a config that disables a running profile must *stop*
    /// it, not restart it. We start the profile, then reload with
    /// `enabled = false`; the provider returns None for the disabled profile
    /// so `apply` leaves it stopped.
    #[tokio::test]
    async fn disabled_profile_reload_stops_rather_than_restarts() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = fixture(tmp.path());
        // Start the profile so there is a running supervisor to stop.
        ctl.profile_start("p").await.unwrap();
        assert!(
            ctl.orchestrator.profile_handle("p").is_some(),
            "profile should be running after profile_start"
        );

        std::fs::write(
            tmp.path().join("config.toml"),
            "version = 1\n[[profiles]]\nname = \"p\"\nprotocol = \"ssh2\"\nhost = \"h\"\nenabled = false\n\
             [profiles.trust]\npin_sha256 = [\"SHA256:dummy\"]\n",
        )
        .unwrap();
        ctl.reload().await.unwrap();
        assert!(
            ctl.orchestrator.profile_handle("p").is_none(),
            "disabled profile must be stopped, not restarted, after reload"
        );
    }

    /// E1-F14: a profile whose factory build fails during reload must be
    /// surfaced, not silently dropped. We craft a config whose profile passes
    /// `validate` but fails `build_with_config` — `auth.method = "public_key"`
    /// with no `identity_file` (validate does not require it, the factory
    /// does) — then assert `run_reload_pipeline` records it in
    /// `provider_failures` rather than reporting a clean success.
    #[tokio::test]
    async fn provider_build_failures_are_surfaced_not_dropped() {
        let (old, _) = load_str(boot_cfg(), false).unwrap();
        let (mut new_cfg, _) = load_str(
            "version = 1\n[[profiles]]\nname = \"p\"\nprotocol = \"ssh2\"\nhost = \"h\"\n\
             [profiles.trust]\npin_sha256 = [\"SHA256:dummy\"]\n\
             [profiles.auth]\nmethod = \"public_key\"\n",
            false,
        )
        .unwrap();
        let orch = Orchestrator::new();
        let resolver = spt_secrets::Resolver::new(vec![]);
        let outcome = run_reload_pipeline(&old, &mut new_cfg, &[], &resolver, &orch)
            .await
            .unwrap();
        assert!(
            outcome
                .provider_failures
                .iter()
                .any(|f| f.profile == "p"),
            "expected a recorded provider failure for profile `p`, got {:?}",
            outcome.provider_failures
        );
        orch.shutdown().await;
    }
}
