//! Thin wrapper that wires `spt_mcp::McpServer` with the binary's adapters.
//!
//! # Public adapter API (E8-F2)
//!
//! The MCP resource catalogue and the sources-backed read-only tools read
//! through two adapter traits defined in `spt-mcp`: [`spt_mcp::ConfigSource`]
//! and [`spt_mcp::StateSource`]. `spt-mcp` deliberately does *not* depend on
//! `spt-config` / `spt-state`, so the binary supplies the concrete adapters.
//!
//! This module exports:
//!
//! * [`ConfigSnapshotSource`] — a [`spt_mcp::ConfigSource`] over an owned
//!   [`spt_config::schema::Config`]. Constructed once per server build from
//!   the live (last-applied) config.
//! * [`StateDirSource`] — a [`spt_mcp::StateSource`] over the state directory.
//!   Reads `<state_dir>/status.json` (the same file the supervisor's
//!   `StatusWriter` updates) and the Prometheus metrics file on demand.
//! * [`build_server_with_sources`] — the production constructor. Callers in
//!   `cli_dispatch` (`maybe_spawn_mcp_loopback`) build a [`McpSources`] bundle
//!   and pass it here so resource reads serve real data instead of fixtures.
//! * [`build_server`] / [`build_noop_server`] — back-compat shims that hand
//!   the server `NoopSources` (used by `spt mcp serve` standalone smoke runs).
//!
//! ## How `p4-dispatch-wire` wires this
//!
//! ```ignore
//! let sources = crate::mcp_server::McpSources::from_config_and_state_dir(
//!     cfg.clone(),          // spt_config::schema::Config (last-applied)
//!     state_dir.to_path_buf(),
//! );
//! let audit = crate::mcp_server::mcp_audit_sink(cfg); // Option<DynAuditSink>
//! let server = crate::mcp_server::build_server_with_sources(
//!     policy, controller, sources, audit,
//! ).with_auth_token(token);
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use spt_config::schema::Config;
use spt_mcp::{
    audit::DynAuditSink,
    sources::{DynConfigSource, DynStateSource},
    ConfigSource, Controller, McpPolicy, McpServer, NoopSources, Policy, StateSource,
};
use spt_state::status::StatusSnapshot;

// ===========================================================================
// ConfigSource adapter (E8-F2)
// ===========================================================================

/// [`spt_mcp::ConfigSource`] backed by an owned [`Config`] snapshot.
///
/// All methods are pure (no I/O) — they project the already-loaded,
/// already-validated config into the JSON shapes the resource handlers
/// expect. Secret redaction is still applied centrally by the server's
/// [`spt_mcp::Policy`] pass; the `effective`/`redacted` renders here mirror
/// the `spt config render` CLI output for consistency.
#[derive(Debug, Clone)]
pub struct ConfigSnapshotSource {
    cfg: Arc<Config>,
}

impl ConfigSnapshotSource {
    /// Build over an owned [`Config`].
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self { cfg: Arc::new(cfg) }
    }

    /// Build over a shared [`Config`].
    #[must_use]
    pub fn from_arc(cfg: Arc<Config>) -> Self {
        Self { cfg }
    }

    fn render_to_value(&self, mode: spt_core::RedactionMode) -> spt_mcp::Result<Value> {
        // Render to canonical TOML, then re-parse into JSON so resources emit
        // a structured object rather than a TOML string. `toml::Value` →
        // `serde_json::Value` via a round-trip keeps numbers/bools typed.
        let toml_text = spt_config::render::render(&self.cfg, mode);
        let toml_value: toml::Value = toml_text
            .parse()
            .map_err(|e| spt_mcp::Error::Internal(format!("render parse: {e}")))?;
        serde_json::to_value(toml_value)
            .map_err(|e| spt_mcp::Error::Internal(format!("render to json: {e}")))
    }
}

#[async_trait]
impl ConfigSource for ConfigSnapshotSource {
    async fn effective(&self) -> spt_mcp::Result<Value> {
        // "Effective" = post-merge config with the standard redaction posture.
        self.render_to_value(spt_core::RedactionMode::Standard)
    }

    async fn redacted(&self) -> spt_mcp::Result<Value> {
        self.render_to_value(spt_core::RedactionMode::Strict)
    }

    async fn profiles(&self) -> spt_mcp::Result<Value> {
        let arr: Vec<Value> = self
            .cfg
            .profiles
            .iter()
            .map(|p| {
                json!({
                    "name": p.name,
                    "protocol": p.protocol,
                    "enabled": p.enabled.unwrap_or(true),
                    "endpoints": p.endpoints.len(),
                    "forwards": p.forwards.len(),
                })
            })
            .collect();
        Ok(Value::Array(arr))
    }

    async fn forwards(&self) -> spt_mcp::Result<Value> {
        let mut arr: Vec<Value> = Vec::new();
        for p in &self.cfg.profiles {
            for f in &p.forwards {
                arr.push(json!({
                    "profile": p.name,
                    "name": f.name,
                    "type": f.kind,
                    "transport": f.transport,
                    "bind": f.bind,
                    "target": f.target,
                }));
            }
        }
        Ok(Value::Array(arr))
    }

    async fn dns_records(&self) -> spt_mcp::Result<Value> {
        let records = self
            .cfg
            .dns
            .as_ref()
            .map_or(&[][..], |d| d.records.as_slice());
        let v = serde_json::to_value(records)
            .map_err(|e| spt_mcp::Error::Internal(format!("dns records: {e}")))?;
        Ok(v)
    }

    async fn mcp_policy(&self) -> spt_mcp::Result<Value> {
        let policy = mcp_policy_from_config(&self.cfg);
        let v = serde_json::to_value(&policy)
            .map_err(|e| spt_mcp::Error::Internal(format!("mcp policy: {e}")))?;
        Ok(v)
    }

    async fn service_definition(&self) -> spt_mcp::Result<Value> {
        // The rendered service unit/plist requires a target-OS + scope choice
        // that the MCP read path doesn't carry — the `spt service render` CLI
        // produces the concrete artifact. Report the platform default manager
        // kind so a client sees what `spt service` would target, with an empty
        // rendered body.
        let format = if cfg!(target_os = "windows") {
            "windows_service"
        } else if cfg!(target_os = "macos") {
            "launchd"
        } else {
            "systemd"
        };
        Ok(json!({ "format": format, "body": "" }))
    }

    async fn snmp_mib(&self) -> spt_mcp::Result<Value> {
        // The MIB body is a static artifact emitted by `spt snmp mib`; the read
        // resource reports whether SNMP is configured rather than re-rendering
        // the (large) MIB text inline.
        let enabled = self
            .cfg
            .observability
            .as_ref()
            .and_then(|o| o.snmp.as_ref())
            .and_then(|s| s.enabled)
            .unwrap_or(false);
        Ok(json!({ "format": "smi", "enabled": enabled, "body": "" }))
    }
}

// ===========================================================================
// StateSource adapter (E8-F2)
// ===========================================================================

/// [`spt_mcp::StateSource`] backed by the on-disk state directory.
///
/// Reads `<state_dir>/status.json` (best-effort; a missing/corrupt file maps
/// to a default snapshot so the resource never errors) and the Prometheus
/// metrics exposition file when present. This mirrors the file-backed status
/// API source so the MCP view and the HTTP status API view stay consistent.
#[derive(Debug, Clone)]
pub struct StateDirSource {
    state_dir: PathBuf,
}

impl StateDirSource {
    /// Build over a state directory.
    #[must_use]
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
        }
    }

    fn read_snapshot(&self) -> StatusSnapshot {
        let path = spt_state::paths::status_path(&self.state_dir);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<StatusSnapshot>(&bytes).unwrap_or_default(),
            Err(_) => StatusSnapshot::default(),
        }
    }

    fn snapshot_value(&self) -> spt_mcp::Result<Value> {
        serde_json::to_value(self.read_snapshot())
            .map_err(|e| spt_mcp::Error::Internal(format!("status snapshot: {e}")))
    }
}

#[async_trait]
impl StateSource for StateDirSource {
    async fn status(&self) -> spt_mcp::Result<Value> {
        self.snapshot_value()
    }

    async fn stats_summary(&self) -> spt_mcp::Result<Value> {
        let snap = self.read_snapshot();
        let counters = serde_json::to_value(&snap.counters)
            .map_err(|e| spt_mcp::Error::Internal(format!("counters: {e}")))?;
        let per_profile: Vec<Value> = snap
            .profiles
            .iter()
            .map(|p| {
                json!({
                    "profile": p.id,
                    "state": p.state,
                    "reconnect_count": p.reconnect_count,
                    "failover_count": p.failover_count,
                    "active_endpoint": p.active_endpoint,
                })
            })
            .collect();
        Ok(json!({ "global": counters, "profiles": per_profile }))
    }

    async fn sessions_current(&self) -> spt_mcp::Result<Value> {
        let snap = self.read_snapshot();
        serde_json::to_value(&snap.sessions)
            .map_err(|e| spt_mcp::Error::Internal(format!("sessions: {e}")))
    }

    async fn events_recent(&self) -> spt_mcp::Result<Value> {
        // Tail the most recent daily events JSONL the EventRing wrote, if any.
        Ok(Value::Array(read_recent_events(&self.state_dir)))
    }

    async fn logs_recent(&self) -> spt_mcp::Result<Value> {
        // Structured-log tail: read the last lines of `<state_dir>/spt.log`.
        Ok(Value::Array(read_log_tail(&self.state_dir, 200)))
    }

    async fn metrics(&self) -> spt_mcp::Result<Value> {
        let path = self.state_dir.join("metrics.prom");
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        Ok(json!({ "format": "prometheus", "body": body }))
    }

    async fn diagnostics_recent(&self) -> spt_mcp::Result<Value> {
        let path = self.state_dir.join("diagnostics").join("latest.json");
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
                .map_err(|e| spt_mcp::Error::Internal(format!("diagnostics: {e}"))),
            Err(_) => Ok(json!({})),
        }
    }

    async fn benchmarks_recent(&self) -> spt_mcp::Result<Value> {
        let path = self.state_dir.join("benchmarks").join("latest.json");
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
                .map_err(|e| spt_mcp::Error::Internal(format!("benchmarks: {e}"))),
            Err(_) => Ok(json!({})),
        }
    }
}

/// Read the tail of the most recent daily events JSONL file under
/// `<state_dir>/events/`. Best-effort; returns an empty vec on any error.
fn read_recent_events(state_dir: &std::path::Path) -> Vec<Value> {
    let dir = state_dir.join("events");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    // Pick the lexicographically-greatest file name (daily files are
    // `events-YYYY-MM-DD.jsonl`, so lexical order == chronological order).
    let latest = rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).max();
    let Some(path) = latest else {
        return Vec::new();
    };
    let Ok(body) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    body.lines()
        .rev()
        .take(200)
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

/// Read the last `n` lines of `<state_dir>/spt.log` as JSON string values.
/// Best-effort; returns an empty vec when the log is absent.
fn read_log_tail(state_dir: &std::path::Path, n: usize) -> Vec<Value> {
    let path = state_dir.join("spt.log");
    let Ok(body) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let lines: Vec<&str> = body.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..]
        .iter()
        .map(|l| Value::String((*l).to_owned()))
        .collect()
}

// ===========================================================================
// Source bundle + config → policy mapping
// ===========================================================================

/// Bundle of the two source adapters passed into the server builder.
///
/// Construct via [`McpSources::from_config_and_state_dir`] in `cli_dispatch`
/// and hand to [`build_server_with_sources`].
#[derive(Clone)]
pub struct McpSources {
    /// Config-backed read source.
    pub config: DynConfigSource,
    /// State-dir-backed read source.
    pub state: DynStateSource,
}

impl McpSources {
    /// Build real adapters from a live config snapshot + the state directory.
    #[must_use]
    pub fn from_config_and_state_dir(cfg: Config, state_dir: PathBuf) -> Self {
        Self {
            config: Arc::new(ConfigSnapshotSource::new(cfg)) as DynConfigSource,
            state: Arc::new(StateDirSource::new(state_dir)) as DynStateSource,
        }
    }

    /// All-noop sources (fixtures). Used by `spt mcp serve` standalone.
    #[must_use]
    pub fn noop() -> Self {
        let sources = Arc::new(NoopSources);
        Self {
            config: sources.clone() as DynConfigSource,
            state: sources as DynStateSource,
        }
    }
}

/// Project the loaded `[mcp]` config table into the `spt-mcp` [`McpPolicy`].
///
/// Honours the operator's `enabled`, `default_mode`, `allow_write_tools`,
/// `allow_secret_reveal`, `listen`, and `stdio` settings. The live-loopback
/// path in `cli_dispatch` widens `allow_write_tools` to the live-bridge tools
/// it needs *on top of* this base (see `maybe_spawn_mcp_loopback`), but the
/// `spt://config/mcp_policy` resource reports the configured policy verbatim.
#[must_use]
pub fn mcp_policy_from_config(cfg: &Config) -> McpPolicy {
    let Some(mcp) = cfg.mcp.as_ref() else {
        return McpPolicy::default();
    };
    McpPolicy {
        enabled: mcp.enabled.unwrap_or(false),
        // E-w4: honor `[mcp].default_mode` (the baseline read/write posture).
        // Unknown / absent maps fail-closed to `read_only`.
        default_mode: spt_mcp::McpMode::from_config_str(mcp.default_mode.as_deref()),
        allow_write_tools: mcp.allow_write_tools.clone().unwrap_or_default(),
        allow_secret_reveal: mcp.allow_secret_reveal.unwrap_or(false),
        listen: mcp.listen.clone().unwrap_or_default(),
        stdio: mcp.stdio.unwrap_or(true),
        // E-w4: carry the TLS-pin surface so it is enforced fail-closed on the
        // MCP TLS listener/client instead of silently ignored.
        tls_pins: spt_mcp::TlsPinPolicy {
            pin_spki_sha256: mcp.pin_spki_sha256.clone(),
            allow_self_signed: mcp.allow_self_signed.unwrap_or(false),
            max_cert_chain_depth: mcp.max_cert_chain_depth,
        },
    }
}

/// Build the optional MCP audit sink, gated on `[mcp].audit_events` (E8-F5).
///
/// Returns `Some(bridge)` when `audit_events = true`, where the bridge
/// forwards every MCP tool call into the workspace [`spt_core::audit`] seam
/// (the same seam wired to the operator log / event bus at startup). Returns
/// `None` otherwise, so the caller falls back to the no-op sink.
#[must_use]
pub fn mcp_audit_sink(cfg: &Config) -> Option<DynAuditSink> {
    let audit_events = cfg
        .mcp
        .as_ref()
        .and_then(|m| m.audit_events)
        .unwrap_or(false);
    if audit_events {
        Some(crate::audit::McpAuditBridge::arc())
    } else {
        None
    }
}

// ===========================================================================
// Server constructors
// ===========================================================================

/// Production constructor: build an MCP server with real adapters.
///
/// `sources` carries the config/state adapters; `audit` is the optional audit
/// sink (`None` → no-op). The caller chains `.with_auth_token(..)` for the
/// loopback bearer-token gate.
#[must_use]
pub fn build_server_with_sources(
    policy: McpPolicy,
    controller: Arc<dyn Controller>,
    sources: McpSources,
    audit: Option<DynAuditSink>,
) -> McpServer {
    let audit = audit.unwrap_or_else(|| Arc::new(spt_mcp::NoopAuditSink) as DynAuditSink);
    McpServer::new(
        Policy::new(policy),
        audit,
        controller,
        sources.config,
        sources.state,
    )
}

/// Back-compat: build an MCP server with all-noop sources, given a controller.
///
/// Retained for callers that have no live config to back the sources (e.g.
/// `spt mcp serve` standalone smoke runs). Prefer
/// [`build_server_with_sources`] in the `tunnel run` loopback path.
#[must_use]
pub fn build_server(policy: McpPolicy, controller: Arc<dyn Controller>) -> McpServer {
    build_server_with_sources(policy, controller, McpSources::noop(), None)
}

/// Build an MCP server with all-noop sources/controller and the supplied
/// policy. Used by `spt mcp serve` when the binary has no running
/// orchestrator (i.e. ad-hoc inspection / smoke tests).
#[must_use]
pub fn build_noop_server(policy: McpPolicy) -> McpServer {
    build_server(policy, Arc::new(spt_mcp::NoopController))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_profile() -> Config {
        let toml = r#"
version = 1

[[profiles]]
name = "alpha"
protocol = "ssh2"
host = "edge-1.example"
port = 22

[[profiles.forwards]]
name = "web"
type = "local"
transport = "tcp"
bind = "127.0.0.1:8080"
target = "10.0.0.5:80"

[mcp]
enabled = true
audit_events = true
allow_write_tools = ["tunnel_reload"]
"#;
        spt_config::load_str(toml, false)
            .expect("load test config")
            .0
    }

    #[tokio::test]
    async fn config_source_effective_is_non_empty_object() {
        let src = ConfigSnapshotSource::new(config_with_profile());
        let v = src.effective().await.expect("effective");
        assert!(v.is_object(), "effective must be a structured object");
        assert!(
            v.get("profiles").is_some(),
            "effective config must carry the [profiles] table, got {v}"
        );
    }

    #[tokio::test]
    async fn config_source_profiles_lists_real_profiles() {
        let src = ConfigSnapshotSource::new(config_with_profile());
        let v = src.profiles().await.expect("profiles");
        let arr = v.as_array().expect("array");
        assert_eq!(arr.len(), 1, "expected one profile, got {v}");
        assert_eq!(arr[0]["name"], "alpha");
        assert_eq!(arr[0]["forwards"], 1);
    }

    #[tokio::test]
    async fn config_source_forwards_flattens_across_profiles() {
        let src = ConfigSnapshotSource::new(config_with_profile());
        let v = src.forwards().await.expect("forwards");
        let arr = v.as_array().expect("array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["profile"], "alpha");
        assert_eq!(arr[0]["name"], "web");
        assert_eq!(arr[0]["target"], "10.0.0.5:80");
    }

    #[tokio::test]
    async fn config_source_mcp_policy_reflects_config() {
        let src = ConfigSnapshotSource::new(config_with_profile());
        let v = src.mcp_policy().await.expect("policy");
        assert_eq!(v["enabled"], true);
        assert_eq!(v["allow_write_tools"][0], "tunnel_reload");
    }

    #[tokio::test]
    async fn state_source_status_reads_real_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        // Write a status.json with a known pid + a profile entry.
        let snap = StatusSnapshot {
            pid: 4242,
            profiles: vec![spt_state::status::ProfileStatus {
                id: "alpha".to_owned(),
                state: "active".to_owned(),
                reconnect_count: 3,
                ..Default::default()
            }],
            ..Default::default()
        };
        let path = spt_state::paths::status_path(tmp.path());
        std::fs::write(&path, serde_json::to_vec(&snap).unwrap()).unwrap();

        let src = StateDirSource::new(tmp.path().to_path_buf());
        let v = src.status().await.expect("status");
        assert_eq!(v["pid"], 4242, "status must reflect the on-disk snapshot");
        assert_eq!(v["profiles"][0]["id"], "alpha");

        let stats = src.stats_summary().await.expect("stats");
        assert_eq!(stats["profiles"][0]["reconnect_count"], 3);
    }

    #[tokio::test]
    async fn state_source_missing_status_defaults_not_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let src = StateDirSource::new(tmp.path().to_path_buf());
        // No status.json written — must default rather than error.
        let v = src.status().await.expect("status");
        assert!(v.is_object());
        assert_eq!(v["pid"], 0);
    }

    #[test]
    fn audit_sink_gated_on_config_flag() {
        let cfg = config_with_profile();
        assert!(
            mcp_audit_sink(&cfg).is_some(),
            "audit_events = true must yield a sink"
        );

        let (mut cfg2, _) =
            spt_config::load_str("version = 1\n[mcp]\nenabled = true\n", false).unwrap();
        cfg2.mcp.as_mut().unwrap().audit_events = None;
        assert!(
            mcp_audit_sink(&cfg2).is_none(),
            "absent audit_events must yield no sink"
        );
    }
}
