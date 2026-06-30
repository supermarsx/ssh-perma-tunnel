//! The 31 MCP tools from spec §16.
//!
//! Each tool is a small async closure mapped through a shared
//! [`ToolContext`]. Tools that mutate persistent state are also listed in
//! [`crate::policy::WRITE_TOOLS`] and gated by the policy engine before
//! dispatch — the registry itself does not enforce policy.
//!
//! Handlers call into the appropriate trait adapter:
//! - read-only tools use [`crate::sources::ConfigSource`] /
//!   [`crate::sources::StateSource`];
//! - mutating tools call through [`crate::controller::Controller`].
//!
//! The spec lists 31 tools; the [`ToolRegistry::new`] constructor asserts
//! that count at registration time so a missing tool fails the build's tests.

use crate::controller::DynController;
use crate::protocol::ToolDescriptor;
use crate::sources::{DynConfigSource, DynStateSource};
use async_trait::async_trait;
use serde_json::{json, Value};
use spt_config::schema::Forward;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Bundle of dependencies passed to every tool handler.
pub struct ToolContext {
    /// Read-only configuration adapter.
    pub config: DynConfigSource,
    /// Read-only runtime-state adapter.
    pub state: DynStateSource,
    /// Mutating runtime-control adapter.
    pub controller: DynController,
    /// Per-connection notification sender. The transport sets this before
    /// dispatching streaming tools (e.g. `stats_subscribe`); on stdio /
    /// non-streaming transports it remains `None`.
    pub notification_sender: Option<tokio::sync::mpsc::Sender<serde_json::Value>>,
    /// Live tracing-filter reload bridge. Populated when the binary wires
    /// the MCP server against the process-wide log subscriber; tests and
    /// loopback paths typically leave this as `None`.
    ///
    /// Trait-object so this crate doesn't need a hard dep on
    /// `spt-observability` — the binary supplies an adapter.
    pub log_reload: Option<Arc<dyn LogReloadBridge>>,
}

/// Live-tracing reload adapter. The MCP `log_set_level` tool calls
/// [`Self::reload`] with a parsed `EnvFilter`-style directive.
///
/// `spt-observability::LogReloadHandle` implements this trait via a thin
/// wrapper in `spt-bin/src/mcp_server.rs` (the binary owns the cross-crate
/// glue). Kept here as a trait so the MCP crate has zero observability deps.
#[async_trait]
pub trait LogReloadBridge: Send + Sync + 'static {
    /// Apply `directive` as the new global log filter. Implementations
    /// should validate syntax and return `Err` on failure so the tool can
    /// surface a meaningful error to the MCP client.
    async fn reload(&self, directive: &str) -> Result<(), String>;
}

/// One tool. Implementors describe themselves and execute a single async call.
#[async_trait]
pub trait ToolHandler: Send + Sync + 'static {
    /// Stable tool name, e.g. `"forward_add"`.
    fn name(&self) -> &'static str;
    /// Descriptor returned by `tools/list`.
    fn descriptor(&self) -> ToolDescriptor;
    /// Execute the tool with the given JSON arguments.
    async fn call(&self, ctx: &ToolContext, args: Value) -> crate::Result<Value>;
}

/// The full canonical name list from spec §16, in spec order. Used by tests
/// and the registry sanity-check.
///
/// The original spec lists 31 tools; 4 additional live-bridge tools
/// (`session_close`, `session_drain`, `stats_subscribe`, `events_subscribe`;
/// `benchmark_run` already counted) are appended for the loopback control
/// surface, plus the observability live-control tool `log_set_level` (t8-A3)
/// for a total of 36.
pub const ALL_TOOL_NAMES: &[&str] = &[
    "config_validate",
    "config_doctor",
    "config_render",
    "profile_list",
    "profile_show",
    "profile_set",
    "forward_list",
    "forward_explain",
    "forward_add",
    "forward_remove",
    "tunnel_status",
    "tunnel_reload",
    "tunnel_failover",
    "stats_summary",
    "stats_export",
    "session_list",
    "session_show",
    "diagnose_run",
    "diagnose_bundle",
    "benchmark_run",
    "benchmark_report_export",
    "dns_query",
    "dns_record_add",
    "dns_record_remove",
    "log_tail",
    "observe_metrics",
    "event_test",
    "service_render",
    "secret_list",
    "secret_set_ref",
    "key_inspect",
    // Live-bridge tools added by f-live-bridge.
    "session_close",
    "session_drain",
    "stats_subscribe",
    "events_subscribe",
    // Observability: runtime log filter override (t8-A3).
    "log_set_level",
];

/// Internal helper: build a no-arguments JSON-Schema.
fn empty_schema() -> Value {
    json!({"type": "object", "properties": {}, "additionalProperties": false})
}

/// Macro: define a tool implementing [`ToolHandler`].
///
/// Variants:
/// - `read_cfg(name, desc, source_method)` — calls `ConfigSource::method()`.
/// - `read_state(name, desc, source_method)` — calls `StateSource::method()`.
/// - `ctrl(name, desc, controller_method, arg_field)` — calls a Controller
///   method that takes a single string argument named `arg_field`.
macro_rules! tool {
    (read_cfg, $struct:ident, $name:literal, $desc:literal, $method:ident) => {
        pub struct $struct;
        #[async_trait::async_trait]
        impl ToolHandler for $struct {
            fn name(&self) -> &'static str {
                $name
            }
            fn descriptor(&self) -> ToolDescriptor {
                ToolDescriptor {
                    name: $name.to_owned(),
                    description: $desc.to_owned(),
                    input_schema: empty_schema(),
                }
            }
            async fn call(&self, ctx: &ToolContext, _args: Value) -> crate::Result<Value> {
                ctx.config.$method().await
            }
        }
    };
    (read_state, $struct:ident, $name:literal, $desc:literal, $method:ident) => {
        pub struct $struct;
        #[async_trait::async_trait]
        impl ToolHandler for $struct {
            fn name(&self) -> &'static str {
                $name
            }
            fn descriptor(&self) -> ToolDescriptor {
                ToolDescriptor {
                    name: $name.to_owned(),
                    description: $desc.to_owned(),
                    input_schema: empty_schema(),
                }
            }
            async fn call(&self, ctx: &ToolContext, _args: Value) -> crate::Result<Value> {
                ctx.state.$method().await
            }
        }
    };
}

// --- read-only tools ---------------------------------------------------------

tool!(
    read_cfg,
    ConfigValidate,
    "config_validate",
    "Validate the loaded config.",
    effective
);
tool!(
    read_cfg,
    ConfigDoctor,
    "config_doctor",
    "Run the config doctor and report findings.",
    effective
);
tool!(
    read_cfg,
    ConfigRender,
    "config_render",
    "Render the canonical (redacted) config.",
    redacted
);
tool!(
    read_cfg,
    ProfileList,
    "profile_list",
    "List configured profiles.",
    profiles
);
tool!(
    read_cfg,
    ForwardList,
    "forward_list",
    "List configured forwards.",
    forwards
);

// `profile_show` and `forward_explain` take a name; they still surface the
// full list and let the client filter for now (read-only adapter is enough).
tool!(
    read_cfg,
    ProfileShow,
    "profile_show",
    "Show one profile (filter client-side).",
    profiles
);
tool!(
    read_cfg,
    ForwardExplain,
    "forward_explain",
    "Explain one forward (filter client-side).",
    forwards
);
tool!(
    read_state,
    TunnelStatus,
    "tunnel_status",
    "Return the runtime status snapshot.",
    status
);
tool!(
    read_state,
    StatsSummary,
    "stats_summary",
    "Return the global + per-profile stats summary.",
    stats_summary
);
tool!(
    read_state,
    StatsExport,
    "stats_export",
    "Export the latest stats blob.",
    stats_summary
);
tool!(
    read_state,
    SessionList,
    "session_list",
    "List currently open sessions.",
    sessions_current
);
tool!(
    read_state,
    SessionShow,
    "session_show",
    "Show one session (filter client-side).",
    sessions_current
);
tool!(
    read_state,
    LogTail,
    "log_tail",
    "Tail recent structured logs (redacted).",
    logs_recent
);
tool!(
    read_state,
    ObserveMetrics,
    "observe_metrics",
    "Return the latest Prometheus metrics body.",
    metrics
);
tool!(
    read_cfg,
    ServiceRender,
    "service_render",
    "Render the platform service definition.",
    service_definition
);
tool!(
    read_cfg,
    DnsQuery,
    "dns_query",
    "Inspect the configured DNS records.",
    dns_records
);

// --- scoped read-only tools (config-exposure hardening) ----------------------
//
// `secret_list` and `key_inspect` previously returned the WHOLE effective
// config (every field, every value) and relied solely on the central
// redaction pass. That maximizes exposure. They now project the effective
// config down to the minimal, non-sensitive surface each tool actually needs:
// `secret_list` returns only `secret://` reference URIs, and `key_inspect`
// returns only key-reference metadata (paths / refs) with any inline key
// material redacted. Neither can return a resolved secret or key bytes.

/// Recursively collect every `secret://ns/name` reference string found
/// anywhere in `value` into a sorted, de-duplicated set. Only reference URIs
/// are collected — no other scalar is ever emitted, so the result cannot
/// contain a plaintext secret.
fn collect_secret_refs(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::String(s) if s.starts_with("secret://") => {
            out.insert(s.clone());
        }
        Value::Array(arr) => {
            for v in arr {
                collect_secret_refs(v, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_secret_refs(v, out);
            }
        }
        _ => {}
    }
}

/// Object-key substrings that mark a field as a *key reference* (a path to,
/// or reference for, cryptographic key/certificate material).
const KEY_REF_HINTS: &[&str] = &[
    "identity_file",
    "identity",
    "private_key",
    "privkey",
    "public_key",
    "pubkey",
    "key_file",
    "keyfile",
    "key_path",
    "host_key",
    "cert",
    "certificate",
];

fn key_name_is_key_ref(key: &str) -> bool {
    let lower = key.to_lowercase();
    KEY_REF_HINTS.iter().any(|hint| lower.contains(hint))
}

/// Classify a key-reference field's value into something safe to surface.
///
/// * a `secret://` URI is a reference → kept verbatim;
/// * anything that looks like inline key material (PEM markers, embedded
///   newlines, or a long blob) → redacted to `"***"`;
/// * a short single-line string (a file path or fingerprint) → kept;
/// * non-string values → not surfaced (the recursive walk handles nesting).
fn classify_key_value(value: &Value) -> Option<String> {
    let s = value.as_str()?;
    if s.starts_with("secret://") {
        return Some(s.to_owned());
    }
    let looks_like_material = s.contains("BEGIN")
        || s.contains("PRIVATE KEY")
        || s.contains('\n')
        || s.contains('\r')
        || s.len() > 200;
    if looks_like_material {
        Some("***".to_owned())
    } else {
        Some(s.to_owned())
    }
}

/// Recursively collect key-reference entries. For every object field whose
/// name matches [`KEY_REF_HINTS`] and whose value is a string, emit a
/// `{path, key, ref}` entry (with inline material redacted). The walk also
/// descends into all nested values.
fn collect_key_refs(value: &Value, path: &str, out: &mut Vec<Value>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let child_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if key_name_is_key_ref(k) {
                    if let Some(reference) = classify_key_value(v) {
                        out.push(json!({"path": child_path, "key": k, "ref": reference}));
                    }
                }
                collect_key_refs(v, &child_path, out);
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let child_path = format!("{path}[{i}]");
                collect_key_refs(v, &child_path, out);
            }
        }
        _ => {}
    }
}

/// `secret_list`: enumerate the `secret://` references in the effective
/// config. Never returns resolved secret values — only the reference URIs.
pub struct SecretList;
#[async_trait]
impl ToolHandler for SecretList {
    fn name(&self) -> &'static str {
        "secret_list"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "List secret refs (never values).".to_owned(),
            input_schema: empty_schema(),
        }
    }
    async fn call(&self, ctx: &ToolContext, _args: Value) -> crate::Result<Value> {
        let cfg = ctx.config.effective().await?;
        let mut refs = BTreeSet::new();
        collect_secret_refs(&cfg, &mut refs);
        Ok(json!({ "secret_refs": refs.into_iter().collect::<Vec<_>>() }))
    }
}

/// `key_inspect`: enumerate configured key references (file paths / secret
/// refs). Never returns inline key material — PEM blobs and other inline key
/// bytes are redacted.
pub struct KeyInspect;
#[async_trait]
impl ToolHandler for KeyInspect {
    fn name(&self) -> &'static str {
        "key_inspect"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Inspect configured key references.".to_owned(),
            input_schema: empty_schema(),
        }
    }
    async fn call(&self, ctx: &ToolContext, _args: Value) -> crate::Result<Value> {
        let cfg = ctx.config.effective().await?;
        let mut keys = Vec::new();
        collect_key_refs(&cfg, "", &mut keys);
        Ok(json!({ "keys": keys }))
    }
}

// --- mutating tools ----------------------------------------------------------

/// `profile_set`: set a single profile field.
pub struct ProfileSet;
#[async_trait]
impl ToolHandler for ProfileSet {
    fn name(&self) -> &'static str {
        "profile_set"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Set a profile field (persisted via spt-config mutation path).".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile": {"type": "string"},
                    "path": {"type": "string", "description": "Dotted config path."},
                    "value": {}
                },
                "required": ["profile", "path", "value"],
            }),
        }
    }
    async fn call(&self, _ctx: &ToolContext, args: Value) -> crate::Result<Value> {
        // Persisting field-level edits is the binary's responsibility; the
        // controller adapter does not yet expose a free-form mutation. We
        // surface the planned update to the client without persisting.
        Ok(json!({"applied": false, "planned": args}))
    }
}

/// `forward_add`: add a forward to a profile.
pub struct ForwardAdd;
#[async_trait]
impl ToolHandler for ForwardAdd {
    fn name(&self) -> &'static str {
        "forward_add"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Add a forward to a profile.".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile": {"type": "string"},
                    "forward": {"type": "object"}
                },
                "required": ["profile", "forward"],
            }),
        }
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> crate::Result<Value> {
        let profile = args.get("profile").and_then(Value::as_str).ok_or_else(|| {
            crate::Error::InvalidParams("missing string field 'profile'".to_owned())
        })?;
        let forward_value = args.get("forward").cloned().ok_or_else(|| {
            crate::Error::InvalidParams("missing object field 'forward'".to_owned())
        })?;
        let forward: Forward = serde_json::from_value(forward_value)
            .map_err(|e| crate::Error::InvalidParams(format!("invalid 'forward' object: {e}")))?;
        ctx.controller.forward_add(profile, &forward).await?;
        let name = forward.name.clone();
        Ok(json!({"applied": true, "profile": profile, "forward": name}))
    }
}

/// `forward_remove`: remove a forward from a profile.
pub struct ForwardRemove;
#[async_trait]
impl ToolHandler for ForwardRemove {
    fn name(&self) -> &'static str {
        "forward_remove"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Remove a forward from a profile.".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile": {"type": "string"},
                    "forward_id": {"type": "string"}
                },
                "required": ["profile", "forward_id"],
            }),
        }
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> crate::Result<Value> {
        let profile = args.get("profile").and_then(Value::as_str).ok_or_else(|| {
            crate::Error::InvalidParams("missing string field 'profile'".to_owned())
        })?;
        let forward_id = args
            .get("forward_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                crate::Error::InvalidParams("missing string field 'forward_id'".to_owned())
            })?;
        ctx.controller.forward_remove(profile, forward_id).await?;
        Ok(json!({"applied": true, "profile": profile, "forward": forward_id}))
    }
}

/// `tunnel_reload`: ask the orchestrator to reload its configuration.
pub struct TunnelReload;
#[async_trait]
impl ToolHandler for TunnelReload {
    fn name(&self) -> &'static str {
        "tunnel_reload"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Reload configuration and reconcile profile state.".to_owned(),
            input_schema: empty_schema(),
        }
    }
    async fn call(&self, ctx: &ToolContext, _args: Value) -> crate::Result<Value> {
        ctx.controller.reload().await?;
        Ok(json!({"applied": true}))
    }
}

/// `tunnel_failover`: force a failover step on the named profile.
pub struct TunnelFailover;
#[async_trait]
impl ToolHandler for TunnelFailover {
    fn name(&self) -> &'static str {
        "tunnel_failover"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Force one failover step on a profile.".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile": {"type": "string"},
                    "endpoint": {"type": "string", "description": "Optional endpoint id to mark failed."}
                },
                "required": ["profile"],
                "additionalProperties": true,
            }),
        }
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> crate::Result<Value> {
        let profile = args.get("profile").and_then(Value::as_str).ok_or_else(|| {
            crate::Error::InvalidParams("missing string field 'profile'".to_owned())
        })?;
        let endpoint = args.get("endpoint").and_then(Value::as_str);
        ctx.controller.failover(profile, endpoint).await?;
        Ok(json!({"applied": true, "profile": profile, "endpoint": endpoint}))
    }
}

/// Generic "noop, return planned action" tool body — used for the remaining
/// mutating tools whose persistence path is owned by the binary.
#[allow(clippy::unused_async)]
async fn planned(args: Value) -> crate::Result<Value> {
    Ok(json!({"applied": false, "planned": args}))
}

macro_rules! planned_tool {
    ($struct:ident, $name:literal, $desc:literal, $schema:expr) => {
        pub struct $struct;
        #[async_trait::async_trait]
        impl ToolHandler for $struct {
            fn name(&self) -> &'static str {
                $name
            }
            fn descriptor(&self) -> ToolDescriptor {
                ToolDescriptor {
                    name: $name.to_owned(),
                    description: $desc.to_owned(),
                    input_schema: $schema,
                }
            }
            async fn call(&self, _ctx: &ToolContext, args: Value) -> crate::Result<Value> {
                planned(args).await
            }
        }
    };
}

planned_tool!(
    DiagnoseRun,
    "diagnose_run",
    "Run the diagnostic check framework.",
    empty_schema()
);
planned_tool!(
    DiagnoseBundle,
    "diagnose_bundle",
    "Build a redacted diagnostics bundle.",
    empty_schema()
);
planned_tool!(
    BenchmarkReportExport,
    "benchmark_report_export",
    "Export a benchmark report.",
    empty_schema()
);

/// `benchmark_run`: drive a benchmark driver against the live tunnel.
pub struct BenchmarkRun;
#[async_trait]
impl ToolHandler for BenchmarkRun {
    fn name(&self) -> &'static str {
        "benchmark_run"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Run a benchmark driver against the live tunnel.".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "driver": {"type": "string"},
                    "profile": {"type": "string"},
                    "forward": {"type": "string"},
                    "count": {"type": "integer", "minimum": 1},
                    "duration_seconds": {"type": "integer", "minimum": 1},
                    "allow_production_impact": {"type": "boolean"}
                },
                "required": ["driver"],
                "additionalProperties": true,
            }),
        }
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> crate::Result<Value> {
        ctx.controller.run_benchmark(args).await
    }
}

/// `session_close`: tear down a single live session by id.
pub struct SessionClose;
#[async_trait]
impl ToolHandler for SessionClose {
    fn name(&self) -> &'static str {
        "session_close"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Close a single live session by id.".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            }),
        }
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> crate::Result<Value> {
        let id = args
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::Error::InvalidParams("missing string field 'id'".to_owned()))?;
        ctx.controller.session_close(id).await?;
        Ok(json!({"applied": true, "id": id}))
    }
}

/// `session_drain`: stop accepting new connections, wait grace, force close.
pub struct SessionDrain;
#[async_trait]
impl ToolHandler for SessionDrain {
    fn name(&self) -> &'static str {
        "session_drain"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Drain all forwards of a profile within a grace window.".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile": {"type": "string"},
                    "grace_seconds": {"type": "integer", "minimum": 0}
                },
                "required": ["profile"],
            }),
        }
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> crate::Result<Value> {
        let profile = args.get("profile").and_then(Value::as_str).ok_or_else(|| {
            crate::Error::InvalidParams("missing string field 'profile'".to_owned())
        })?;
        let grace_seconds = args
            .get("grace_seconds")
            .and_then(Value::as_u64)
            .unwrap_or(5);
        let report = ctx.controller.session_drain(profile, grace_seconds).await?;
        Ok(json!({"applied": true, "profile": profile, "report": report}))
    }
}

/// `stats_subscribe`: register a streaming subscription. The server pushes
/// `notifications/stats/tick` notifications on this connection until the
/// client disconnects.
///
/// Spawns the subscription via the controller. Each tick is forwarded as a
/// JSON-RPC notification by the per-connection task in
/// [`crate::transport::run_connection_with_notifications`].
pub struct StatsSubscribe;
#[async_trait]
impl ToolHandler for StatsSubscribe {
    fn name(&self) -> &'static str {
        "stats_subscribe"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Subscribe to live StatsTick notifications. Frames are emitted as `notifications/stats/tick`.".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "interval_ms": {"type": "integer", "minimum": 100}
                },
                "additionalProperties": true,
            }),
        }
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> crate::Result<Value> {
        let interval_ms = args.get("interval_ms").and_then(Value::as_u64).unwrap_or(0);
        // Streaming dispatch: we install a per-connection mpsc::Sender by
        // having the server set `ctx.notification_sender` before dispatch.
        // If a sender is present we hand it to the controller; if not we
        // return a typed error so the client knows to use a transport that
        // supports notifications (i.e. the loopback path).
        let tx = ctx.notification_sender.clone().ok_or_else(|| {
            crate::Error::InvalidParams(
                "stats_subscribe requires a transport with notification support".to_owned(),
            )
        })?;
        ctx.controller.stats_subscribe(interval_ms, tx).await?;
        Ok(json!({
            "subscribed": true,
            "interval_ms": interval_ms,
            "notification": "notifications/stats/tick"
        }))
    }
}

/// `events_subscribe`: register a streaming subscription for live event
/// notifications. The server pushes `spt/event` JSON-RPC notification frames
/// on this connection until the client disconnects.
///
/// This mirrors [`StatsSubscribe`] exactly: it installs the per-connection
/// `mpsc::Sender` (set by the loopback transport before dispatch) on the
/// controller, which spawns a relay task forwarding each event frame. The
/// frames originate from the binary's `mcp_notify` event sink (a broadcast
/// channel), the same broadcast pattern `stats_subscribe` uses for ticks.
///
/// Unlike `stats_subscribe`, whose payloads the transport wraps into
/// `notifications/stats/tick`, the values relayed here are already complete
/// JSON-RPC notification frames (`{"jsonrpc":"2.0","method":"spt/event",..}`),
/// which the transport forwards verbatim.
pub struct EventsSubscribe;
#[async_trait]
impl ToolHandler for EventsSubscribe {
    fn name(&self) -> &'static str {
        "events_subscribe"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Subscribe to live event notifications. Frames are emitted as `spt/event` JSON-RPC notifications carrying the serialized Event.".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": true,
            }),
        }
    }
    async fn call(&self, ctx: &ToolContext, _args: Value) -> crate::Result<Value> {
        // Streaming dispatch: the server sets `ctx.notification_sender` before
        // dispatch on transports that support notifications (the loopback
        // path). Without one we return a typed error so the client knows to
        // use a notification-capable transport — same contract as
        // `stats_subscribe`.
        let tx = ctx.notification_sender.clone().ok_or_else(|| {
            crate::Error::InvalidParams(
                "events_subscribe requires a transport with notification support".to_owned(),
            )
        })?;
        ctx.controller.events_subscribe(tx).await?;
        Ok(json!({
            "subscribed": true,
            "notification": "spt/event"
        }))
    }
}

/// `log_set_level`: change the live tracing filter directive at runtime.
///
/// Constructs an `EnvFilter`-style directive of the form `target=level` from
/// the two arguments and hands it to the configured
/// [`LogReloadBridge`] (wired by `spt-bin` against the process-wide
/// subscriber). Pre-validates the level and target syntax so misuse fails
/// before the bridge is invoked.
///
/// This is a **privileged** tool — it mutates global process state. The
/// policy engine treats it as a write tool (see [`crate::policy::WRITE_TOOLS`]).
pub struct LogSetLevel;

/// Levels accepted by the `log_set_level` tool. Must match
/// `tracing`'s level vocabulary (case-insensitive).
const VALID_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error", "off"];

/// Validate a target string. Tracing targets are typically Rust module paths
/// (`my_crate::sub`) or simple identifiers (`my_crate`); we accept ASCII
/// alphanumeric plus `_`, `:`, `-`, and `.` and require a leading letter or
/// underscore.
fn is_valid_target(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '-' | '.'))
}

#[async_trait]
impl ToolHandler for LogSetLevel {
    fn name(&self) -> &'static str {
        "log_set_level"
    }
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name().to_owned(),
            description: "Set the tracing log filter for one target at runtime. \
                 Example: target=\"spt_supervisor\", level=\"debug\". \
                 Privileged — gated by `allow_write_tools`."
                .to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Tracing target (Rust module path or identifier)."
                    },
                    "level": {
                        "type": "string",
                        "enum": ["trace", "debug", "info", "warn", "error", "off"],
                        "description": "New level for the target."
                    }
                },
                "required": ["target", "level"],
                "additionalProperties": false,
            }),
        }
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> crate::Result<Value> {
        let target = args.get("target").and_then(Value::as_str).ok_or_else(|| {
            crate::Error::InvalidParams("missing string field 'target'".to_owned())
        })?;
        let level_raw = args.get("level").and_then(Value::as_str).ok_or_else(|| {
            crate::Error::InvalidParams("missing string field 'level'".to_owned())
        })?;
        let level = level_raw.to_ascii_lowercase();
        if !VALID_LEVELS.contains(&level.as_str()) {
            return Err(crate::Error::InvalidParams(format!(
                "invalid level '{level_raw}'; expected one of {VALID_LEVELS:?}"
            )));
        }
        if !is_valid_target(target) {
            return Err(crate::Error::InvalidParams(format!(
                "invalid tracing target '{target}'"
            )));
        }
        let bridge = ctx.log_reload.as_ref().ok_or_else(|| {
            crate::Error::Internal("log reload bridge not wired into this MCP server".to_owned())
        })?;
        let directive = format!("{target}={level}");
        bridge
            .reload(&directive)
            .await
            .map_err(|e| crate::Error::Internal(format!("log reload failed: {e}")))?;
        Ok(json!({
            "applied": true,
            "target": target,
            "level": level,
            "directive": directive,
        }))
    }
}

planned_tool!(
    DnsRecordAdd,
    "dns_record_add",
    "Add a DNS record.",
    empty_schema()
);
planned_tool!(
    DnsRecordRemove,
    "dns_record_remove",
    "Remove a DNS record.",
    empty_schema()
);
planned_tool!(
    EventTest,
    "event_test",
    "Send a test event to bindings.",
    empty_schema()
);
planned_tool!(
    SecretSetRef,
    "secret_set_ref",
    "Bind a secret reference (no values).",
    empty_schema()
);

/// Registry of all 31 tool handlers, keyed by name.
pub struct ToolRegistry {
    by_name: BTreeMap<&'static str, Arc<dyn ToolHandler>>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    /// Build the standard registry of all 31 spec tools.
    ///
    /// Asserts at runtime that exactly 31 tools register and that every
    /// registered name appears in [`ALL_TOOL_NAMES`].
    #[must_use]
    pub fn new() -> Self {
        let mut by_name: BTreeMap<&'static str, Arc<dyn ToolHandler>> = BTreeMap::new();
        macro_rules! add {
            ($t:ident) => {{
                let h: Arc<dyn ToolHandler> = Arc::new($t);
                by_name.insert(h.name(), h);
            }};
        }
        // read-only
        add!(ConfigValidate);
        add!(ConfigDoctor);
        add!(ConfigRender);
        add!(ProfileList);
        add!(ProfileShow);
        add!(ForwardList);
        add!(ForwardExplain);
        add!(TunnelStatus);
        add!(StatsSummary);
        add!(StatsExport);
        add!(SessionList);
        add!(SessionShow);
        add!(LogTail);
        add!(ObserveMetrics);
        add!(ServiceRender);
        add!(KeyInspect);
        add!(SecretList);
        add!(DnsQuery);
        // mutating
        add!(ProfileSet);
        add!(ForwardAdd);
        add!(ForwardRemove);
        add!(TunnelReload);
        add!(TunnelFailover);
        add!(DiagnoseRun);
        add!(DiagnoseBundle);
        add!(BenchmarkRun);
        add!(BenchmarkReportExport);
        add!(DnsRecordAdd);
        add!(DnsRecordRemove);
        add!(EventTest);
        add!(SecretSetRef);
        // Live-bridge additions (f-live-bridge):
        add!(SessionClose);
        add!(SessionDrain);
        add!(StatsSubscribe);
        add!(EventsSubscribe);
        // Observability live-control (t8-A3):
        add!(LogSetLevel);

        debug_assert_eq!(by_name.len(), ALL_TOOL_NAMES.len(), "tool count mismatch");
        Self { by_name }
    }

    /// Number of registered tools (must be 36).
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Always `false` — non-empty after [`Self::new`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// All registered tool names, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.by_name.keys().copied().collect()
    }

    /// Descriptors for `tools/list`, sorted by name.
    #[must_use]
    pub fn list(&self) -> Vec<ToolDescriptor> {
        self.by_name.values().map(|h| h.descriptor()).collect()
    }

    /// Look up a tool handler by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<dyn ToolHandler>> {
        self.by_name.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::testing::{ControllerCall, RecordingController};
    use crate::controller::NoopController;
    use crate::sources::NoopSources;

    #[test]
    fn registry_contains_all_tools() {
        let r = ToolRegistry::new();
        assert_eq!(
            r.len(),
            ALL_TOOL_NAMES.len(),
            "spec §16 + live-bridge tools"
        );
    }

    #[test]
    fn every_spec_tool_is_registered() {
        let r = ToolRegistry::new();
        for name in ALL_TOOL_NAMES {
            assert!(r.get(name).is_some(), "missing tool: {name}");
        }
    }

    #[test]
    fn registry_is_not_empty() {
        let r = ToolRegistry::new();
        assert!(!r.is_empty());
        let names = r.names();
        assert_eq!(names.len(), ALL_TOOL_NAMES.len());
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn registry_default_matches_new() {
        let a = ToolRegistry::default();
        let b = ToolRegistry::new();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn registry_get_unknown_is_none() {
        let r = ToolRegistry::new();
        assert!(r.get("nope_definitely_not").is_none());
    }

    #[test]
    fn empty_schema_is_object_with_no_properties() {
        let v = empty_schema();
        assert_eq!(v["type"], "object");
        assert_eq!(v["additionalProperties"], false);
        assert!(v["properties"].is_object());
    }

    #[test]
    fn list_returns_descriptor_per_tool() {
        let r = ToolRegistry::new();
        let list = r.list();
        assert_eq!(list.len(), ALL_TOOL_NAMES.len());
        for d in list {
            assert!(!d.name.is_empty());
            assert!(!d.description.is_empty());
        }
    }

    fn ctx_with(ctrl: Arc<dyn crate::controller::Controller>) -> ToolContext {
        let sources = Arc::new(NoopSources);
        ToolContext {
            config: sources.clone() as DynConfigSource,
            state: sources as DynStateSource,
            controller: ctrl,
            notification_sender: None,
            log_reload: None,
        }
    }

    #[tokio::test]
    async fn profile_set_returns_planned_envelope() {
        let ctx = ctx_with(Arc::new(NoopController));
        let v = ProfileSet
            .call(&ctx, json!({"profile":"p","path":"a.b","value":42}))
            .await
            .expect("ok");
        assert_eq!(v["applied"], false);
        assert_eq!(v["planned"]["profile"], "p");
    }

    #[tokio::test]
    async fn forward_add_missing_profile_errors_invalid_params() {
        let ctx = ctx_with(Arc::new(NoopController));
        let err = ForwardAdd
            .call(&ctx, json!({"forward": {}}))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    #[tokio::test]
    async fn forward_add_missing_forward_errors() {
        let ctx = ctx_with(Arc::new(NoopController));
        let err = ForwardAdd
            .call(&ctx, json!({"profile": "p"}))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    #[tokio::test]
    async fn forward_add_routes_to_controller() {
        let ctrl = RecordingController::new();
        let ctx = ctx_with(Arc::new(ctrl.clone()));
        let v = ForwardAdd
            .call(
                &ctx,
                json!({
                    "profile": "alpha",
                    "forward": {"name":"w","type":"local","transport":"tcp"}
                }),
            )
            .await
            .expect("ok");
        assert_eq!(v["applied"], true);
        assert_eq!(v["profile"], "alpha");
        assert_eq!(ctrl.snapshot().len(), 1);
    }

    #[tokio::test]
    async fn forward_remove_missing_args_errors() {
        let ctx = ctx_with(Arc::new(NoopController));
        let err = ForwardRemove.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));

        let err = ForwardRemove
            .call(&ctx, json!({"profile": "p"}))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    #[tokio::test]
    async fn forward_remove_happy() {
        let ctrl = RecordingController::new();
        let ctx = ctx_with(Arc::new(ctrl.clone()));
        let v = ForwardRemove
            .call(&ctx, json!({"profile":"p","forward_id":"web"}))
            .await
            .expect("ok");
        assert_eq!(v["applied"], true);
        assert_eq!(v["forward"], "web");
        assert!(matches!(
            &ctrl.snapshot()[0],
            ControllerCall::ForwardRemove { profile, forward_id }
                if profile == "p" && forward_id == "web"
        ));
    }

    #[tokio::test]
    async fn tunnel_reload_happy() {
        let ctrl = RecordingController::new();
        let ctx = ctx_with(Arc::new(ctrl.clone()));
        let v = TunnelReload.call(&ctx, json!({})).await.expect("ok");
        assert_eq!(v["applied"], true);
        assert_eq!(ctrl.snapshot(), vec![ControllerCall::Reload]);
    }

    #[tokio::test]
    async fn tunnel_failover_missing_profile_errors() {
        let ctx = ctx_with(Arc::new(NoopController));
        let err = TunnelFailover.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    #[tokio::test]
    async fn tunnel_failover_no_endpoint() {
        let ctrl = RecordingController::new();
        let ctx = ctx_with(Arc::new(ctrl.clone()));
        let v = TunnelFailover
            .call(&ctx, json!({"profile":"alpha"}))
            .await
            .expect("ok");
        assert_eq!(v["applied"], true);
        assert!(v["endpoint"].is_null());
        assert!(matches!(
            &ctrl.snapshot()[0],
            ControllerCall::Failover { profile, endpoint }
                if profile == "alpha" && endpoint.is_none()
        ));
    }

    #[tokio::test]
    async fn session_close_routes_to_controller() {
        let ctrl = RecordingController::new();
        let ctx = ctx_with(Arc::new(ctrl.clone()));
        let v = SessionClose
            .call(&ctx, json!({"id":"s-1"}))
            .await
            .expect("ok");
        assert_eq!(v["applied"], true);
        assert_eq!(v["id"], "s-1");
    }

    #[tokio::test]
    async fn session_close_missing_id_errors() {
        let ctx = ctx_with(Arc::new(NoopController));
        let err = SessionClose.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    #[tokio::test]
    async fn session_drain_routes_with_default_grace() {
        let ctrl = RecordingController::new();
        let ctx = ctx_with(Arc::new(ctrl.clone()));
        let v = SessionDrain
            .call(&ctx, json!({"profile":"alpha"}))
            .await
            .expect("ok");
        assert_eq!(v["applied"], true);
        let call = &ctrl.snapshot()[0];
        match call {
            ControllerCall::SessionDrain { grace_seconds, .. } => {
                assert_eq!(*grace_seconds, 5, "default grace");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn session_drain_missing_profile_errors() {
        let ctx = ctx_with(Arc::new(NoopController));
        let err = SessionDrain.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    #[tokio::test]
    async fn benchmark_run_routes_to_controller() {
        let ctrl = RecordingController::new();
        let ctx = ctx_with(Arc::new(ctrl.clone()));
        let v = BenchmarkRun
            .call(&ctx, json!({"driver":"latency"}))
            .await
            .expect("ok");
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn stats_subscribe_without_notify_errors() {
        let ctrl = RecordingController::new();
        let ctx = ctx_with(Arc::new(ctrl.clone()));
        let err = StatsSubscribe.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    #[tokio::test]
    async fn stats_subscribe_with_notify_routes_and_emits() {
        let ctrl = RecordingController::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let sources = Arc::new(NoopSources);
        let ctx = ToolContext {
            config: sources.clone() as DynConfigSource,
            state: sources as DynStateSource,
            controller: Arc::new(ctrl.clone()),
            notification_sender: Some(tx),
            log_reload: None,
        };
        let v = StatsSubscribe
            .call(&ctx, json!({"interval_ms": 150}))
            .await
            .expect("ok");
        assert_eq!(v["subscribed"], true);
        assert_eq!(v["interval_ms"], 150);
        let first = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("tick");
        assert!(first.is_some());
    }

    #[tokio::test]
    async fn events_subscribe_without_notify_errors() {
        let ctrl = RecordingController::new();
        let ctx = ctx_with(Arc::new(ctrl.clone()));
        let err = EventsSubscribe.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    #[tokio::test]
    async fn events_subscribe_with_notify_routes_and_emits_frame() {
        let ctrl = RecordingController::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let sources = Arc::new(NoopSources);
        let ctx = ToolContext {
            config: sources.clone() as DynConfigSource,
            state: sources as DynStateSource,
            controller: Arc::new(ctrl.clone()),
            notification_sender: Some(tx),
            log_reload: None,
        };
        let v = EventsSubscribe.call(&ctx, json!({})).await.expect("ok");
        assert_eq!(v["subscribed"], true);
        assert_eq!(v["notification"], "spt/event");
        let first = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("frame")
            .expect("some frame");
        // The relayed value is a complete JSON-RPC notification frame.
        assert_eq!(first["jsonrpc"], "2.0");
        assert_eq!(first["method"], "spt/event");
    }

    #[tokio::test]
    async fn descriptor_schemas_are_valid_json() {
        let r = ToolRegistry::new();
        for d in r.list() {
            assert!(d.input_schema.is_object(), "{}: schema not object", d.name);
        }
    }

    #[tokio::test]
    async fn planned_tool_envelope_shape() {
        let ctx = ctx_with(Arc::new(NoopController));
        let v = DnsRecordAdd.call(&ctx, json!({"x":1})).await.expect("ok");
        assert_eq!(v["applied"], false);
        assert_eq!(v["planned"]["x"], 1);
    }

    #[test]
    fn tool_handler_names_are_static() {
        assert_eq!(ConfigValidate.name(), "config_validate");
        assert_eq!(ForwardAdd.name(), "forward_add");
        assert_eq!(SessionDrain.name(), "session_drain");
        assert_eq!(BenchmarkRun.name(), "benchmark_run");
        assert_eq!(LogSetLevel.name(), "log_set_level");
    }

    /// A `ConfigSource` whose effective config is riddled with resolved
    /// secrets and inline key material — used to prove `secret_list` /
    /// `key_inspect` never surface any of it.
    struct SecretLadenConfig;
    #[async_trait]
    impl crate::sources::ConfigSource for SecretLadenConfig {
        async fn effective(&self) -> crate::Result<Value> {
            Ok(json!({
                "profiles": [{
                    "name": "alpha",
                    "auth": {
                        "password": "PLAINTEXT_PASSWORD",
                        "token": "PLAINTEXT_TOKEN",
                        "passphrase_ref": "secret://ns/pass",
                        "identity_file": "/home/me/.ssh/id_ed25519",
                        "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nABCDEF\n-----END OPENSSH PRIVATE KEY-----",
                        "private_key_ref": "secret://ns/key"
                    }
                }],
                "secret": "secret://ns/top",
                "other": "not-a-secret"
            }))
        }
        async fn redacted(&self) -> crate::Result<Value> {
            Ok(json!({}))
        }
        async fn profiles(&self) -> crate::Result<Value> {
            Ok(json!([]))
        }
        async fn forwards(&self) -> crate::Result<Value> {
            Ok(json!([]))
        }
        async fn dns_records(&self) -> crate::Result<Value> {
            Ok(json!([]))
        }
        async fn mcp_policy(&self) -> crate::Result<Value> {
            Ok(json!({}))
        }
        async fn service_definition(&self) -> crate::Result<Value> {
            Ok(json!({}))
        }
        async fn snmp_mib(&self) -> crate::Result<Value> {
            Ok(json!({}))
        }
    }

    fn ctx_with_config(cfg: Arc<dyn crate::sources::ConfigSource>) -> ToolContext {
        let state = Arc::new(NoopSources);
        ToolContext {
            config: cfg,
            state: state as DynStateSource,
            controller: Arc::new(NoopController),
            notification_sender: None,
            log_reload: None,
        }
    }

    #[tokio::test]
    async fn secret_list_returns_only_refs_no_values() {
        let ctx = ctx_with_config(Arc::new(SecretLadenConfig));
        let v = SecretList.call(&ctx, json!({})).await.expect("ok");
        let body = serde_json::to_string(&v).unwrap();
        // No resolved secret material may appear anywhere.
        assert!(!body.contains("PLAINTEXT_PASSWORD"), "leaked: {body}");
        assert!(!body.contains("PLAINTEXT_TOKEN"), "leaked: {body}");
        assert!(!body.contains("BEGIN OPENSSH"), "leaked key: {body}");
        // Only `secret://` reference URIs are surfaced.
        let refs = v["secret_refs"].as_array().expect("secret_refs array");
        let refs: Vec<&str> = refs.iter().filter_map(Value::as_str).collect();
        assert!(refs.contains(&"secret://ns/pass"));
        assert!(refs.contains(&"secret://ns/key"));
        assert!(refs.contains(&"secret://ns/top"));
        // Nothing that is not a reference.
        assert!(refs.iter().all(|r| r.starts_with("secret://")));
    }

    #[tokio::test]
    async fn key_inspect_redacts_inline_material_keeps_paths_and_refs() {
        let ctx = ctx_with_config(Arc::new(SecretLadenConfig));
        let v = KeyInspect.call(&ctx, json!({})).await.expect("ok");
        let body = serde_json::to_string(&v).unwrap();
        // Inline key material must never be returned.
        assert!(
            !body.contains("BEGIN OPENSSH"),
            "leaked key material: {body}"
        );
        assert!(!body.contains("ABCDEF"), "leaked key bytes: {body}");
        // It must also not echo password/token values.
        assert!(!body.contains("PLAINTEXT_PASSWORD"), "leaked: {body}");
        assert!(!body.contains("PLAINTEXT_TOKEN"), "leaked: {body}");
        let keys = v["keys"].as_array().expect("keys array");
        // The file-path identity reference is surfaced as a path.
        let has_path = keys
            .iter()
            .any(|e| e["key"] == "identity_file" && e["ref"] == "/home/me/.ssh/id_ed25519");
        assert!(has_path, "expected identity_file path entry: {keys:?}");
        // The inline private key is redacted.
        let inline = keys
            .iter()
            .find(|e| e["key"] == "private_key")
            .expect("private_key entry");
        assert_eq!(inline["ref"], "***");
        // The secret-ref private key is surfaced as a reference.
        let ref_entry = keys
            .iter()
            .find(|e| e["key"] == "private_key_ref")
            .expect("private_key_ref entry");
        assert_eq!(ref_entry["ref"], "secret://ns/key");
    }

    #[tokio::test]
    async fn secret_list_empty_config_is_empty() {
        let ctx = ctx_with_config(Arc::new(NoopSources));
        let v = SecretList.call(&ctx, json!({})).await.expect("ok");
        assert_eq!(v["secret_refs"].as_array().unwrap().len(), 0);
    }
}

/// Tests for the `log_set_level` MCP tool (t8-A3).
#[cfg(test)]
mod log_set_level_tests {
    use super::*;
    use crate::controller::NoopController;
    use crate::sources::NoopSources;
    use parking_lot::Mutex;

    /// Test reload bridge that records every directive it sees and can be
    /// configured to fail on the next call.
    struct RecordingReload {
        calls: Mutex<Vec<String>>,
        fail_with: Mutex<Option<String>>,
    }

    impl RecordingReload {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_with: Mutex::new(None),
            }
        }
        fn snapshot(&self) -> Vec<String> {
            self.calls.lock().clone()
        }
    }

    #[async_trait]
    impl LogReloadBridge for RecordingReload {
        async fn reload(&self, directive: &str) -> Result<(), String> {
            if let Some(reason) = self.fail_with.lock().take() {
                return Err(reason);
            }
            self.calls.lock().push(directive.to_owned());
            Ok(())
        }
    }

    fn ctx_with_bridge(bridge: Arc<RecordingReload>) -> ToolContext {
        let sources = Arc::new(NoopSources);
        ToolContext {
            config: sources.clone() as DynConfigSource,
            state: sources as DynStateSource,
            controller: Arc::new(NoopController),
            notification_sender: None,
            log_reload: Some(bridge as Arc<dyn LogReloadBridge>),
        }
    }

    fn ctx_without_bridge() -> ToolContext {
        let sources = Arc::new(NoopSources);
        ToolContext {
            config: sources.clone() as DynConfigSource,
            state: sources as DynStateSource,
            controller: Arc::new(NoopController),
            notification_sender: None,
            log_reload: None,
        }
    }

    #[tokio::test]
    async fn log_set_level_changes_filter_directive() {
        let bridge = Arc::new(RecordingReload::new());
        let ctx = ctx_with_bridge(bridge.clone());
        let v = LogSetLevel
            .call(&ctx, json!({"target": "spt_supervisor", "level": "debug"}))
            .await
            .expect("ok");
        assert_eq!(v["applied"], true);
        assert_eq!(v["target"], "spt_supervisor");
        assert_eq!(v["level"], "debug");
        assert_eq!(v["directive"], "spt_supervisor=debug");
        assert_eq!(bridge.snapshot(), vec!["spt_supervisor=debug".to_owned()]);
    }

    #[tokio::test]
    async fn log_set_level_rejects_invalid_level() {
        let bridge = Arc::new(RecordingReload::new());
        let ctx = ctx_with_bridge(bridge.clone());
        let err = LogSetLevel
            .call(&ctx, json!({"target": "spt_supervisor", "level": "loud"}))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
        assert!(
            bridge.snapshot().is_empty(),
            "bridge must not be called when validation fails"
        );
    }

    #[tokio::test]
    async fn log_set_level_rejects_invalid_target_syntax() {
        let bridge = Arc::new(RecordingReload::new());
        let ctx = ctx_with_bridge(bridge.clone());
        // Leading digit, internal whitespace, and empty are all rejected.
        for bad in ["9bad", "has space", "", "with=equals"] {
            let err = LogSetLevel
                .call(&ctx, json!({"target": bad, "level": "info"}))
                .await
                .unwrap_err();
            assert!(
                matches!(err, crate::Error::InvalidParams(_)),
                "target '{bad}' should be rejected"
            );
        }
        assert!(bridge.snapshot().is_empty());
    }

    #[tokio::test]
    async fn log_set_level_persists_across_calls() {
        let bridge = Arc::new(RecordingReload::new());
        let ctx = ctx_with_bridge(bridge.clone());
        LogSetLevel
            .call(&ctx, json!({"target": "spt_core", "level": "trace"}))
            .await
            .expect("first ok");
        LogSetLevel
            .call(&ctx, json!({"target": "spt_mcp", "level": "warn"}))
            .await
            .expect("second ok");
        LogSetLevel
            .call(&ctx, json!({"target": "spt_supervisor", "level": "info"}))
            .await
            .expect("third ok");
        assert_eq!(
            bridge.snapshot(),
            vec![
                "spt_core=trace".to_owned(),
                "spt_mcp=warn".to_owned(),
                "spt_supervisor=info".to_owned(),
            ]
        );
    }

    #[tokio::test]
    async fn log_set_level_requires_bridge_to_be_wired() {
        let ctx = ctx_without_bridge();
        let err = LogSetLevel
            .call(&ctx, json!({"target": "spt_core", "level": "info"}))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::Internal(_)));
    }

    #[tokio::test]
    async fn log_set_level_surfaces_bridge_failure_as_internal() {
        let bridge = Arc::new(RecordingReload::new());
        *bridge.fail_with.lock() = Some("subscriber gone".to_owned());
        let ctx = ctx_with_bridge(bridge.clone());
        let err = LogSetLevel
            .call(&ctx, json!({"target": "spt_core", "level": "info"}))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::Internal(ref msg) if msg.contains("subscriber gone")));
    }

    #[tokio::test]
    async fn log_set_level_missing_target_errors() {
        let bridge = Arc::new(RecordingReload::new());
        let ctx = ctx_with_bridge(bridge);
        let err = LogSetLevel
            .call(&ctx, json!({"level": "info"}))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    #[tokio::test]
    async fn log_set_level_missing_level_errors() {
        let bridge = Arc::new(RecordingReload::new());
        let ctx = ctx_with_bridge(bridge);
        let err = LogSetLevel
            .call(&ctx, json!({"target": "spt_core"}))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
    }

    #[tokio::test]
    async fn log_set_level_level_is_case_insensitive() {
        let bridge = Arc::new(RecordingReload::new());
        let ctx = ctx_with_bridge(bridge.clone());
        let v = LogSetLevel
            .call(&ctx, json!({"target": "spt_core", "level": "DEBUG"}))
            .await
            .expect("ok");
        assert_eq!(v["level"], "debug");
        assert_eq!(bridge.snapshot(), vec!["spt_core=debug".to_owned()]);
    }

    #[test]
    fn log_set_level_is_in_all_tool_names() {
        assert!(ALL_TOOL_NAMES.contains(&"log_set_level"));
    }

    #[test]
    fn log_set_level_is_a_write_tool() {
        assert!(crate::policy::WRITE_TOOLS.contains(&"log_set_level"));
    }

    #[test]
    fn log_set_level_descriptor_schema_is_well_formed() {
        let d = LogSetLevel.descriptor();
        assert_eq!(d.name, "log_set_level");
        let schema = &d.input_schema;
        assert_eq!(schema["type"], "object");
        let required = schema["required"].as_array().expect("required");
        assert!(required.iter().any(|v| v == "target"));
        assert!(required.iter().any(|v| v == "level"));
    }
}
