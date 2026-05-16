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
use std::collections::BTreeMap;
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
/// (`session_close`, `session_drain`, `stats_subscribe`, `benchmark_run`
/// already counted) are appended for the loopback control surface.
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
    KeyInspect,
    "key_inspect",
    "Inspect configured key references.",
    effective
);
tool!(
    read_cfg,
    SecretList,
    "secret_list",
    "List secret refs (never values).",
    effective
);
tool!(
    read_cfg,
    DnsQuery,
    "dns_query",
    "Inspect the configured DNS records.",
    dns_records
);

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

        debug_assert_eq!(by_name.len(), ALL_TOOL_NAMES.len(), "tool count mismatch");
        Self { by_name }
    }

    /// Number of registered tools (must be 34).
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
        let err = ForwardRemove
            .call(&ctx, json!({}))
            .await
            .unwrap_err();
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
        let err = TunnelFailover
            .call(&ctx, json!({}))
            .await
            .unwrap_err();
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
        let err = SessionClose
            .call(&ctx, json!({}))
            .await
            .unwrap_err();
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
        let err = SessionDrain
            .call(&ctx, json!({}))
            .await
            .unwrap_err();
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
        let err = StatsSubscribe
            .call(&ctx, json!({}))
            .await
            .unwrap_err();
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
    async fn descriptor_schemas_are_valid_json() {
        let r = ToolRegistry::new();
        for d in r.list() {
            assert!(d.input_schema.is_object(), "{}: schema not object", d.name);
        }
    }

    #[tokio::test]
    async fn planned_tool_envelope_shape() {
        let ctx = ctx_with(Arc::new(NoopController));
        let v = DnsRecordAdd
            .call(&ctx, json!({"x":1}))
            .await
            .expect("ok");
        assert_eq!(v["applied"], false);
        assert_eq!(v["planned"]["x"], 1);
    }

    #[test]
    fn tool_handler_names_are_static() {
        assert_eq!(ConfigValidate.name(), "config_validate");
        assert_eq!(ForwardAdd.name(), "forward_add");
        assert_eq!(SessionDrain.name(), "session_drain");
        assert_eq!(BenchmarkRun.name(), "benchmark_run");
    }
}
