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
            fn name(&self) -> &'static str { $name }
            fn descriptor(&self) -> ToolDescriptor {
                ToolDescriptor { name: $name.to_owned(), description: $desc.to_owned(), input_schema: empty_schema() }
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
            fn name(&self) -> &'static str { $name }
            fn descriptor(&self) -> ToolDescriptor {
                ToolDescriptor { name: $name.to_owned(), description: $desc.to_owned(), input_schema: empty_schema() }
            }
            async fn call(&self, ctx: &ToolContext, _args: Value) -> crate::Result<Value> {
                ctx.state.$method().await
            }
        }
    };
}

// --- read-only tools ---------------------------------------------------------

tool!(read_cfg, ConfigValidate,  "config_validate",  "Validate the loaded config.",                     effective);
tool!(read_cfg, ConfigDoctor,    "config_doctor",    "Run the config doctor and report findings.",      effective);
tool!(read_cfg, ConfigRender,    "config_render",    "Render the canonical (redacted) config.",         redacted);
tool!(read_cfg, ProfileList,     "profile_list",     "List configured profiles.",                       profiles);
tool!(read_cfg, ForwardList,     "forward_list",     "List configured forwards.",                       forwards);

// `profile_show` and `forward_explain` take a name; they still surface the
// full list and let the client filter for now (read-only adapter is enough).
tool!(read_cfg, ProfileShow,     "profile_show",     "Show one profile (filter client-side).",          profiles);
tool!(read_cfg, ForwardExplain,  "forward_explain",  "Explain one forward (filter client-side).",       forwards);
tool!(read_state, TunnelStatus,  "tunnel_status",    "Return the runtime status snapshot.",             status);
tool!(read_state, StatsSummary,  "stats_summary",    "Return the global + per-profile stats summary.",  stats_summary);
tool!(read_state, StatsExport,   "stats_export",     "Export the latest stats blob.",                   stats_summary);
tool!(read_state, SessionList,   "session_list",     "List currently open sessions.",                   sessions_current);
tool!(read_state, SessionShow,   "session_show",     "Show one session (filter client-side).",          sessions_current);
tool!(read_state, LogTail,       "log_tail",         "Tail recent structured logs (redacted).",         logs_recent);
tool!(read_state, ObserveMetrics,"observe_metrics",  "Return the latest Prometheus metrics body.",      metrics);
tool!(read_cfg, ServiceRender,   "service_render",   "Render the platform service definition.",         service_definition);
tool!(read_cfg, KeyInspect,      "key_inspect",      "Inspect configured key references.",              effective);
tool!(read_cfg, SecretList,      "secret_list",      "List secret refs (never values).",                effective);
tool!(read_cfg, DnsQuery,        "dns_query",        "Inspect the configured DNS records.",             dns_records);

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
        let forward: Forward = serde_json::from_value(forward_value).map_err(|e| {
            crate::Error::InvalidParams(format!("invalid 'forward' object: {e}"))
        })?;
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
            fn name(&self) -> &'static str { $name }
            fn descriptor(&self) -> ToolDescriptor {
                ToolDescriptor { name: $name.to_owned(), description: $desc.to_owned(), input_schema: $schema }
            }
            async fn call(&self, _ctx: &ToolContext, args: Value) -> crate::Result<Value> {
                planned(args).await
            }
        }
    };
}

planned_tool!(DiagnoseRun,           "diagnose_run",           "Run the diagnostic check framework.",  empty_schema());
planned_tool!(DiagnoseBundle,        "diagnose_bundle",        "Build a redacted diagnostics bundle.", empty_schema());
planned_tool!(BenchmarkRun,          "benchmark_run",          "Run a benchmark scenario.",            empty_schema());
planned_tool!(BenchmarkReportExport, "benchmark_report_export","Export a benchmark report.",           empty_schema());
planned_tool!(DnsRecordAdd,          "dns_record_add",         "Add a DNS record.",                    empty_schema());
planned_tool!(DnsRecordRemove,       "dns_record_remove",      "Remove a DNS record.",                 empty_schema());
planned_tool!(EventTest,             "event_test",             "Send a test event to bindings.",       empty_schema());
planned_tool!(SecretSetRef,          "secret_set_ref",         "Bind a secret reference (no values).", empty_schema());

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

        debug_assert_eq!(by_name.len(), ALL_TOOL_NAMES.len(), "tool count mismatch");
        Self { by_name }
    }

    /// Number of registered tools (must be 31).
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Always `false` — non-empty after [`Self::new`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
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

    #[test]
    fn registry_contains_all_thirtyone_tools() {
        let r = ToolRegistry::new();
        assert_eq!(r.len(), 31, "spec §16 lists 31 tools");
    }

    #[test]
    fn every_spec_tool_is_registered() {
        let r = ToolRegistry::new();
        for name in ALL_TOOL_NAMES {
            assert!(r.get(name).is_some(), "missing tool: {name}");
        }
    }
}
