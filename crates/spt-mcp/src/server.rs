//! The MCP server entry point.
//!
//! [`McpServer`] wires together:
//!
//! - the resource and tool registries,
//! - the [`crate::policy::Policy`] gate,
//! - the [`crate::audit::McpAuditSink`] sink,
//! - the [`crate::controller::Controller`] runtime adapter,
//! - the [`crate::sources::ConfigSource`] / [`crate::sources::StateSource`] adapters,
//! - the chosen [`crate::transport::Transport`] (stdio or loopback TCP).
//!
//! `spt-bin` constructs an `McpServer`, then calls [`McpServer::run`] which
//! drives the transport loop until the transport closes.
//!
//! # The audit invariant
//!
//! Every successful tool call emits exactly one audit event. Policy denials
//! also emit one event with `ok = false`. Resource reads do not emit events;
//! they are read-only by construction and tracked separately by `tracing`.
//!
//! # Concurrency
//!
//! The server's mutable state lives behind an [`Arc`] so the loopback
//! transport can spawn one task per accepted connection. The stdio transport
//! is single-connection.

use crate::audit::{AuditEvent, DynAuditSink, NoopAuditSink};
use crate::controller::{DynController, NoopController};
use crate::policy::{McpPolicy, Policy};
use crate::protocol::{Id, Request, Response};
use crate::resources::ResourceRegistry;
use crate::sources::{DynConfigSource, DynStateSource, NoopSources};
use crate::tools::{ToolContext, ToolRegistry};
use crate::transport::{stdio::StdioTransport, Transport, TransportKind};
use serde_json::{json, Value};
use std::sync::Arc;

/// Capabilities advertised in the `initialize` response.
///
/// The values intentionally describe the subset implemented in this crate.
#[derive(Debug, Clone)]
pub struct ServerCapabilities {
    /// Server name reported in `initialize`.
    pub name: String,
    /// Semver string reported in `initialize`.
    pub version: String,
    /// Protocol revision string reported in `initialize`.
    pub protocol_version: String,
}

impl Default for ServerCapabilities {
    fn default() -> Self {
        Self {
            name: "spt-mcp".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: "2024-11-05".to_owned(),
        }
    }
}

/// Shared state of an MCP server.
///
/// All transports hand requests to an `Arc<McpServerInner>`. This allows the
/// loopback transport to spawn one connection task per accepted peer while
/// stdio runs the same dispatch on a single task.
pub struct McpServerInner {
    capabilities: ServerCapabilities,
    policy: Policy,
    audit: DynAuditSink,
    controller: DynController,
    config: DynConfigSource,
    state: DynStateSource,
    resources: Arc<ResourceRegistry>,
    tools: Arc<ToolRegistry>,
    /// Optional bearer token. When `Some`, `initialize` requires a matching
    /// `params.token` string. Per-connection `authenticated` flag is enforced
    /// by the transport runner.
    auth_token: Option<String>,
}

impl McpServerInner {
    /// Capabilities (advertised to clients during `initialize`).
    #[must_use]
    pub fn capabilities(&self) -> &ServerCapabilities {
        &self.capabilities
    }

    /// Dispatch a single JSON-RPC request to a result. Notification handling
    /// is the transport's responsibility; this method is only called for
    /// request frames.
    pub async fn dispatch(&self, req: Request) -> Response {
        self.dispatch_with_notify(req, None).await
    }

    /// Dispatch with an optional per-connection notification sender. The
    /// loopback transport supplies one so streaming tools work.
    pub async fn dispatch_with_notify(
        &self,
        req: Request,
        notify: Option<tokio::sync::mpsc::Sender<Value>>,
    ) -> Response {
        let id = req.id.clone().unwrap_or(Id::Null);
        let res = if req.method == "tools/call" {
            self.call_tool_with_notify(req.params, notify).await
        } else {
            self.handle_request(req).await
        };
        match res {
            Ok(value) => Response::ok(id, value),
            Err(e) => {
                let code = e.rpc_code();
                Response::err(id, code, e.to_string())
            }
        }
    }

    /// Log a notification frame. Returns nothing — JSON-RPC forbids responses
    /// to notifications.
    #[allow(clippy::unused_self)]
    pub fn note(&self, req: &Request) {
        tracing::debug!(method = %req.method, "received notification");
    }

    async fn handle_request(&self, req: Request) -> crate::Result<Value> {
        match req.method.as_str() {
            "initialize" => {
                self.verify_init_token(req.params.as_ref())?;
                Ok(self.initialize_result())
            }
            "resources/list" => Ok(self.list_resources()),
            "resources/read" => self.read_resource(req.params).await,
            "tools/list" => Ok(self.list_tools()),
            "tools/call" => self.call_tool(req.params).await,
            "ping" => Ok(json!({"pong": true})),
            other => Err(crate::Error::MethodNotFound(other.to_owned())),
        }
    }

    /// Verify the optional bearer token. When `auth_token` is `None` this
    /// is a no-op; when `Some`, `params.token` must match exactly.
    fn verify_init_token(&self, params: Option<&Value>) -> crate::Result<()> {
        let Some(expected) = &self.auth_token else {
            return Ok(());
        };
        let supplied = params
            .and_then(|p| p.get("token"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                crate::Error::PolicyDenied(
                    "initialize requires `params.token` for this MCP listener".to_owned(),
                )
            })?;
        if supplied == expected {
            Ok(())
        } else {
            Err(crate::Error::PolicyDenied(
                "initialize token mismatch".to_owned(),
            ))
        }
    }

    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": self.capabilities.protocol_version,
            "serverInfo": {
                "name": self.capabilities.name,
                "version": self.capabilities.version,
            },
            "capabilities": {
                "resources": {"listChanged": false},
                "tools": {"listChanged": false},
                "logging": {},
            }
        })
    }

    fn list_resources(&self) -> Value {
        json!({"resources": self.resources.list()})
    }

    async fn read_resource(&self, params: Option<Value>) -> crate::Result<Value> {
        let uri = params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
            .ok_or_else(|| crate::Error::InvalidParams("missing string field 'uri'".to_owned()))?;
        let handler = self
            .resources
            .get(uri)
            .ok_or_else(|| crate::Error::ResourceNotFound(uri.to_owned()))?;
        let raw = handler.read(&self.config, &self.state).await?;
        let redacted = self.policy.redact(raw);
        Ok(json!({
            "contents": [{
                "uri": uri,
                "mimeType": handler.descriptor().mime_type,
                "text": serde_json::to_string(&redacted)?,
            }]
        }))
    }

    fn list_tools(&self) -> Value {
        json!({"tools": self.tools.list()})
    }

    async fn call_tool(&self, params: Option<Value>) -> crate::Result<Value> {
        let params = params.unwrap_or(Value::Null);
        let name = params.get("name").and_then(Value::as_str).ok_or_else(|| {
            crate::Error::InvalidParams("missing string field 'name'".to_owned())
        })?;
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let client_id = params
            .get("clientId")
            .and_then(Value::as_str)
            .map(str::to_owned);

        let result = self.dispatch_tool(name, arguments.clone()).await;
        let (ok, error_text) = match &result {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };
        let event = AuditEvent {
            tool: name.to_owned(),
            arguments: self.policy.redact(arguments),
            ok,
            client_id,
            error: error_text,
            timestamp_ms: now_ms(),
        };
        self.audit.record(event).await;

        let payload = result?;
        let redacted = self.policy.redact(payload);
        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string(&redacted)?,
            }],
            "isError": false,
        }))
    }

    async fn dispatch_tool(&self, name: &str, arguments: Value) -> crate::Result<Value> {
        self.dispatch_tool_with_notify(name, arguments, None).await
    }

    /// Dispatch a tool with an optional per-connection notification sender.
    /// Streaming tools (e.g. `stats_subscribe`) consult the sender; for
    /// non-streaming transports `notify` is `None`.
    pub async fn dispatch_tool_with_notify(
        &self,
        name: &str,
        arguments: Value,
        notify: Option<tokio::sync::mpsc::Sender<Value>>,
    ) -> crate::Result<Value> {
        self.policy.ensure_enabled()?;
        self.policy.ensure_write_allowed(name)?;
        let handler = self
            .tools
            .get(name)
            .ok_or_else(|| crate::Error::ToolNotFound(name.to_owned()))?;
        let ctx = ToolContext {
            config: self.config.clone(),
            state: self.state.clone(),
            controller: self.controller.clone(),
            notification_sender: notify,
        };
        handler.call(&ctx, arguments).await
    }

    /// Public: full `tools/call` path with optional notification sender.
    /// Used by the loopback transport to expose streaming tools.
    pub async fn call_tool_with_notify(
        &self,
        params: Option<Value>,
        notify: Option<tokio::sync::mpsc::Sender<Value>>,
    ) -> crate::Result<Value> {
        let params = params.unwrap_or(Value::Null);
        let name = params.get("name").and_then(Value::as_str).ok_or_else(|| {
            crate::Error::InvalidParams("missing string field 'name'".to_owned())
        })?;
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let client_id = params
            .get("clientId")
            .and_then(Value::as_str)
            .map(str::to_owned);

        let result = self
            .dispatch_tool_with_notify(name, arguments.clone(), notify)
            .await;
        let (ok, error_text) = match &result {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };
        let event = AuditEvent {
            tool: name.to_owned(),
            arguments: self.policy.redact(arguments),
            ok,
            client_id,
            error: error_text,
            timestamp_ms: now_ms(),
        };
        self.audit.record(event).await;

        let payload = result?;
        let redacted = self.policy.redact(payload);
        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string(&redacted)?,
            }],
            "isError": false,
        }))
    }

    /// Optional bearer token. When `Some`, the `initialize` request must
    /// carry a matching `params.token` string. Set via [`McpServer::with_auth_token`].
    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }
}

/// MCP server handle. Built once per `spt mcp serve` invocation.
pub struct McpServer {
    inner: Arc<McpServerInner>,
}

impl McpServer {
    /// Build a server with the given policy and adapter set.
    #[must_use]
    pub fn new(
        policy: Policy,
        audit: DynAuditSink,
        controller: DynController,
        config: DynConfigSource,
        state: DynStateSource,
    ) -> Self {
        Self {
            inner: Arc::new(McpServerInner {
                capabilities: ServerCapabilities::default(),
                policy,
                audit,
                controller,
                config,
                state,
                resources: Arc::new(ResourceRegistry::new()),
                tools: Arc::new(ToolRegistry::new()),
                auth_token: None,
            }),
        }
    }

    /// Require `initialize` to carry `params.token` matching the supplied
    /// value. The token is **per-process** — generated by `tunnel run` and
    /// written to `<state_dir>/mcp-listen.json` for the CLI to read.
    /// Connections that omit or mis-match the token are dropped with a
    /// `PolicyDenied` after `initialize`.
    #[must_use]
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        let inner = match Arc::try_unwrap(self.inner) {
            Ok(mut i) => {
                i.auth_token = Some(token.into());
                i
            }
            Err(arc) => McpServerInner {
                capabilities: arc.capabilities.clone(),
                policy: arc.policy.clone(),
                audit: arc.audit.clone(),
                controller: arc.controller.clone(),
                config: arc.config.clone(),
                state: arc.state.clone(),
                resources: arc.resources.clone(),
                tools: arc.tools.clone(),
                auth_token: Some(token.into()),
            },
        };
        self.inner = Arc::new(inner);
        self
    }

    /// Build a server with all-noop dependencies. Useful for tests and
    /// initial wiring.
    #[must_use]
    pub fn new_noop(policy: McpPolicy) -> Self {
        let sources = Arc::new(NoopSources);
        Self::new(
            Policy::new(policy),
            Arc::new(NoopAuditSink),
            Arc::new(NoopController),
            sources.clone() as DynConfigSource,
            sources as DynStateSource,
        )
    }

    /// Override advertised capabilities (kept).
    #[must_use]
    pub fn with_capabilities(mut self, caps: ServerCapabilities) -> Self {
        // We hold the only Arc here in the typical builder flow; if not, we
        // copy-on-write via `Arc::make_mut` … but `McpServerInner` is not
        // `Clone`. Instead, deconstruct via `Arc::try_unwrap` and rebuild.
        let inner = match Arc::try_unwrap(self.inner) {
            Ok(mut i) => {
                i.capabilities = caps;
                i
            }
            Err(arc) => McpServerInner {
                capabilities: caps,
                policy: arc.policy.clone(),
                audit: arc.audit.clone(),
                controller: arc.controller.clone(),
                config: arc.config.clone(),
                state: arc.state.clone(),
                resources: arc.resources.clone(),
                tools: arc.tools.clone(),
                auth_token: arc.auth_token.clone(),
            },
        };
        self.inner = Arc::new(inner);
        self
    }

    /// Server capabilities (advertised to clients during `initialize`).
    #[must_use]
    pub fn capabilities(&self) -> &ServerCapabilities {
        &self.inner.capabilities
    }

    /// Shared inner handle. Useful when wiring custom transports.
    #[must_use]
    pub fn inner(&self) -> Arc<McpServerInner> {
        self.inner.clone()
    }

    /// Drive the chosen transport until it closes.
    ///
    /// `transport` selects the concrete I/O strategy; the dispatch logic is
    /// transport-agnostic and lives on [`McpServerInner`].
    ///
    /// The server **does not** check `policy.enabled` here — that gate is
    /// the binary's responsibility. Inside dispatch we still refuse
    /// `tools/call` on disabled policies, so this is belt-and-braces.
    pub async fn run<T: Transport>(self, transport: T) -> crate::Result<()> {
        transport.serve(self.inner).await
    }

    /// Convenience: drive the stdio transport.
    pub async fn run_stdio(self) -> crate::Result<()> {
        self.run(StdioTransport::new()).await
    }

    /// Convenience: pick a transport from a [`TransportKind`] discriminant.
    /// Loopback callers should use [`crate::transport::loopback::LoopbackTransport`]
    /// directly to supply a bind address.
    pub async fn run_kind(self, kind: TransportKind) -> crate::Result<()> {
        match kind {
            TransportKind::Stdio => self.run_stdio().await,
            TransportKind::Loopback => Err(crate::Error::InvalidParams(
                "loopback transport requires an explicit bind address".to_owned(),
            )),
        }
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::MockAuditSink;
    use crate::controller::testing::{ControllerCall, RecordingController};
    use crate::policy::McpPolicy;
    use serde_json::json;

    fn server_with(policy: McpPolicy, audit: MockAuditSink) -> McpServer {
        let sources = Arc::new(NoopSources);
        McpServer::new(
            Policy::new(policy),
            Arc::new(audit),
            Arc::new(NoopController),
            sources.clone() as DynConfigSource,
            sources as DynStateSource,
        )
    }

    fn server_with_controller(
        policy: McpPolicy,
        audit: MockAuditSink,
        ctrl: RecordingController,
    ) -> McpServer {
        let sources = Arc::new(NoopSources);
        McpServer::new(
            Policy::new(policy),
            Arc::new(audit),
            Arc::new(ctrl),
            sources.clone() as DynConfigSource,
            sources as DynStateSource,
        )
    }

    fn write_enabled_policy() -> McpPolicy {
        McpPolicy {
            enabled: true,
            allow_write_tools: vec![
                "tunnel_reload".to_owned(),
                "tunnel_failover".to_owned(),
                "forward_add".to_owned(),
                "forward_remove".to_owned(),
            ],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn initialize_returns_capabilities() {
        let s = server_with(McpPolicy::default(), MockAuditSink::new());
        let v = s.inner.initialize_result();
        assert_eq!(v["protocolVersion"], "2024-11-05");
        assert_eq!(v["serverInfo"]["name"], "spt-mcp");
    }

    #[tokio::test]
    async fn resources_list_returns_sixteen() {
        let s = server_with(McpPolicy::default(), MockAuditSink::new());
        let v = s.inner.list_resources();
        assert_eq!(v["resources"].as_array().unwrap().len(), 16);
    }

    #[tokio::test]
    async fn tools_list_returns_all_tools() {
        let s = server_with(McpPolicy::default(), MockAuditSink::new());
        let v = s.inner.list_tools();
        assert_eq!(
            v["tools"].as_array().unwrap().len(),
            crate::tools::ALL_TOOL_NAMES.len()
        );
    }

    #[tokio::test]
    async fn read_resource_returns_well_formed_envelope() {
        let s = server_with(McpPolicy::default(), MockAuditSink::new());
        let v = s
            .inner
            .read_resource(Some(json!({"uri": "spt://status"})))
            .await
            .expect("read");
        let arr = v["contents"].as_array().expect("contents array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["uri"], "spt://status");
        assert_eq!(arr[0]["mimeType"], "application/json");
        let body: Value = serde_json::from_str(arr[0]["text"].as_str().unwrap()).unwrap();
        assert!(body.is_object());
    }

    #[tokio::test]
    async fn read_unknown_resource_errors() {
        let s = server_with(McpPolicy::default(), MockAuditSink::new());
        let err = s
            .inner
            .read_resource(Some(json!({"uri": "spt://nope"})))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::ResourceNotFound(_)));
    }

    #[tokio::test]
    async fn write_tool_denied_when_not_in_allow_list() {
        let policy = McpPolicy {
            enabled: true,
            ..Default::default()
        };
        let audit = MockAuditSink::new();
        let s = server_with(policy, audit.clone());
        let err = s
            .inner
            .call_tool(Some(json!({
                "name": "forward_add",
                "arguments": {"profile": "p", "forward": {"name":"x","type":"local","transport":"tcp"}}
            })))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::PolicyDenied(_)));
        let events = audit.snapshot();
        assert_eq!(events.len(), 1);
        assert!(!events[0].ok);
        assert_eq!(events[0].tool, "forward_add");
    }

    #[tokio::test]
    async fn read_tool_emits_one_audit_event() {
        let policy = McpPolicy {
            enabled: true,
            ..Default::default()
        };
        let audit = MockAuditSink::new();
        let s = server_with(policy, audit.clone());
        let _ = s
            .inner
            .call_tool(Some(json!({"name": "tunnel_status", "arguments": {}})))
            .await
            .expect("ok");
        let events = audit.snapshot();
        assert_eq!(events.len(), 1);
        assert!(events[0].ok);
        assert_eq!(events[0].tool, "tunnel_status");
    }

    #[tokio::test]
    async fn disabled_policy_blocks_tool_calls() {
        let s = server_with(McpPolicy::default(), MockAuditSink::new());
        let err = s
            .inner
            .call_tool(Some(json!({"name": "tunnel_status", "arguments": {}})))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::Disabled));
    }

    #[tokio::test]
    async fn unknown_tool_errors() {
        let policy = McpPolicy {
            enabled: true,
            ..Default::default()
        };
        let s = server_with(policy, MockAuditSink::new());
        let err = s
            .inner
            .call_tool(Some(json!({"name": "nope_nope"})))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::ToolNotFound(_)));
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let s = server_with(McpPolicy::default(), MockAuditSink::new());
        let err = s
            .inner
            .handle_request(Request {
                jsonrpc: "2.0".to_owned(),
                id: Some(Id::Num(1)),
                method: "nope/nope".to_owned(),
                params: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::MethodNotFound(_)));
    }

    /// A read-only tool that pulls a config-shaped payload containing
    /// secrets has those secrets redacted in the response.
    #[tokio::test]
    async fn secrets_in_tool_result_are_redacted() {
        use async_trait::async_trait;

        struct LeakyConfig;
        #[async_trait]
        impl crate::sources::ConfigSource for LeakyConfig {
            async fn effective(&self) -> crate::Result<Value> {
                Ok(json!({"auth": {"password": "PLAINTEXT"}}))
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

        let policy = McpPolicy {
            enabled: true,
            ..Default::default()
        };
        let s = McpServer::new(
            Policy::new(policy),
            Arc::new(NoopAuditSink),
            Arc::new(NoopController),
            Arc::new(LeakyConfig) as DynConfigSource,
            Arc::new(NoopSources) as DynStateSource,
        );
        let v = s
            .inner
            .call_tool(Some(json!({"name": "config_validate", "arguments": {}})))
            .await
            .expect("ok");
        let text = v["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("PLAINTEXT"), "secret leaked: {text}");
        assert!(text.contains("***"));
    }

    // ----- Controller-mutating tools route through the controller. -----

    #[tokio::test]
    async fn tunnel_reload_invokes_controller() {
        let ctrl = RecordingController::new();
        let s = server_with_controller(write_enabled_policy(), MockAuditSink::new(), ctrl.clone());
        let _ = s
            .inner
            .call_tool(Some(json!({"name": "tunnel_reload", "arguments": {}})))
            .await
            .expect("ok");
        assert_eq!(ctrl.snapshot(), vec![ControllerCall::Reload]);
    }

    #[tokio::test]
    async fn tunnel_failover_passes_endpoint() {
        let ctrl = RecordingController::new();
        let s = server_with_controller(write_enabled_policy(), MockAuditSink::new(), ctrl.clone());
        let _ = s
            .inner
            .call_tool(Some(json!({
                "name": "tunnel_failover",
                "arguments": {"profile": "alpha", "endpoint": "edge-2"}
            })))
            .await
            .expect("ok");
        assert_eq!(
            ctrl.snapshot(),
            vec![ControllerCall::Failover {
                profile: "alpha".to_owned(),
                endpoint: Some("edge-2".to_owned()),
            }]
        );
    }

    #[tokio::test]
    async fn forward_add_deserializes_and_routes() {
        let ctrl = RecordingController::new();
        let s = server_with_controller(write_enabled_policy(), MockAuditSink::new(), ctrl.clone());
        let _ = s
            .inner
            .call_tool(Some(json!({
                "name": "forward_add",
                "arguments": {
                    "profile": "alpha",
                    "forward": {
                        "name": "web",
                        "type": "local",
                        "transport": "tcp",
                        "bind": "127.0.0.1:8080",
                        "target": "10.0.0.5:80"
                    }
                }
            })))
            .await
            .expect("ok");
        let calls = ctrl.snapshot();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            ControllerCall::ForwardAdd { profile, forward } => {
                assert_eq!(profile, "alpha");
                assert_eq!(forward.name, "web");
                assert_eq!(forward.transport, "tcp");
            }
            other => panic!("unexpected call: {other:?}"),
        }
    }

    #[tokio::test]
    async fn forward_add_invalid_payload_errors_invalid_params() {
        let ctrl = RecordingController::new();
        let s = server_with_controller(write_enabled_policy(), MockAuditSink::new(), ctrl.clone());
        // Missing required `name`/`type`/`transport` fields.
        let err = s
            .inner
            .call_tool(Some(json!({
                "name": "forward_add",
                "arguments": {"profile": "p", "forward": {}}
            })))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidParams(_)));
        assert!(ctrl.snapshot().is_empty());
    }

    #[tokio::test]
    async fn forward_remove_routes_to_controller() {
        let ctrl = RecordingController::new();
        let s = server_with_controller(write_enabled_policy(), MockAuditSink::new(), ctrl.clone());
        let _ = s
            .inner
            .call_tool(Some(json!({
                "name": "forward_remove",
                "arguments": {"profile": "alpha", "forward_id": "web"}
            })))
            .await
            .expect("ok");
        assert_eq!(
            ctrl.snapshot(),
            vec![ControllerCall::ForwardRemove {
                profile: "alpha".to_owned(),
                forward_id: "web".to_owned(),
            }]
        );
    }
}
