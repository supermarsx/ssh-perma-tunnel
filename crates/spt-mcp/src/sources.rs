//! Data-source adapters used by read-only MCP resources and a few tools.
//!
//! `spt-mcp` does not import `spt-config`/`spt-state` directly so the crate
//! stays test-friendly and keeps the dependency graph shallow. The binary
//! supplies adapters that delegate to those crates' public APIs.
//!
//! Every method returns a `serde_json::Value`. Resource handlers apply the
//! redaction pass before returning to the client; sources are encouraged but
//! not required to redact too — the central pass in [`crate::policy::Policy`]
//! is the authoritative defense.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;

/// Read-only access to configuration: effective config, redacted config,
/// profiles, forwards, DNS records, the MCP policy, the rendered service
/// definition, and the SNMP MIB.
#[async_trait]
pub trait ConfigSource: Send + Sync + 'static {
    /// Effective (post-merge, post-validate) config as JSON.
    async fn effective(&self) -> crate::Result<Value>;
    /// Same config rendered with `--redacted`.
    async fn redacted(&self) -> crate::Result<Value>;
    /// Array of profile summaries.
    async fn profiles(&self) -> crate::Result<Value>;
    /// Array of forward summaries.
    async fn forwards(&self) -> crate::Result<Value>;
    /// Array of `[[dns.records]]`.
    async fn dns_records(&self) -> crate::Result<Value>;
    /// Current `[mcp]` policy as JSON.
    async fn mcp_policy(&self) -> crate::Result<Value>;
    /// Rendered service-unit / plist / Windows service definition.
    async fn service_definition(&self) -> crate::Result<Value>;
    /// Project SNMP MIB body (RFC-style).
    async fn snmp_mib(&self) -> crate::Result<Value>;
}

/// Read-only access to runtime state: the status snapshot, sessions, events,
/// logs, metrics, recent diagnostics, and recent benchmarks.
#[async_trait]
pub trait StateSource: Send + Sync + 'static {
    /// Status snapshot per spec §13.5.
    async fn status(&self) -> crate::Result<Value>;
    /// Per-profile + global stats summary.
    async fn stats_summary(&self) -> crate::Result<Value>;
    /// Currently open sessions.
    async fn sessions_current(&self) -> crate::Result<Value>;
    /// Tail of the recent events ring (post-redaction).
    async fn events_recent(&self) -> crate::Result<Value>;
    /// Tail of structured logs (post-redaction).
    async fn logs_recent(&self) -> crate::Result<Value>;
    /// Latest Prometheus exposition text.
    async fn metrics(&self) -> crate::Result<Value>;
    /// Most recent diagnostics bundle metadata.
    async fn diagnostics_recent(&self) -> crate::Result<Value>;
    /// Most recent benchmark result metadata.
    async fn benchmarks_recent(&self) -> crate::Result<Value>;
}

/// Convenience boxed aliases used by the server.
pub type DynConfigSource = Arc<dyn ConfigSource>;
/// Convenience boxed alias for [`StateSource`].
pub type DynStateSource = Arc<dyn StateSource>;

/// Default no-op sources that return empty objects/arrays. Used by tests and
/// embedding harnesses that only exercise the protocol layer.
#[derive(Debug, Default, Clone)]
pub struct NoopSources;

#[async_trait]
impl ConfigSource for NoopSources {
    async fn effective(&self) -> crate::Result<Value> {
        Ok(json!({}))
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
        Ok(json!({"enabled": false, "default_mode": "read_only"}))
    }
    async fn service_definition(&self) -> crate::Result<Value> {
        Ok(json!({"format": "none", "body": ""}))
    }
    async fn snmp_mib(&self) -> crate::Result<Value> {
        Ok(json!({"format": "smi", "body": ""}))
    }
}

#[async_trait]
impl StateSource for NoopSources {
    async fn status(&self) -> crate::Result<Value> {
        Ok(json!({"profiles": [], "forwards": [], "sessions": []}))
    }
    async fn stats_summary(&self) -> crate::Result<Value> {
        Ok(json!({}))
    }
    async fn sessions_current(&self) -> crate::Result<Value> {
        Ok(json!([]))
    }
    async fn events_recent(&self) -> crate::Result<Value> {
        Ok(json!([]))
    }
    async fn logs_recent(&self) -> crate::Result<Value> {
        Ok(json!([]))
    }
    async fn metrics(&self) -> crate::Result<Value> {
        Ok(json!({"format": "prometheus", "body": ""}))
    }
    async fn diagnostics_recent(&self) -> crate::Result<Value> {
        Ok(json!({}))
    }
    async fn benchmarks_recent(&self) -> crate::Result<Value> {
        Ok(json!({}))
    }
}
