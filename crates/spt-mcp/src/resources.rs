//! The 16 read-only MCP resources from spec §16.
//!
//! Each entry maps a stable `spt://...` URI to a handler closure that returns
//! a JSON `Value`. The server applies [`crate::policy::Policy::redact`] over
//! the result before sending it back to the client, so handlers may read
//! straight from the source adapters without a manual redaction pass.

use crate::protocol::ResourceDescriptor;
use crate::sources::{DynConfigSource, DynStateSource};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Trait object returned by each resource. Kept tiny — one `read` method that
/// borrows the two source adapters and returns JSON.
#[async_trait]
pub trait ResourceHandler: Send + Sync + 'static {
    /// Resource URI.
    fn uri(&self) -> &'static str;
    /// Display name and description for `resources/list`.
    fn descriptor(&self) -> ResourceDescriptor;
    /// Read the resource body.
    async fn read(&self, cfg: &DynConfigSource, state: &DynStateSource) -> crate::Result<Value>;
}

macro_rules! simple_resource {
    ($vis:vis $name:ident, $uri:literal, $display:literal, $desc:literal, $kind:ident, $method:ident) => {
        $vis struct $name;

        #[async_trait::async_trait]
        impl ResourceHandler for $name {
            fn uri(&self) -> &'static str { $uri }

            fn descriptor(&self) -> ResourceDescriptor {
                ResourceDescriptor {
                    uri: $uri.to_owned(),
                    name: $display.to_owned(),
                    description: $desc.to_owned(),
                    mime_type: "application/json".to_owned(),
                }
            }

            async fn read(
                &self,
                cfg: &DynConfigSource,
                state: &DynStateSource,
            ) -> crate::Result<Value> {
                let _ = (cfg, state);
                simple_resource!(@dispatch self, cfg, state, $kind, $method)
            }
        }
    };
    (@dispatch $self:ident, $cfg:ident, $state:ident, cfg, $method:ident) => {
        $cfg.$method().await
    };
    (@dispatch $self:ident, $cfg:ident, $state:ident, state, $method:ident) => {
        $state.$method().await
    };
}

simple_resource!(
    pub ConfigEffective, "spt://config/effective",
    "Effective config", "Effective merged config (redaction applied).",
    cfg, effective
);
simple_resource!(
    pub ConfigRedacted, "spt://config/redacted",
    "Redacted config", "Config rendered with secrets replaced by references.",
    cfg, redacted
);
simple_resource!(
    pub Profiles, "spt://profiles",
    "Profiles", "Array of profile summaries.",
    cfg, profiles
);
simple_resource!(
    pub Forwards, "spt://forwards",
    "Forwards", "Array of forward summaries.",
    cfg, forwards
);
simple_resource!(
    pub Status, "spt://status",
    "Status snapshot", "Live status snapshot per spec §13.5.",
    state, status
);
simple_resource!(
    pub StatsSummary, "spt://stats/summary",
    "Stats summary", "Per-profile and global counters.",
    state, stats_summary
);
simple_resource!(
    pub SessionsCurrent, "spt://sessions/current",
    "Current sessions", "Currently open SSH sessions.",
    state, sessions_current
);
simple_resource!(
    pub EventsRecent, "spt://events/recent",
    "Recent events", "Recent events from the in-memory ring buffer.",
    state, events_recent
);
simple_resource!(
    pub LogsRecent, "spt://logs/recent",
    "Recent logs", "Tail of the structured log buffer (redacted).",
    state, logs_recent
);
simple_resource!(
    pub Metrics, "spt://metrics",
    "Prometheus metrics", "Latest Prometheus text-format exposition.",
    state, metrics
);
simple_resource!(
    pub DiagnosticsRecent, "spt://diagnostics/recent",
    "Recent diagnostics", "Most recent diagnostics bundle metadata.",
    state, diagnostics_recent
);
simple_resource!(
    pub BenchmarksRecent, "spt://benchmarks/recent",
    "Recent benchmarks", "Most recent benchmark report metadata.",
    state, benchmarks_recent
);
simple_resource!(
    pub DnsRecords, "spt://dns/records",
    "DNS records", "Configured `[[dns.records]]` entries.",
    cfg, dns_records
);
simple_resource!(
    pub SnmpMib, "spt://snmp/mib",
    "Project SNMP MIB", "Project enterprise MIB body.",
    cfg, snmp_mib
);
simple_resource!(
    pub ServiceDefinition, "spt://service/definition",
    "Service definition", "Rendered systemd unit / plist / SCM definition.",
    cfg, service_definition
);
simple_resource!(
    pub PolicyMcp, "spt://policy/mcp",
    "MCP policy", "Effective `[mcp]` policy (read-only view).",
    cfg, mcp_policy
);

/// Registry holding the 16 resource handlers, keyed by URI.
pub struct ResourceRegistry {
    by_uri: BTreeMap<&'static str, Arc<dyn ResourceHandler>>,
}

impl Default for ResourceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceRegistry {
    /// Build the standard registry of all 16 spec resources.
    #[must_use]
    pub fn new() -> Self {
        let mut by_uri: BTreeMap<&'static str, Arc<dyn ResourceHandler>> = BTreeMap::new();
        macro_rules! add {
            ($t:ident) => {{
                let h: Arc<dyn ResourceHandler> = Arc::new($t);
                by_uri.insert(h.uri(), h);
            }};
        }
        add!(ConfigEffective);
        add!(ConfigRedacted);
        add!(Profiles);
        add!(Forwards);
        add!(Status);
        add!(StatsSummary);
        add!(SessionsCurrent);
        add!(EventsRecent);
        add!(LogsRecent);
        add!(Metrics);
        add!(DiagnosticsRecent);
        add!(BenchmarksRecent);
        add!(DnsRecords);
        add!(SnmpMib);
        add!(ServiceDefinition);
        add!(PolicyMcp);
        Self { by_uri }
    }

    /// Number of registered resources (must be 16).
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_uri.len()
    }

    /// Always `false` — the registry is non-empty after [`Self::new`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_uri.is_empty()
    }

    /// List all descriptors in URI order for `resources/list`.
    #[must_use]
    pub fn list(&self) -> Vec<ResourceDescriptor> {
        self.by_uri.values().map(|h| h.descriptor()).collect()
    }

    /// Look up a handler by URI.
    #[must_use]
    pub fn get(&self, uri: &str) -> Option<Arc<dyn ResourceHandler>> {
        self.by_uri.get(uri).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_all_sixteen_resources() {
        let r = ResourceRegistry::new();
        assert_eq!(r.len(), 16, "spec §16 mandates 16 resources");
    }

    #[test]
    fn every_resource_has_unique_uri() {
        let r = ResourceRegistry::new();
        let mut uris: Vec<_> = r.list().into_iter().map(|d| d.uri).collect();
        uris.sort();
        let dedup_len = {
            let mut dedup = uris.clone();
            dedup.dedup();
            dedup.len()
        };
        assert_eq!(uris.len(), dedup_len);
    }

    #[test]
    fn registry_is_not_empty_and_default_equals_new() {
        let r = ResourceRegistry::new();
        assert!(!r.is_empty());
        let d = ResourceRegistry::default();
        assert_eq!(r.len(), d.len());
    }

    #[test]
    fn registry_get_known_uri_returns_handler() {
        let r = ResourceRegistry::new();
        let h = r.get("spt://status").expect("status handler");
        assert_eq!(h.uri(), "spt://status");
        let d = h.descriptor();
        assert_eq!(d.uri, "spt://status");
        assert_eq!(d.mime_type, "application/json");
        assert!(!d.name.is_empty());
        assert!(!d.description.is_empty());
    }

    #[test]
    fn registry_get_unknown_uri_is_none() {
        let r = ResourceRegistry::new();
        assert!(r.get("spt://does-not-exist").is_none());
    }

    #[tokio::test]
    async fn handler_read_uses_correct_source() {
        use crate::sources::{DynConfigSource, DynStateSource, NoopSources};
        let cfg: DynConfigSource = Arc::new(NoopSources);
        let state: DynStateSource = Arc::new(NoopSources);
        let r = ResourceRegistry::new();
        let v = r
            .get("spt://status")
            .unwrap()
            .read(&cfg, &state)
            .await
            .expect("read");
        assert!(v["profiles"].is_array());

        let v = r
            .get("spt://profiles")
            .unwrap()
            .read(&cfg, &state)
            .await
            .expect("read");
        assert!(v.is_array());
    }

    #[test]
    fn list_descriptors_are_sorted_by_uri() {
        let r = ResourceRegistry::new();
        let uris: Vec<String> = r.list().into_iter().map(|d| d.uri).collect();
        let mut sorted = uris.clone();
        sorted.sort();
        assert_eq!(uris, sorted, "BTreeMap iteration is sorted");
    }
}
