//! Policy engine: the enable bit, the write-tool allow-list, and the redaction
//! pass that runs over every outbound JSON `Value`.
//!
//! Spec invariants enforced here (§16):
//!
//! - MCP is **disabled by default**. [`Policy::ensure_enabled`] is the gate.
//! - MCP is **read-only by default**. [`Policy::ensure_write_allowed`] checks
//!   that mutating tools appear in `allow_write_tools`.
//! - MCP **never returns plaintext secrets**. [`Policy::redact`] walks the JSON
//!   tree and replaces any value that looks like a resolved secret with the
//!   token `"***"`. `secret://ns/name` reference strings pass through.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// MCP policy as it appears in `[mcp]` in the user's config.
///
/// `spt-bin` parses this from the loaded config and hands it to the server.
/// All defaults match the spec's "fail-closed" posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct McpPolicy {
    /// Master enable. **Default `false`** per spec §16.
    pub enabled: bool,
    /// Names of tools that are allowed to mutate state. Any mutating tool not
    /// in this list returns a policy-denied error.
    pub allow_write_tools: Vec<String>,
    /// If `true`, attempting to read a config containing a resolved secret will
    /// **still** redact it. The flag exists for forward-compatibility (spec
    /// §16 allows future narrow flows) but currently has no relaxing effect.
    pub allow_secret_reveal: bool,
    /// `loopback`/`disabled` listen address such as `127.0.0.1:7421`. Empty by
    /// default — stdio only.
    pub listen: String,
    /// Whether to expose stdio transport. Default `true`.
    pub stdio: bool,
}

impl Default for McpPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_write_tools: Vec::new(),
            allow_secret_reveal: false,
            listen: String::new(),
            stdio: true,
        }
    }
}

/// The list of tool names whose handlers may mutate persistent state. Used by
/// [`Policy::ensure_write_allowed`] to gate the allow-list check.
///
/// Read-only tools (`*_list`, `*_show`, `*_validate`, etc.) are not included
/// because they need no allow-listing.
pub const WRITE_TOOLS: &[&str] = &[
    "profile_set",
    "forward_add",
    "forward_remove",
    "tunnel_reload",
    "tunnel_failover",
    "diagnose_run",
    "diagnose_bundle",
    "benchmark_run",
    "benchmark_report_export",
    "dns_record_add",
    "dns_record_remove",
    "event_test",
    "secret_set_ref",
    // Live-bridge tools (f-live-bridge):
    "session_close",
    "session_drain",
    "stats_subscribe",
];

/// Runtime policy wrapper that applies `enabled`, `allow_write_tools`, and
/// redaction over a [`McpPolicy`] snapshot.
#[derive(Debug, Clone)]
pub struct Policy {
    inner: McpPolicy,
}

impl Policy {
    /// Wraps a config-shaped [`McpPolicy`].
    #[must_use]
    pub fn new(inner: McpPolicy) -> Self {
        Self { inner }
    }

    /// Returns the underlying [`McpPolicy`].
    #[must_use]
    pub fn snapshot(&self) -> &McpPolicy {
        &self.inner
    }

    /// Errors with [`crate::Error::Disabled`] if MCP is not enabled.
    pub fn ensure_enabled(&self) -> crate::Result<()> {
        if self.inner.enabled {
            Ok(())
        } else {
            Err(crate::Error::Disabled)
        }
    }

    /// Errors with [`crate::Error::PolicyDenied`] if `tool` is a write tool
    /// and is not in `allow_write_tools`.
    pub fn ensure_write_allowed(&self, tool: &str) -> crate::Result<()> {
        if !WRITE_TOOLS.contains(&tool) {
            return Ok(());
        }
        if self.inner.allow_write_tools.iter().any(|t| t == tool) {
            Ok(())
        } else {
            Err(crate::Error::PolicyDenied(format!(
                "tool {tool} is not in allow_write_tools"
            )))
        }
    }

    /// Walk a JSON value and replace anything that looks like a resolved
    /// secret with the token `"***"`. Reference strings of the form
    /// `secret://ns/name` are preserved.
    ///
    /// The redactor inspects object keys: any key whose lowercase form
    /// contains one of the substrings in [`SENSITIVE_KEY_HINTS`] has its
    /// scalar value replaced unless that scalar is already a `secret://` URI.
    /// This is intentionally conservative — false positives are preferable to
    /// leaks per spec §16.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn redact(&self, value: Value) -> Value {
        redact_value(value, /* sensitive_parent: */ false)
    }
}

/// Object keys that mark their scalar value as sensitive.
pub const SENSITIVE_KEY_HINTS: &[&str] = &[
    "password",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth_key",
    "private_key",
    "privkey",
    "bearer",
    "credential",
];

fn key_is_sensitive(key: &str) -> bool {
    let lower = key.to_lowercase();
    // `secret_ref` and `secret://` URIs are intentionally NOT redacted —
    // they are references, not values.
    if lower == "secret_ref" || lower == "ref" {
        return false;
    }
    SENSITIVE_KEY_HINTS.iter().any(|hint| lower.contains(hint))
}

fn looks_like_secret_uri(s: &str) -> bool {
    s.starts_with("secret://")
}

fn redact_value(value: Value, sensitive_parent: bool) -> Value {
    match value {
        Value::String(s) if sensitive_parent && !looks_like_secret_uri(&s) => {
            Value::String("***".to_owned())
        }
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                let child_sensitive = key_is_sensitive(&k);
                out.insert(k, redact_value(v, child_sensitive));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .map(|v| redact_value(v, sensitive_parent))
                .collect(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_is_disabled() {
        let p = Policy::new(McpPolicy::default());
        assert!(p.ensure_enabled().is_err());
    }

    #[test]
    fn read_only_default_blocks_write_tools() {
        let p = Policy::new(McpPolicy {
            enabled: true,
            ..Default::default()
        });
        assert!(p.ensure_enabled().is_ok());
        assert!(p.ensure_write_allowed("forward_add").is_err());
        assert!(p.ensure_write_allowed("forward_list").is_ok());
    }

    #[test]
    fn allow_list_permits_named_tool() {
        let p = Policy::new(McpPolicy {
            enabled: true,
            allow_write_tools: vec!["forward_add".to_owned()],
            ..Default::default()
        });
        assert!(p.ensure_write_allowed("forward_add").is_ok());
        assert!(p.ensure_write_allowed("forward_remove").is_err());
    }

    #[test]
    fn redacts_password_fields() {
        let p = Policy::new(McpPolicy::default());
        let v = json!({
            "user": "alice",
            "password": "hunter2",
            "auth": { "bearer_token": "abc123", "ref": "secret://ns/foo" }
        });
        let r = p.redact(v);
        assert_eq!(r["user"], "alice");
        assert_eq!(r["password"], "***");
        assert_eq!(r["auth"]["bearer_token"], "***");
        assert_eq!(r["auth"]["ref"], "secret://ns/foo");
    }

    #[test]
    fn preserves_secret_uri_under_sensitive_key() {
        let p = Policy::new(McpPolicy::default());
        let v = json!({"password": "secret://ns/db"});
        let r = p.redact(v);
        assert_eq!(r["password"], "secret://ns/db");
    }
}
