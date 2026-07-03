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

/// The default read/write posture of the MCP control surface (`[mcp].default_mode`).
///
/// This is the **baseline** write policy applied *before* the per-tool
/// `allow_write_tools` allow-list. It is deliberately fail-closed:
///
/// - [`McpMode::ReadOnly`] (the default, and the value used when the config
///   key is absent or unrecognised) keeps the strict posture — a mutating
///   tool is permitted only when it appears in `allow_write_tools`.
/// - [`McpMode::ReadWrite`] is an explicit operator opt-in that flips the
///   baseline: every mutating tool is permitted (the allow-list is then a
///   no-op superset). This is a documented widening the operator asked for,
///   never a silent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpMode {
    /// Mutating tools require an explicit `allow_write_tools` entry.
    ReadOnly,
    /// Mutating tools are permitted by default (operator opt-in).
    ReadWrite,
}

impl Default for McpMode {
    fn default() -> Self {
        Self::ReadOnly
    }
}

impl McpMode {
    /// Parse the config string form (`read_only` / `read_write`). Any other
    /// value — including `None`/unknown — maps fail-closed to
    /// [`McpMode::ReadOnly`].
    #[must_use]
    pub fn from_config_str(s: Option<&str>) -> Self {
        match s.map(str::trim) {
            Some("read_write") => Self::ReadWrite,
            _ => Self::ReadOnly,
        }
    }
}

/// SPKI-pin enforcement for the MCP TLS surface (`[mcp].pin_spki_sha256` /
/// `allow_self_signed` / `max_cert_chain_depth`).
///
/// The MCP control surface itself is loopback-only plain TCP, but when the
/// server or a client speaks TLS to a pinned peer these fields drive
/// fail-closed verification that mirrors `spt_trust::PinnedTlsConnector` /
/// the ssh3 pin enforcement:
///
/// - [`TlsPinPolicy::validate`] refuses a self-signed-allowed config that
///   carries no pins (a fully-unauthenticated posture), fail-closed;
/// - [`TlsPinPolicy::verify_spki`] rejects a presented certificate whose SPKI
///   SHA-256 digest is not in the pin set (pin mismatch → deny);
/// - [`TlsPinPolicy::verify_chain_depth`] enforces `max_cert_chain_depth`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsPinPolicy {
    /// SPKI SHA-256 pin set. Each entry is a `SHA256:<base64>` or hex digest.
    /// Empty means "no pinning configured" (defer to system-root trust).
    pub pin_spki_sha256: Vec<String>,
    /// Allow self-signed certificates. **Requires** a non-empty pin set — a
    /// self-signed-allowed peer with no pins is unauthenticated and refused.
    pub allow_self_signed: bool,
    /// Maximum certificate-chain depth (intermediates between leaf and anchor).
    /// `None` maps to the runtime default cap.
    pub max_cert_chain_depth: Option<u32>,
}

impl TlsPinPolicy {
    /// True when at least one pin is configured (pinning is active).
    #[must_use]
    pub fn is_pinning(&self) -> bool {
        self.pin_spki_sha256.iter().any(|p| !p.trim().is_empty())
    }

    /// Validate the pin configuration fail-closed. Mirrors
    /// `spt_trust::PinnedTlsConnector`'s refusal to build a fully
    /// unauthenticated client: `allow_self_signed` without any pin is a
    /// policy error, and a blank pin string is rejected so a typo cannot
    /// silently disable pinning.
    pub fn validate(&self) -> crate::Result<()> {
        if self.pin_spki_sha256.iter().any(|p| p.trim().is_empty()) {
            return Err(crate::Error::PolicyDenied(
                "mcp.pin_spki_sha256 contains a blank pin".to_owned(),
            ));
        }
        if self.allow_self_signed && !self.is_pinning() {
            return Err(crate::Error::PolicyDenied(
                "mcp.allow_self_signed requires a non-empty mcp.pin_spki_sha256 set \
                 (refusing an unauthenticated TLS posture)"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Verify a presented certificate's SPKI SHA-256 digest against the pin
    /// set. When no pins are configured this is a no-op (`Ok`) — system-root
    /// verification still applies elsewhere. When pins ARE configured a digest
    /// that matches none of them is rejected fail-closed (pin mismatch).
    ///
    /// `presented` is compared case-insensitively and tolerant of an optional
    /// `SHA256:` prefix on either side so hex/base64 forms interoperate with
    /// the operator's configured string.
    pub fn verify_spki(&self, presented: &str) -> crate::Result<()> {
        if !self.is_pinning() {
            return Ok(());
        }
        let want = normalize_pin(presented);
        if self
            .pin_spki_sha256
            .iter()
            .any(|p| normalize_pin(p) == want)
        {
            Ok(())
        } else {
            tracing::warn!(
                pins = self.pin_spki_sha256.len(),
                "MCP TLS pin mismatch — presented SPKI digest not in pin set; rejecting peer"
            );
            Err(crate::Error::PolicyDenied(
                "MCP TLS pin mismatch: presented certificate SPKI not in pin set".to_owned(),
            ))
        }
    }

    /// Enforce `max_cert_chain_depth` against an observed chain depth. `None`
    /// defers to the runtime default and always accepts here.
    pub fn verify_chain_depth(&self, depth: u32) -> crate::Result<()> {
        match self.max_cert_chain_depth {
            Some(cap) if depth > cap => {
                tracing::warn!(
                    depth,
                    cap,
                    "MCP TLS certificate chain exceeds max_cert_chain_depth; rejecting peer"
                );
                Err(crate::Error::PolicyDenied(format!(
                    "MCP TLS chain depth {depth} exceeds max_cert_chain_depth {cap}"
                )))
            }
            _ => Ok(()),
        }
    }
}

/// Normalize a pin/digest string for comparison: strip an optional `sha256:`
/// prefix and surrounding whitespace, and lowercase it.
fn normalize_pin(s: &str) -> String {
    let t = s.trim();
    let t = t
        .strip_prefix("SHA256:")
        .or_else(|| t.strip_prefix("sha256:"))
        .unwrap_or(t);
    t.trim().to_ascii_lowercase()
}

/// MCP policy as it appears in `[mcp]` in the user's config.
///
/// `spt-bin` parses this from the loaded config and hands it to the server.
/// All defaults match the spec's "fail-closed" posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct McpPolicy {
    /// Master enable. **Default `false`** per spec §16.
    pub enabled: bool,
    /// Baseline read/write posture (`[mcp].default_mode`). Applied *before*
    /// `allow_write_tools`; see [`McpMode`]. Fail-closed default: `ReadOnly`.
    pub default_mode: McpMode,
    /// Names of tools that are allowed to mutate state. Any mutating tool not
    /// in this list returns a policy-denied error (unless `default_mode` is
    /// [`McpMode::ReadWrite`]).
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
    /// TLS SPKI-pin enforcement for the MCP TLS surface. Fail-closed; see
    /// [`TlsPinPolicy`].
    pub tls_pins: TlsPinPolicy,
}

impl Default for McpPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            default_mode: McpMode::ReadOnly,
            allow_write_tools: Vec::new(),
            allow_secret_reveal: false,
            listen: String::new(),
            stdio: true,
            tls_pins: TlsPinPolicy::default(),
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
    "profile_stop",
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
    "events_subscribe",
    // Observability live-control (t8-A3): mutates process-wide tracing filter.
    "log_set_level",
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

    /// The baseline read/write posture of this policy (`[mcp].default_mode`).
    #[must_use]
    pub fn default_mode(&self) -> McpMode {
        self.inner.default_mode
    }

    /// Errors with [`crate::Error::PolicyDenied`] if `tool` is a write tool
    /// and the policy does not permit it.
    ///
    /// A mutating tool is permitted when either the baseline
    /// [`McpMode::ReadWrite`] is set (operator opt-in) or the tool appears in
    /// `allow_write_tools`. Denials are logged at WARN — a refused mutation is
    /// a security-relevant decision an operator must be able to see (the tool
    /// name is safe to log; no arguments/secrets are touched here).
    pub fn ensure_write_allowed(&self, tool: &str) -> crate::Result<()> {
        if !WRITE_TOOLS.contains(&tool) {
            return Ok(());
        }
        if self.inner.default_mode == McpMode::ReadWrite {
            return Ok(());
        }
        if self.inner.allow_write_tools.iter().any(|t| t == tool) {
            Ok(())
        } else {
            tracing::warn!(
                tool = %tool,
                default_mode = ?self.inner.default_mode,
                "MCP policy denied write tool: not in allow_write_tools and default_mode is read_only"
            );
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
        // A `secret://ns/name` reference is a reference, not a value — keep it
        // verbatim even under a sensitive key.
        Value::String(s) if sensitive_parent && looks_like_secret_uri(&s) => Value::String(s),
        // Under a sensitive key/parent, redact ANY scalar value — strings,
        // numbers, and bools all leak a secret if returned verbatim
        // (e.g. `{"token": 1234567}`). `null` carries nothing and is left
        // as-is via the `other` arm below.
        Value::String(_) | Value::Number(_) | Value::Bool(_) if sensitive_parent => {
            Value::String("***".to_owned())
        }
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                // Propagate the inherited sensitivity: once we are inside a
                // sensitive key, every nested value stays sensitive. Without
                // this, `{"password": {"plain": "hunter2"}}` would restart
                // sensitivity from the inner key and leak `hunter2` verbatim.
                let child_sensitive = key_is_sensitive(&k) || sensitive_parent;
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

/// Test-only WARN-counting `tracing::Subscriber` (dep-free — uses only the
/// `tracing` facade). Lets unit tests assert a security-relevant WARN was
/// emitted at a decision site without pulling in `tracing-subscriber`.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct WarnCounter(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(test)]
impl WarnCounter {
    pub(crate) fn count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
impl tracing::Subscriber for WarnCounter {
    fn enabled(&self, _md: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _a: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _s: &tracing::span::Id, _v: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _s: &tracing::span::Id, _f: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() == tracing::Level::WARN {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    fn enter(&self, _s: &tracing::span::Id) {}
    fn exit(&self, _s: &tracing::span::Id) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A denied write tool must be logged at WARN at the decision site
    /// (security-relevant). A permitted read tool logs nothing. Pre-fix
    /// `ensure_write_allowed` emitted no log, so this test fails against it.
    #[test]
    fn write_denial_logs_warn() {
        let counter = WarnCounter::default();
        let observer = counter.clone();
        tracing::subscriber::with_default(counter, || {
            let p = Policy::new(McpPolicy {
                enabled: true,
                ..Default::default()
            });
            assert!(p.ensure_write_allowed("forward_add").is_err());
            assert!(p.ensure_write_allowed("forward_list").is_ok());
        });
        assert_eq!(
            observer.count(),
            1,
            "exactly one WARN for the single denied write tool"
        );
    }

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

    /// `default_mode` is honored: the default (`read_only`) keeps the strict
    /// posture (identical to today), while an explicit `read_write` permits a
    /// mutating tool that is NOT in `allow_write_tools`. Pre-fix `McpPolicy`
    /// had no `default_mode`, so this behavior could not exist.
    #[test]
    fn default_mode_read_write_permits_writes_without_allow_list() {
        // read_only baseline (default): empty allow-list denies writes.
        let ro = Policy::new(McpPolicy {
            enabled: true,
            ..Default::default()
        });
        assert_eq!(ro.default_mode(), McpMode::ReadOnly);
        assert!(ro.ensure_write_allowed("forward_add").is_err());

        // read_write baseline: the SAME empty allow-list now permits writes.
        let rw = Policy::new(McpPolicy {
            enabled: true,
            default_mode: McpMode::ReadWrite,
            ..Default::default()
        });
        assert_eq!(rw.default_mode(), McpMode::ReadWrite);
        assert!(rw.ensure_write_allowed("forward_add").is_ok());
        assert!(rw.ensure_write_allowed("profile_stop").is_ok());
        // Read tools remain fine in both modes.
        assert!(rw.ensure_write_allowed("forward_list").is_ok());
    }

    #[test]
    fn mcp_mode_from_config_str_is_fail_closed() {
        assert_eq!(
            McpMode::from_config_str(Some("read_write")),
            McpMode::ReadWrite
        );
        assert_eq!(
            McpMode::from_config_str(Some("read_only")),
            McpMode::ReadOnly
        );
        assert_eq!(McpMode::from_config_str(Some("bogus")), McpMode::ReadOnly);
        assert_eq!(McpMode::from_config_str(None), McpMode::ReadOnly);
    }

    #[test]
    fn profile_stop_is_a_write_tool() {
        assert!(WRITE_TOOLS.contains(&"profile_stop"));
        let p = Policy::new(McpPolicy {
            enabled: true,
            ..Default::default()
        });
        // Not in an empty allow-list → denied fail-closed.
        assert!(p.ensure_write_allowed("profile_stop").is_err());
        let p = Policy::new(McpPolicy {
            enabled: true,
            allow_write_tools: vec!["profile_stop".to_owned()],
            ..Default::default()
        });
        assert!(p.ensure_write_allowed("profile_stop").is_ok());
    }

    #[test]
    fn tls_pin_validate_rejects_self_signed_without_pins() {
        let p = TlsPinPolicy {
            allow_self_signed: true,
            ..Default::default()
        };
        assert!(matches!(p.validate(), Err(crate::Error::PolicyDenied(_))));

        // With a pin present, self-signed is permitted to validate.
        let p = TlsPinPolicy {
            allow_self_signed: true,
            pin_spki_sha256: vec!["SHA256:abc123".to_owned()],
            ..Default::default()
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn tls_pin_validate_rejects_blank_pin() {
        let p = TlsPinPolicy {
            pin_spki_sha256: vec!["  ".to_owned()],
            ..Default::default()
        };
        assert!(matches!(p.validate(), Err(crate::Error::PolicyDenied(_))));
    }

    /// A presented SPKI that is not in the pin set is rejected fail-closed; a
    /// matching one (prefix/case-insensitive) is accepted. With no pins the
    /// verifier is a no-op.
    #[test]
    fn tls_pin_verify_spki_fail_closed_on_mismatch() {
        let p = TlsPinPolicy {
            pin_spki_sha256: vec!["SHA256:AbC123".to_owned()],
            ..Default::default()
        };
        // Mismatch → denied.
        assert!(matches!(
            p.verify_spki("sha256:deadbeef"),
            Err(crate::Error::PolicyDenied(_))
        ));
        // Match (case/prefix tolerant) → ok.
        assert!(p.verify_spki("abc123").is_ok());
        assert!(p.verify_spki("SHA256:abc123").is_ok());

        // No pins configured → no-op accept.
        let unpinned = TlsPinPolicy::default();
        assert!(unpinned.verify_spki("anything").is_ok());
    }

    #[test]
    fn tls_pin_verify_chain_depth_enforced() {
        let p = TlsPinPolicy {
            max_cert_chain_depth: Some(2),
            ..Default::default()
        };
        assert!(p.verify_chain_depth(2).is_ok());
        assert!(matches!(
            p.verify_chain_depth(3),
            Err(crate::Error::PolicyDenied(_))
        ));
        // No cap → always ok.
        assert!(TlsPinPolicy::default().verify_chain_depth(99).is_ok());
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

    /// A secret nested inside an object under a sensitive key must be redacted
    /// at every depth — the inherited sensitivity flag must propagate into the
    /// recursive object walk (the High finding).
    #[test]
    fn redacts_nested_object_under_sensitive_key() {
        let p = Policy::new(McpPolicy::default());
        let v = json!({"password": {"plain": "hunter2", "deeper": {"again": "s3cr3t"}}});
        let r = p.redact(v);
        assert_eq!(r["password"]["plain"], "***");
        assert_eq!(r["password"]["deeper"]["again"], "***");
        assert!(
            !serde_json::to_string(&r).unwrap().contains("hunter2"),
            "nested secret leaked: {r}"
        );
        assert!(!serde_json::to_string(&r).unwrap().contains("s3cr3t"));
    }

    /// An array of objects under a sensitive key must have every element
    /// redacted, including nested object values.
    #[test]
    fn redacts_array_of_objects_under_sensitive_key() {
        let p = Policy::new(McpPolicy::default());
        let v = json!({"credential": [{"inner": "a"}, {"inner": "b"}, "raw"]});
        let r = p.redact(v);
        assert_eq!(r["credential"][0]["inner"], "***");
        assert_eq!(r["credential"][1]["inner"], "***");
        assert_eq!(r["credential"][2], "***");
    }

    /// Non-string scalars (numbers, bools) under a sensitive key must also be
    /// redacted — a numeric token leaks just as badly as a string (the Med
    /// companion finding).
    #[test]
    fn redacts_non_string_scalar_secrets() {
        let p = Policy::new(McpPolicy::default());
        let v = json!({"token": 1_234_567, "secret": true, "api_key": 9.5});
        let r = p.redact(v);
        assert_eq!(r["token"], "***");
        assert_eq!(r["secret"], "***");
        assert_eq!(r["api_key"], "***");
    }

    /// A numeric/bool value nested under a sensitive parent object must also be
    /// redacted, exercising both propagation and the scalar arm together.
    #[test]
    fn redacts_nested_non_string_scalar_under_sensitive_parent() {
        let p = Policy::new(McpPolicy::default());
        let v = json!({"password": {"pin": 4242, "enabled": true}});
        let r = p.redact(v);
        assert_eq!(r["password"]["pin"], "***");
        assert_eq!(r["password"]["enabled"], "***");
    }

    /// Non-sensitive values — including non-sensitive scalars and nested
    /// non-sensitive objects — must pass through untouched.
    #[test]
    fn leaves_non_sensitive_values_untouched() {
        let p = Policy::new(McpPolicy::default());
        let v = json!({
            "user": "alice",
            "port": 22,
            "enabled": true,
            "nested": {"host": "example.com", "retries": 3}
        });
        let r = p.redact(v);
        assert_eq!(r["user"], "alice");
        assert_eq!(r["port"], 22);
        assert_eq!(r["enabled"], true);
        assert_eq!(r["nested"]["host"], "example.com");
        assert_eq!(r["nested"]["retries"], 3);
    }

    /// A `secret://` reference nested under a sensitive parent is still a
    /// reference, not a value, and must be preserved.
    #[test]
    fn preserves_nested_secret_uri_under_sensitive_parent() {
        let p = Policy::new(McpPolicy::default());
        let v = json!({"password": {"ref": "secret://ns/db", "value": "leak"}});
        let r = p.redact(v);
        assert_eq!(r["password"]["ref"], "secret://ns/db");
        assert_eq!(r["password"]["value"], "***");
    }
}
