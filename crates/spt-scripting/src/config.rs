//! Configuration types for the scripting engine.
//!
//! These mirror [`spt_config::schema::ScriptConfig`] one-for-one but in
//! engine-facing terms (concrete `PathBuf`, `u64`/`usize` rather than
//! optional strings). The runtime mapper in `spt-bin` (Bwire) converts
//! between the two so `spt-config` need not depend on this crate.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Resolved scripting configuration for one profile.
///
/// `path` is an absolute filesystem path (resolved at config-load time
/// relative to the config-file directory). The script is read once at
/// [`crate::ScriptEngine::load`] time and compiled to an AST; failures are
/// raised then, not at first hook invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptConfig {
    /// Filesystem path to the Rhai script.
    pub path: PathBuf,
    /// Per-hook entry-point function names.
    #[serde(default)]
    pub hooks: ScriptHooks,
    /// Sandbox limits.
    #[serde(default)]
    pub limits: ScriptLimits,
}

/// Per-hook entry-point function names.
///
/// `None` means the corresponding lifecycle event is not delivered to the
/// script — the call site short-circuits without entering the engine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptHooks {
    /// Pre-connect entry point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_connect: Option<String>,
    /// Post-connect entry point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_connect: Option<String>,
    /// Forward state-machine entry point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_forward_state: Option<String>,
    /// Disconnect entry point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_disconnect: Option<String>,
    /// Generic event entry point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_event: Option<String>,
}

impl ScriptHooks {
    /// Returns `true` if every hook slot is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pre_connect.is_none()
            && self.post_connect.is_none()
            && self.on_forward_state.is_none()
            && self.on_disconnect.is_none()
            && self.on_event.is_none()
    }

    /// Lookup the configured function name for a given hook slot.
    #[must_use]
    pub fn function_for(&self, hook: HookName) -> Option<&str> {
        match hook {
            HookName::PreConnect => self.pre_connect.as_deref(),
            HookName::PostConnect => self.post_connect.as_deref(),
            HookName::OnForwardState => self.on_forward_state.as_deref(),
            HookName::OnDisconnect => self.on_disconnect.as_deref(),
            HookName::OnEvent => self.on_event.as_deref(),
        }
    }
}

/// Sandbox limits applied to the Rhai engine before AST registration.
///
/// All limits are honoured by Rhai natively via the
/// `Engine::set_max_operations` / `set_max_call_levels` /
/// `set_max_string_size` / `set_max_array_size` / `set_max_modules`
/// builders. Defaults are documented per field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)] // every limit is `max_*` by spec.
pub struct ScriptLimits {
    /// Maximum number of Rhai operations per hook invocation. Default
    /// `1_000_000`. Exceeding the limit aborts the script with
    /// [`crate::ScriptError::LimitExceeded`].
    pub max_operations: u64,
    /// Maximum recursion depth. Default `32`.
    pub max_call_levels: usize,
    /// Maximum allocation size of any single string in bytes. Default
    /// `65_536`. Larger string concatenations abort.
    pub max_string_size: usize,
    /// Maximum length of any single array. Default `4_096`.
    pub max_array_size: usize,
    /// Maximum number of modules loadable per session. Default `0` —
    /// `import` is effectively forbidden in addition to being
    /// `disable_symbol`-ed.
    pub max_modules: usize,
}

impl Default for ScriptLimits {
    fn default() -> Self {
        Self {
            max_operations: 1_000_000,
            max_call_levels: 32,
            max_string_size: 65_536,
            max_array_size: 4_096,
            max_modules: 0,
        }
    }
}

/// Discriminator for the five hook slots. Stable for log / audit emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookName {
    /// `pre_connect`.
    PreConnect,
    /// `post_connect`.
    PostConnect,
    /// `on_forward_state`.
    OnForwardState,
    /// `on_disconnect`.
    OnDisconnect,
    /// `on_event`.
    OnEvent,
}

impl HookName {
    /// Stable wire / log identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreConnect => "pre_connect",
            Self::PostConnect => "post_connect",
            Self::OnForwardState => "on_forward_state",
            Self::OnDisconnect => "on_disconnect",
            Self::OnEvent => "on_event",
        }
    }
}

impl std::fmt::Display for HookName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let l = ScriptLimits::default();
        assert_eq!(l.max_operations, 1_000_000);
        assert_eq!(l.max_call_levels, 32);
        assert_eq!(l.max_string_size, 65_536);
        assert_eq!(l.max_array_size, 4_096);
        assert_eq!(l.max_modules, 0);
    }

    #[test]
    fn empty_hooks_short_circuit() {
        let h = ScriptHooks::default();
        assert!(h.is_empty());
        assert!(h.function_for(HookName::PreConnect).is_none());
        assert!(h.function_for(HookName::OnEvent).is_none());
    }

    #[test]
    fn function_lookup_returns_configured_name() {
        let h = ScriptHooks {
            pre_connect: Some("before".into()),
            on_event: Some("any".into()),
            ..Default::default()
        };
        assert_eq!(h.function_for(HookName::PreConnect), Some("before"));
        assert_eq!(h.function_for(HookName::OnEvent), Some("any"));
        assert_eq!(h.function_for(HookName::PostConnect), None);
        assert!(!h.is_empty());
    }

    #[test]
    fn hook_name_strings_stable() {
        // Asserted as stable identifiers used by audit and tracing layers.
        assert_eq!(HookName::PreConnect.as_str(), "pre_connect");
        assert_eq!(HookName::PostConnect.as_str(), "post_connect");
        assert_eq!(HookName::OnForwardState.as_str(), "on_forward_state");
        assert_eq!(HookName::OnDisconnect.as_str(), "on_disconnect");
        assert_eq!(HookName::OnEvent.as_str(), "on_event");
    }
}
