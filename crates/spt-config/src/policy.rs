//! Group Policy / registry-overlay binding table for `spt-config`.
//!
//! This module is **pure data** — it knows the canonical list of policies that
//! the Windows GPO ADMX template (see `packaging/windows-gpo/`) exposes, and
//! how each one maps onto a [`crate::schema::Config`] field. It contains no
//! Windows or filesystem dependencies; the OS-side reader lives in
//! `spt-bin/src/policy/registry.rs` and the merge driver in
//! `spt-bin/src/policy/overlay.rs`.
//!
//! ## Model
//!
//! Each policy is identified by a `(section, name)` pair under the registry
//! root `Software\Policies\spt`. A policy may be present in either of two
//! hives:
//!
//! * `HKLM\Software\Policies\spt\<Section>\<Name>` — machine policy.
//! * `HKCU\Software\Policies\spt\<Section>\<Name>` — user policy.
//!
//! Co-located with each policy value, an optional `REG_DWORD` named `Enforced`
//! (value `1`) marks the machine policy as **enforced**: the overlay overrides
//! whatever is in `Config` and the field is recorded as locked. Otherwise the
//! policy is **advisory** — it only fills in the field when the loaded
//! `Config` left it unset (`None` / empty `Vec`).
//!
//! User-hive (`HKCU`) values are *never* enforced; `Enforced=1` there is
//! ignored. The merge precedence is:
//!
//! ```text
//! HKLM-enforced > config-file > HKLM-advisory > HKCU-advisory > built-in default
//! ```
//!
//! Allow-list policies (multi-string `REG_MULTI_SZ`) are merged by
//! **most-restrictive intersection**: when both an HKLM enforced list and a
//! config-file list are present, the resulting allowlist is the set of
//! entries that appear in *both*. This makes Group Policy strictly tighter
//! than the local config can be — admins can only further restrict, never
//! expand, a list set by a higher-priority source.

use std::collections::{BTreeSet, HashMap};

use crate::schema::Config;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single policy value loaded from the registry. The OS layer constructs
/// these; this crate only consumes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyValue {
    /// `REG_SZ` / `REG_EXPAND_SZ`.
    String(String),
    /// `REG_DWORD` / `REG_QWORD` rendered as a decimal integer.
    Integer(i64),
    /// `REG_DWORD` of value `0` or `1` interpreted as a boolean.
    Bool(bool),
    /// `REG_MULTI_SZ`. Used by allowlists.
    MultiString(Vec<String>),
}

/// Bundle of policies read from one or both hives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyBundle {
    /// Values found under `HKLM\Software\Policies\spt`. Keys use the canonical
    /// `Section\Name` form (forward or backslash-separated; the OS layer
    /// produces backslashes).
    pub machine: HashMap<String, PolicyValue>,
    /// Values found under `HKCU\Software\Policies\spt`. Same key form.
    pub user: HashMap<String, PolicyValue>,
    /// Set of `Section\Name` keys whose `Enforced` sibling was `REG_DWORD = 1`
    /// in the machine hive. Only the machine hive can enforce.
    pub enforced: BTreeSet<String>,
}

impl PolicyBundle {
    /// Construct an empty bundle.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// True if the bundle contains zero policy values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.machine.is_empty() && self.user.is_empty()
    }

    /// True if the given `Section\Name` is enforced via HKLM.
    #[must_use]
    pub fn is_enforced(&self, key: &str) -> bool {
        self.enforced.contains(key)
    }
}

/// Outcome of applying the overlay onto a [`Config`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverlayReport {
    /// `Section\Name` of every policy that was successfully applied.
    pub applied: Vec<String>,
    /// `Section\Name` of every policy that was applied with the *enforced*
    /// flag and therefore made the corresponding config field locked.
    pub locked: Vec<String>,
    /// Policies that were present in the bundle but not understood.
    /// Useful for logging / diagnostics.
    pub unknown: Vec<String>,
    /// Policies whose value type didn't match the binding's expected type.
    pub type_mismatch: Vec<String>,
}

// ---------------------------------------------------------------------------
// Binding table
// ---------------------------------------------------------------------------

/// Type of value a binding expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingKind {
    /// `REG_SZ` policy mapped onto an `Option<String>` field.
    String,
    /// `REG_DWORD` with `0`/`1` mapped onto an `Option<bool>` field.
    Bool,
    /// `REG_DWORD` mapped onto an `Option<u32>` field.
    U32,
    /// `REG_MULTI_SZ` mapped onto an `Option<Vec<String>>` allowlist field.
    /// When merging, the most-restrictive intersection rule applies.
    Allowlist,
}

/// One row of the policy → config binding table.
#[derive(Debug, Clone, Copy)]
pub struct Binding {
    /// Registry section under `Software\Policies\spt\<section>`.
    pub section: &'static str,
    /// Registry value name under that section.
    pub name: &'static str,
    /// Expected value type.
    pub kind: BindingKind,
    /// Mutator that writes the parsed value into a `Config`.
    /// Returns `true` iff it actually changed something.
    pub apply: fn(&mut Config, &PolicyValue, mode: ApplyMode) -> bool,
    /// Predicate: returns true if the corresponding field is currently unset
    /// in the config (i.e. an advisory policy is allowed to fill it).
    pub is_unset: fn(&Config) -> bool,
}

impl Binding {
    /// Canonical `Section\Name` registry key for this binding.
    #[must_use]
    pub fn key(self) -> String {
        format!("{}\\{}", self.section, self.name)
    }
}

impl BindingKind {
    /// Stable string used by CLI/JSON surfaces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Bool => "bool",
            Self::U32 => "u32",
            Self::Allowlist => "multi_string",
        }
    }
}

/// Whether a binding's `apply` should run as enforced (always overwrite) or
/// advisory (only if `is_unset` was true).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    /// Overwrite the existing config value. For allowlists, intersect with
    /// the current value if present.
    Enforced,
    /// Only fill in if the field was not already set.
    Advisory,
}

/// Find a policy binding by section/name, case-insensitively.
#[must_use]
pub fn find_binding(section: &str, name: &str) -> Option<&'static Binding> {
    BINDINGS.iter().find(|binding| {
        binding.section.eq_ignore_ascii_case(section) && binding.name.eq_ignore_ascii_case(name)
    })
}

/// Static binding table. Order is stable for deterministic reporting.
///
/// The set covers the policies declared in the GPO ADMX template
/// (`packaging/windows-gpo/en-US/spt.admx`):
///
/// * Logging — `Level`, `Format`, `MaxFiles`
/// * Runtime — `RequireValidConfig`, `ProfileStartParallelism`
/// * Secrets — `Backend`, `MemoryProtection`
/// * Firewall — `Manager`, `ApplyRules`, `BindPolicy`
/// * Observability — `Metrics_Enabled`, `Metrics_Format`,
///                    `WindowsEvent_Enabled`, `WindowsEvent_Channel`
/// * Mcp — `Enabled`, `Bind`
/// * `RemoteConfig` — `Enabled`, `Url`, `AllowCachedOnFailure`
/// * Allowlists — `AllowedRemoteSinks`, `AllowedSecretsBackends`,
///                 `AllowedFirewallManagers`, `AllowedLoggingDestinations`
pub static BINDINGS: &[Binding] = &[
    // Logging
    Binding {
        section: "Logging",
        name: "Level",
        kind: BindingKind::String,
        apply: apply_logging_level,
        is_unset: |c| c.logging.as_ref().and_then(|l| l.level.as_ref()).is_none(),
    },
    Binding {
        section: "Logging",
        name: "Format",
        kind: BindingKind::String,
        apply: apply_logging_format,
        is_unset: |c| c.logging.as_ref().and_then(|l| l.format.as_ref()).is_none(),
    },
    Binding {
        section: "Logging",
        name: "MaxFiles",
        kind: BindingKind::U32,
        apply: apply_logging_max_files,
        is_unset: |c| c.logging.as_ref().and_then(|l| l.max_files).is_none(),
    },
    Binding {
        section: "Logging",
        name: "AllowedDestinations",
        kind: BindingKind::Allowlist,
        apply: apply_logging_destinations,
        is_unset: |c| {
            c.logging
                .as_ref()
                .and_then(|l| l.destinations.as_ref())
                .is_none()
        },
    },
    // Runtime
    Binding {
        section: "Runtime",
        name: "ProfileStartParallelism",
        kind: BindingKind::U32,
        apply: apply_runtime_parallelism,
        is_unset: |c| {
            c.runtime
                .as_ref()
                .and_then(|r| r.profile_start_parallelism)
                .is_none()
        },
    },
    Binding {
        section: "Runtime",
        name: "RequireValidConfig",
        kind: BindingKind::Bool,
        apply: apply_runtime_require_valid_config,
        is_unset: |c| {
            c.runtime
                .as_ref()
                .and_then(|r| r.reload.as_ref())
                .and_then(|r| r.require_valid_config)
                .is_none()
        },
    },
    Binding {
        section: "General",
        name: "StateDir",
        kind: BindingKind::String,
        apply: apply_runtime_state_dir,
        is_unset: |c| {
            c.runtime
                .as_ref()
                .and_then(|r| r.state_dir.as_ref())
                .is_none()
        },
    },
    // Secrets
    Binding {
        section: "Secrets",
        name: "Backend",
        kind: BindingKind::String,
        apply: apply_secrets_backend,
        is_unset: |c| {
            c.secrets
                .as_ref()
                .and_then(|s| s.backend.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Secrets",
        name: "MemoryProtection",
        kind: BindingKind::String,
        apply: apply_secrets_mem,
        is_unset: |c| {
            c.secrets
                .as_ref()
                .and_then(|s| s.memory_protection.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Security",
        name: "SecretBackend",
        kind: BindingKind::String,
        apply: apply_secrets_backend,
        is_unset: |c| {
            c.secrets
                .as_ref()
                .and_then(|s| s.backend.as_ref())
                .is_none()
        },
    },
    // Firewall
    Binding {
        section: "Firewall",
        name: "Manager",
        kind: BindingKind::String,
        apply: apply_firewall_manager,
        is_unset: |c| {
            c.firewall
                .as_ref()
                .and_then(|f| f.manager.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Firewall",
        name: "ApplyRules",
        kind: BindingKind::Bool,
        apply: apply_firewall_apply_rules,
        is_unset: |c| c.firewall.as_ref().and_then(|f| f.apply_rules).is_none(),
    },
    Binding {
        section: "Firewall",
        name: "BindPolicy",
        kind: BindingKind::String,
        apply: apply_firewall_bind_policy,
        is_unset: |c| {
            c.firewall
                .as_ref()
                .and_then(|f| f.bind_policy.as_ref())
                .is_none()
        },
    },
    // Network / interface / gateway policy. These are intentionally broad so
    // GPO and CLI-managed policy can constrain routing without editing each
    // profile.
    Binding {
        section: "Network",
        name: "DefaultInterface",
        kind: BindingKind::String,
        apply: apply_network_default_interface,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.interface.as_ref())
                .and_then(|i| i.default_interface.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "AllowedInterfaces",
        kind: BindingKind::Allowlist,
        apply: apply_network_allowed_interfaces,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.interface.as_ref())
                .and_then(|i| i.allowed_interfaces.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "RequireExplicitInterface",
        kind: BindingKind::Bool,
        apply: apply_network_require_explicit_interface,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.interface.as_ref())
                .and_then(|i| i.require_explicit_interface)
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "AllowAllInterfaces",
        kind: BindingKind::Bool,
        apply: apply_network_allow_all_interfaces,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.interface.as_ref())
                .and_then(|i| i.allow_all_interfaces)
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "BindIpv6",
        kind: BindingKind::String,
        apply: apply_network_bind_ipv6,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.interface.as_ref())
                .and_then(|i| i.bind_ipv6.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "DefaultGateway",
        kind: BindingKind::String,
        apply: apply_network_default_gateway,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.gateway.as_ref())
                .and_then(|g| g.default_gateway.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "GatewayInterface",
        kind: BindingKind::String,
        apply: apply_network_gateway_interface,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.gateway.as_ref())
                .and_then(|g| g.interface.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "RouteCheckTarget",
        kind: BindingKind::String,
        apply: apply_network_route_check_target,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.gateway.as_ref())
                .and_then(|g| g.route_check_target.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "RequireGatewayMatch",
        kind: BindingKind::Bool,
        apply: apply_network_require_gateway_match,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.gateway.as_ref())
                .and_then(|g| g.require_gateway_match)
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "GatewayPolicy",
        kind: BindingKind::String,
        apply: apply_network_gateway_policy,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.gateway.as_ref())
                .and_then(|g| g.policy.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "OffloadZeroCopy",
        kind: BindingKind::Bool,
        apply: apply_network_offload_zerocopy,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.offload.as_ref())
                .and_then(|o| o.zerocopy)
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "OffloadIoUring",
        kind: BindingKind::Bool,
        apply: apply_network_offload_io_uring,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.offload.as_ref())
                .and_then(|o| o.io_uring)
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "LoadBalanceStrategy",
        kind: BindingKind::String,
        apply: apply_network_load_balance_strategy,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.load_balance.as_ref())
                .and_then(|lb| lb.strategy.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "LoadBalanceFailAfter",
        kind: BindingKind::U32,
        apply: apply_network_load_balance_fail_after,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.load_balance.as_ref())
                .and_then(|lb| lb.fail_after)
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "LoadBalanceRestoreAfter",
        kind: BindingKind::String,
        apply: apply_network_load_balance_restore_after,
        is_unset: |c| {
            c.network
                .as_ref()
                .and_then(|n| n.load_balance.as_ref())
                .and_then(|lb| lb.restore_after.as_ref())
                .is_none()
        },
    },
    // ADMX compatibility aliases from packaging/windows-gpo.
    Binding {
        section: "Network",
        name: "RemoteConfigUrlPin",
        kind: BindingKind::String,
        apply: apply_remote_cfg_url,
        is_unset: |c| {
            c.runtime
                .as_ref()
                .and_then(|r| r.remote_config.as_ref())
                .and_then(|r| r.url.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "RemoteConfigFingerprintSha256",
        kind: BindingKind::String,
        apply: apply_remote_cfg_fingerprint,
        is_unset: |c| {
            c.runtime
                .as_ref()
                .and_then(|r| r.remote_config.as_ref())
                .and_then(|r| r.fingerprint_sha256.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Network",
        name: "McpEnabled",
        kind: BindingKind::Bool,
        apply: apply_mcp_enabled,
        is_unset: |c| c.mcp.as_ref().and_then(|m| m.enabled).is_none(),
    },
    Binding {
        section: "Network",
        name: "McpListen",
        kind: BindingKind::String,
        apply: apply_mcp_listen,
        is_unset: |c| c.mcp.as_ref().and_then(|m| m.listen.as_ref()).is_none(),
    },
    // Observability
    Binding {
        section: "Observability",
        name: "LogLevel",
        kind: BindingKind::String,
        apply: apply_logging_level,
        is_unset: |c| c.logging.as_ref().and_then(|l| l.level.as_ref()).is_none(),
    },
    Binding {
        section: "Observability",
        name: "LogDestinations",
        kind: BindingKind::Allowlist,
        apply: apply_logging_destinations,
        is_unset: |c| {
            c.logging
                .as_ref()
                .and_then(|l| l.destinations.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Observability",
        name: "WindowsEvent_Enabled",
        kind: BindingKind::Bool,
        apply: apply_winevent_enabled,
        is_unset: |c| {
            c.observability
                .as_ref()
                .and_then(|o| o.windows_event.as_ref())
                .and_then(|w| w.enabled)
                .is_none()
        },
    },
    Binding {
        section: "Observability",
        name: "WindowsEvent_Channel",
        kind: BindingKind::String,
        apply: apply_winevent_channel,
        is_unset: |c| {
            c.observability
                .as_ref()
                .and_then(|o| o.windows_event.as_ref())
                .and_then(|w| w.channel.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "Observability",
        name: "Metrics_Enabled",
        kind: BindingKind::Bool,
        apply: apply_metrics_enabled,
        is_unset: |c| {
            c.observability
                .as_ref()
                .and_then(|o| o.metrics.as_ref())
                .and_then(|m| m.enabled)
                .is_none()
        },
    },
    // Remote config
    Binding {
        section: "RemoteConfig",
        name: "Enabled",
        kind: BindingKind::Bool,
        apply: apply_remote_cfg_enabled,
        is_unset: |c| {
            c.runtime
                .as_ref()
                .and_then(|r| r.remote_config.as_ref())
                .and_then(|r| r.enabled)
                .is_none()
        },
    },
    Binding {
        section: "RemoteConfig",
        name: "Url",
        kind: BindingKind::String,
        apply: apply_remote_cfg_url,
        is_unset: |c| {
            c.runtime
                .as_ref()
                .and_then(|r| r.remote_config.as_ref())
                .and_then(|r| r.url.as_ref())
                .is_none()
        },
    },
    Binding {
        section: "RemoteConfig",
        name: "AllowCachedOnFailure",
        kind: BindingKind::Bool,
        apply: apply_remote_cfg_cached,
        is_unset: |c| {
            c.runtime
                .as_ref()
                .and_then(|r| r.remote_config.as_ref())
                .and_then(|r| r.allow_cached_on_failure)
                .is_none()
        },
    },
];

// ---------------------------------------------------------------------------
// Mutators
// ---------------------------------------------------------------------------

fn ensure_logging(c: &mut Config) -> &mut crate::schema::Logging {
    c.logging.get_or_insert_with(Default::default)
}

fn ensure_runtime(c: &mut Config) -> &mut crate::schema::Runtime {
    c.runtime.get_or_insert_with(Default::default)
}

fn ensure_runtime_reload(c: &mut Config) -> &mut crate::schema::RuntimeReload {
    ensure_runtime(c)
        .reload
        .get_or_insert_with(Default::default)
}

fn ensure_runtime_remote(c: &mut Config) -> &mut crate::schema::RuntimeRemoteConfig {
    ensure_runtime(c)
        .remote_config
        .get_or_insert_with(Default::default)
}

fn ensure_secrets(c: &mut Config) -> &mut crate::schema::Secrets {
    c.secrets.get_or_insert_with(Default::default)
}

fn ensure_firewall(c: &mut Config) -> &mut crate::schema::Firewall {
    c.firewall.get_or_insert_with(Default::default)
}

fn ensure_network(c: &mut Config) -> &mut crate::schema::Network {
    c.network.get_or_insert_with(Default::default)
}

fn ensure_network_interface(c: &mut Config) -> &mut crate::schema::NetworkInterface {
    ensure_network(c)
        .interface
        .get_or_insert_with(Default::default)
}

fn ensure_network_gateway(c: &mut Config) -> &mut crate::schema::NetworkGateway {
    ensure_network(c)
        .gateway
        .get_or_insert_with(Default::default)
}

fn ensure_network_offload(c: &mut Config) -> &mut crate::schema::NetworkOffload {
    ensure_network(c)
        .offload
        .get_or_insert_with(Default::default)
}

fn ensure_network_load_balance(c: &mut Config) -> &mut crate::schema::NetworkLoadBalance {
    ensure_network(c)
        .load_balance
        .get_or_insert_with(Default::default)
}

fn ensure_obs(c: &mut Config) -> &mut crate::schema::Observability {
    c.observability.get_or_insert_with(Default::default)
}

fn ensure_winevent(c: &mut Config) -> &mut crate::schema::ObservabilityWindowsEvent {
    ensure_obs(c)
        .windows_event
        .get_or_insert_with(Default::default)
}

fn ensure_metrics(c: &mut Config) -> &mut crate::schema::ObservabilityMetrics {
    ensure_obs(c).metrics.get_or_insert_with(Default::default)
}

fn ensure_mcp(c: &mut Config) -> &mut crate::schema::Mcp {
    c.mcp.get_or_insert_with(Default::default)
}

// String/bool/u32 setters share a tiny helper closure pattern:

fn as_string(v: &PolicyValue) -> Option<String> {
    match v {
        PolicyValue::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn as_bool(v: &PolicyValue) -> Option<bool> {
    match v {
        PolicyValue::Bool(b) => Some(*b),
        PolicyValue::Integer(i) => Some(*i != 0),
        _ => None,
    }
}

fn as_u32(v: &PolicyValue) -> Option<u32> {
    match v {
        PolicyValue::Integer(i) => u32::try_from(*i).ok(),
        _ => None,
    }
}

fn as_multi(v: &PolicyValue) -> Option<&[String]> {
    match v {
        PolicyValue::MultiString(v) => Some(v),
        _ => None,
    }
}

// Logging

fn apply_logging_level(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let l = ensure_logging(c);
    let changed = l.level.as_deref() != Some(s.as_str());
    l.level = Some(s);
    changed
}

fn apply_logging_format(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let l = ensure_logging(c);
    let changed = l.format.as_deref() != Some(s.as_str());
    l.format = Some(s);
    changed
}

fn apply_logging_max_files(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(n) = as_u32(v) else { return false };
    let l = ensure_logging(c);
    let changed = l.max_files != Some(n);
    l.max_files = Some(n);
    changed
}

fn apply_logging_destinations(c: &mut Config, v: &PolicyValue, mode: ApplyMode) -> bool {
    let Some(policy_list) = as_multi(v) else {
        return false;
    };
    let l = ensure_logging(c);
    let new = match (mode, l.destinations.as_ref()) {
        (ApplyMode::Enforced, Some(existing)) => intersect(existing, policy_list),
        _ => policy_list.to_vec(),
    };
    let changed = l.destinations.as_deref() != Some(new.as_slice());
    l.destinations = Some(new);
    changed
}

// Runtime

fn apply_runtime_parallelism(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(n) = as_u32(v) else { return false };
    let r = ensure_runtime(c);
    let changed = r.profile_start_parallelism != Some(n);
    r.profile_start_parallelism = Some(n);
    changed
}

fn apply_runtime_require_valid_config(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let r = ensure_runtime_reload(c);
    let changed = r.require_valid_config != Some(b);
    r.require_valid_config = Some(b);
    changed
}

fn apply_runtime_state_dir(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let r = ensure_runtime(c);
    let changed = r.state_dir.as_deref() != Some(s.as_str());
    r.state_dir = Some(s);
    changed
}

// Secrets

fn apply_secrets_backend(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let sec = ensure_secrets(c);
    let changed = sec.backend.as_deref() != Some(s.as_str());
    sec.backend = Some(s);
    changed
}

fn apply_secrets_mem(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let sec = ensure_secrets(c);
    let changed = sec.memory_protection.as_deref() != Some(s.as_str());
    sec.memory_protection = Some(s);
    changed
}

// Firewall

fn apply_firewall_manager(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let f = ensure_firewall(c);
    let changed = f.manager.as_deref() != Some(s.as_str());
    f.manager = Some(s);
    changed
}

fn apply_firewall_apply_rules(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let f = ensure_firewall(c);
    let changed = f.apply_rules != Some(b);
    f.apply_rules = Some(b);
    changed
}

fn apply_firewall_bind_policy(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let f = ensure_firewall(c);
    let changed = f.bind_policy.as_deref() != Some(s.as_str());
    f.bind_policy = Some(s);
    changed
}

// Network

fn apply_network_default_interface(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let i = ensure_network_interface(c);
    let changed = i.default_interface.as_deref() != Some(s.as_str());
    i.default_interface = Some(s);
    changed
}

fn apply_network_allowed_interfaces(c: &mut Config, v: &PolicyValue, mode: ApplyMode) -> bool {
    let Some(policy_list) = as_multi(v) else {
        return false;
    };
    let i = ensure_network_interface(c);
    let new = match (mode, i.allowed_interfaces.as_ref()) {
        (ApplyMode::Enforced, Some(existing)) => intersect(existing, policy_list),
        _ => policy_list.to_vec(),
    };
    let changed = i.allowed_interfaces.as_deref() != Some(new.as_slice());
    i.allowed_interfaces = Some(new);
    changed
}

fn apply_network_require_explicit_interface(
    c: &mut Config,
    v: &PolicyValue,
    _m: ApplyMode,
) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let i = ensure_network_interface(c);
    let changed = i.require_explicit_interface != Some(b);
    i.require_explicit_interface = Some(b);
    changed
}

fn apply_network_allow_all_interfaces(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let i = ensure_network_interface(c);
    let changed = i.allow_all_interfaces != Some(b);
    i.allow_all_interfaces = Some(b);
    changed
}

fn apply_network_bind_ipv6(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let i = ensure_network_interface(c);
    let changed = i.bind_ipv6.as_deref() != Some(s.as_str());
    i.bind_ipv6 = Some(s);
    changed
}

fn apply_network_default_gateway(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let g = ensure_network_gateway(c);
    let changed = g.default_gateway.as_deref() != Some(s.as_str());
    g.default_gateway = Some(s);
    changed
}

fn apply_network_gateway_interface(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let g = ensure_network_gateway(c);
    let changed = g.interface.as_deref() != Some(s.as_str());
    g.interface = Some(s);
    changed
}

fn apply_network_route_check_target(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let g = ensure_network_gateway(c);
    let changed = g.route_check_target.as_deref() != Some(s.as_str());
    g.route_check_target = Some(s);
    changed
}

fn apply_network_require_gateway_match(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let g = ensure_network_gateway(c);
    let changed = g.require_gateway_match != Some(b);
    g.require_gateway_match = Some(b);
    changed
}

fn apply_network_gateway_policy(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let g = ensure_network_gateway(c);
    let changed = g.policy.as_deref() != Some(s.as_str());
    g.policy = Some(s);
    changed
}

fn apply_network_offload_zerocopy(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let o = ensure_network_offload(c);
    let changed = o.zerocopy != Some(b);
    o.zerocopy = Some(b);
    changed
}

fn apply_network_offload_io_uring(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let o = ensure_network_offload(c);
    let changed = o.io_uring != Some(b);
    o.io_uring = Some(b);
    changed
}

fn apply_network_load_balance_strategy(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let lb = ensure_network_load_balance(c);
    let changed = lb.strategy.as_deref() != Some(s.as_str());
    lb.strategy = Some(s);
    changed
}

fn apply_network_load_balance_fail_after(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(n) = as_u32(v) else { return false };
    let lb = ensure_network_load_balance(c);
    let changed = lb.fail_after != Some(n);
    lb.fail_after = Some(n);
    changed
}

fn apply_network_load_balance_restore_after(
    c: &mut Config,
    v: &PolicyValue,
    _m: ApplyMode,
) -> bool {
    let Some(s) = as_string(v) else { return false };
    let lb = ensure_network_load_balance(c);
    let changed = lb.restore_after.as_deref() != Some(s.as_str());
    lb.restore_after = Some(s);
    changed
}

// Observability

fn apply_winevent_enabled(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let w = ensure_winevent(c);
    let changed = w.enabled != Some(b);
    w.enabled = Some(b);
    changed
}

fn apply_winevent_channel(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let w = ensure_winevent(c);
    let changed = w.channel.as_deref() != Some(s.as_str());
    w.channel = Some(s);
    changed
}

fn apply_metrics_enabled(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let m = ensure_metrics(c);
    let changed = m.enabled != Some(b);
    m.enabled = Some(b);
    changed
}

// Remote config

fn apply_remote_cfg_enabled(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let r = ensure_runtime_remote(c);
    let changed = r.enabled != Some(b);
    r.enabled = Some(b);
    changed
}

fn apply_remote_cfg_url(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let r = ensure_runtime_remote(c);
    let changed = r.url.as_deref() != Some(s.as_str());
    r.url = Some(s);
    changed
}

fn apply_remote_cfg_fingerprint(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let r = ensure_runtime_remote(c);
    let changed = r.fingerprint_sha256.as_deref() != Some(s.as_str());
    r.fingerprint_sha256 = Some(s);
    changed
}

fn apply_remote_cfg_cached(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let r = ensure_runtime_remote(c);
    let changed = r.allow_cached_on_failure != Some(b);
    r.allow_cached_on_failure = Some(b);
    changed
}

// MCP

fn apply_mcp_enabled(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(b) = as_bool(v) else { return false };
    let m = ensure_mcp(c);
    let changed = m.enabled != Some(b);
    m.enabled = Some(b);
    changed
}

fn apply_mcp_listen(c: &mut Config, v: &PolicyValue, _m: ApplyMode) -> bool {
    let Some(s) = as_string(v) else { return false };
    let m = ensure_mcp(c);
    let changed = m.listen.as_deref() != Some(s.as_str());
    m.listen = Some(s);
    changed
}

// Most-restrictive intersection used by allowlist merges. Order is taken from
// the *current* (config-side) list so that deterministic ordering is preserved
// when the policy did not introduce new positions.
fn intersect(a: &[String], b: &[String]) -> Vec<String> {
    let bset: BTreeSet<&String> = b.iter().collect();
    a.iter().filter(|x| bset.contains(*x)).cloned().collect()
}

// ---------------------------------------------------------------------------
// Overlay driver
// ---------------------------------------------------------------------------

/// Pure-data overlay applier. The Windows-side `policy::overlay::apply` thin
/// wrapper calls this with a [`PolicyBundle`] read from the registry; tests
/// invoke it directly with synthetic bundles.
#[derive(Debug, Clone, Default)]
pub struct PolicyOverlay;

impl PolicyOverlay {
    /// Apply `bundle` onto `cfg`, returning a report.
    ///
    /// Precedence: enforced HKLM > existing config > advisory HKLM > advisory
    /// HKCU. Allowlists merge by most-restrictive intersection.
    pub fn apply(cfg: &mut Config, bundle: &PolicyBundle) -> OverlayReport {
        let mut report = OverlayReport::default();
        let mut consumed: BTreeSet<String> = BTreeSet::new();

        // Pass 1: enforced HKLM (always wins, marks locked)
        for binding in BINDINGS {
            let key = format!("{}\\{}", binding.section, binding.name);
            if !bundle.is_enforced(&key) {
                continue;
            }
            let Some(v) = bundle.machine.get(&key) else {
                continue;
            };
            if !type_matches(binding.kind, v) {
                report.type_mismatch.push(key.clone());
                consumed.insert(key);
                continue;
            }
            // Whether the apply mutated anything or not, the policy was
            // honoured — record it as applied. Enforced policies always count.
            let _ = (binding.apply)(cfg, v, ApplyMode::Enforced);
            report.applied.push(key.clone());
            report.locked.push(key.clone());
            consumed.insert(key);
        }

        // Pass 2: advisory HKLM (only if config field unset)
        for binding in BINDINGS {
            let key = format!("{}\\{}", binding.section, binding.name);
            if consumed.contains(&key) {
                continue;
            }
            let Some(v) = bundle.machine.get(&key) else {
                continue;
            };
            if !type_matches(binding.kind, v) {
                report.type_mismatch.push(key.clone());
                consumed.insert(key);
                continue;
            }
            if !(binding.is_unset)(cfg) {
                consumed.insert(key);
                continue;
            }
            if (binding.apply)(cfg, v, ApplyMode::Advisory) {
                report.applied.push(key.clone());
            }
            consumed.insert(key);
        }

        // Pass 3: advisory HKCU
        for binding in BINDINGS {
            let key = format!("{}\\{}", binding.section, binding.name);
            if consumed.contains(&key) {
                continue;
            }
            let Some(v) = bundle.user.get(&key) else {
                continue;
            };
            if !type_matches(binding.kind, v) {
                report.type_mismatch.push(key.clone());
                consumed.insert(key);
                continue;
            }
            if !(binding.is_unset)(cfg) {
                consumed.insert(key);
                continue;
            }
            if (binding.apply)(cfg, v, ApplyMode::Advisory) {
                report.applied.push(key.clone());
            }
            consumed.insert(key);
        }

        // Diagnostic: unknown keys present in the bundle but not bound.
        let known: BTreeSet<String> = BINDINGS
            .iter()
            .map(|b| format!("{}\\{}", b.section, b.name))
            .collect();
        for k in bundle.machine.keys().chain(bundle.user.keys()) {
            if !known.contains(k) && !report.unknown.iter().any(|u| u == k) {
                report.unknown.push(k.clone());
            }
        }

        report
    }
}

fn type_matches(kind: BindingKind, v: &PolicyValue) -> bool {
    matches!(
        (kind, v),
        (BindingKind::String, PolicyValue::String(_))
            | (
                BindingKind::Bool,
                PolicyValue::Bool(_) | PolicyValue::Integer(_)
            )
            | (BindingKind::U32, PolicyValue::Integer(_))
            | (BindingKind::Allowlist, PolicyValue::MultiString(_))
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    fn key(s: &str, n: &str) -> String {
        format!("{s}\\{n}")
    }

    #[test]
    fn empty_bundle_is_a_noop() {
        let mut cfg = Config::default();
        let report = PolicyOverlay::apply(&mut cfg, &PolicyBundle::empty());
        assert!(report.applied.is_empty());
        assert!(report.locked.is_empty());
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn advisory_machine_fills_unset_field() {
        let mut cfg = Config::default();
        let mut b = PolicyBundle::empty();
        b.machine
            .insert(key("Logging", "Level"), PolicyValue::String("debug".into()));
        let r = PolicyOverlay::apply(&mut cfg, &b);
        assert_eq!(
            cfg.logging.as_ref().unwrap().level.as_deref(),
            Some("debug")
        );
        assert_eq!(r.applied, vec![key("Logging", "Level")]);
        assert!(r.locked.is_empty());
    }

    #[test]
    fn advisory_machine_does_not_override_set_field() {
        let mut cfg = Config::default();
        cfg.logging = Some(crate::schema::Logging {
            level: Some("info".into()),
            ..Default::default()
        });
        let mut b = PolicyBundle::empty();
        b.machine
            .insert(key("Logging", "Level"), PolicyValue::String("debug".into()));
        let r = PolicyOverlay::apply(&mut cfg, &b);
        assert_eq!(cfg.logging.as_ref().unwrap().level.as_deref(), Some("info"));
        assert!(r.applied.is_empty());
    }

    #[test]
    fn enforced_machine_overrides_set_field_and_locks() {
        let mut cfg = Config::default();
        cfg.logging = Some(crate::schema::Logging {
            level: Some("info".into()),
            ..Default::default()
        });
        let mut b = PolicyBundle::empty();
        let k = key("Logging", "Level");
        b.machine
            .insert(k.clone(), PolicyValue::String("error".into()));
        b.enforced.insert(k.clone());
        let r = PolicyOverlay::apply(&mut cfg, &b);
        assert_eq!(
            cfg.logging.as_ref().unwrap().level.as_deref(),
            Some("error")
        );
        assert_eq!(r.locked, vec![k.clone()]);
        assert_eq!(r.applied, vec![k]);
    }

    #[test]
    fn user_hive_cannot_enforce() {
        let mut cfg = Config::default();
        cfg.logging = Some(crate::schema::Logging {
            level: Some("info".into()),
            ..Default::default()
        });
        let mut b = PolicyBundle::empty();
        let k = key("Logging", "Level");
        b.user
            .insert(k.clone(), PolicyValue::String("error".into()));
        b.enforced.insert(k); // ignored — not in machine map
        let r = PolicyOverlay::apply(&mut cfg, &b);
        // existing config wins
        assert_eq!(cfg.logging.as_ref().unwrap().level.as_deref(), Some("info"));
        assert!(r.locked.is_empty());
        assert!(r.applied.is_empty());
    }

    #[test]
    fn user_hive_fills_when_machine_silent_and_field_unset() {
        let mut cfg = Config::default();
        let mut b = PolicyBundle::empty();
        b.user.insert(
            key("Secrets", "Backend"),
            PolicyValue::String("vault".into()),
        );
        let r = PolicyOverlay::apply(&mut cfg, &b);
        assert_eq!(
            cfg.secrets.as_ref().unwrap().backend.as_deref(),
            Some("vault")
        );
        assert_eq!(r.applied, vec![key("Secrets", "Backend")]);
    }

    #[test]
    fn machine_advisory_beats_user_advisory() {
        let mut cfg = Config::default();
        let mut b = PolicyBundle::empty();
        b.machine.insert(
            key("Secrets", "Backend"),
            PolicyValue::String("keychain".into()),
        );
        b.user.insert(
            key("Secrets", "Backend"),
            PolicyValue::String("vault".into()),
        );
        PolicyOverlay::apply(&mut cfg, &b);
        assert_eq!(
            cfg.secrets.as_ref().unwrap().backend.as_deref(),
            Some("keychain")
        );
    }

    #[test]
    fn enforced_allowlist_intersects_with_existing() {
        let mut cfg = Config::default();
        cfg.logging = Some(crate::schema::Logging {
            destinations: Some(vec!["stderr".into(), "file".into(), "remote".into()]),
            ..Default::default()
        });
        let mut b = PolicyBundle::empty();
        let k = key("Logging", "AllowedDestinations");
        b.machine.insert(
            k.clone(),
            PolicyValue::MultiString(vec!["file".into(), "remote".into(), "syslog".into()]),
        );
        b.enforced.insert(k);
        PolicyOverlay::apply(&mut cfg, &b);
        // intersection preserves config-side ordering of "file","remote"
        assert_eq!(
            cfg.logging.as_ref().unwrap().destinations.as_deref(),
            Some(["file".to_string(), "remote".to_string()].as_slice())
        );
    }

    #[test]
    fn advisory_allowlist_only_when_unset() {
        let mut cfg = Config::default();
        let mut b = PolicyBundle::empty();
        b.machine.insert(
            key("Logging", "AllowedDestinations"),
            PolicyValue::MultiString(vec!["stderr".into()]),
        );
        PolicyOverlay::apply(&mut cfg, &b);
        assert_eq!(
            cfg.logging.as_ref().unwrap().destinations.as_deref(),
            Some(["stderr".to_string()].as_slice())
        );
    }

    #[test]
    fn dword_zero_one_round_trip_to_bool() {
        let mut cfg = Config::default();
        let mut b = PolicyBundle::empty();
        b.machine
            .insert(key("Firewall", "ApplyRules"), PolicyValue::Integer(1));
        PolicyOverlay::apply(&mut cfg, &b);
        assert_eq!(cfg.firewall.as_ref().unwrap().apply_rules, Some(true));
    }

    #[test]
    fn type_mismatch_is_recorded_not_applied() {
        let mut cfg = Config::default();
        let mut b = PolicyBundle::empty();
        b.machine.insert(
            key("Logging", "MaxFiles"),
            PolicyValue::String("not-a-number".into()),
        );
        let r = PolicyOverlay::apply(&mut cfg, &b);
        assert!(r.applied.is_empty());
        assert_eq!(r.type_mismatch, vec![key("Logging", "MaxFiles")]);
    }

    #[test]
    fn unknown_key_is_diagnosed() {
        let mut cfg = Config::default();
        let mut b = PolicyBundle::empty();
        b.machine.insert(
            "BogusSection\\BogusName".into(),
            PolicyValue::String("x".into()),
        );
        let r = PolicyOverlay::apply(&mut cfg, &b);
        assert_eq!(r.unknown, vec!["BogusSection\\BogusName".to_string()]);
    }

    #[test]
    fn nested_field_creation_remote_config() {
        let mut cfg = Config::default();
        let mut b = PolicyBundle::empty();
        let k = key("RemoteConfig", "Url");
        b.machine.insert(
            k.clone(),
            PolicyValue::String("https://example/spt.toml".into()),
        );
        b.enforced.insert(k);
        PolicyOverlay::apply(&mut cfg, &b);
        assert_eq!(
            cfg.runtime
                .as_ref()
                .unwrap()
                .remote_config
                .as_ref()
                .unwrap()
                .url
                .as_deref(),
            Some("https://example/spt.toml")
        );
    }

    #[test]
    fn network_policy_creates_gateway_and_interface_tables() {
        let mut cfg = Config::default();
        let mut b = PolicyBundle::empty();
        b.machine.insert(
            key("Network", "DefaultInterface"),
            PolicyValue::String("eth0".into()),
        );
        b.machine.insert(
            key("Network", "DefaultGateway"),
            PolicyValue::String("192.0.2.1".into()),
        );
        b.machine.insert(
            key("Network", "RequireGatewayMatch"),
            PolicyValue::Bool(true),
        );
        b.machine.insert(
            key("Network", "LoadBalanceStrategy"),
            PolicyValue::String("weighted".into()),
        );
        let r = PolicyOverlay::apply(&mut cfg, &b);
        assert_eq!(r.applied.len(), 4);
        let network = cfg.network.as_ref().unwrap();
        assert_eq!(
            network
                .interface
                .as_ref()
                .unwrap()
                .default_interface
                .as_deref(),
            Some("eth0")
        );
        assert_eq!(
            network.gateway.as_ref().unwrap().default_gateway.as_deref(),
            Some("192.0.2.1")
        );
        assert_eq!(
            network.load_balance.as_ref().unwrap().strategy.as_deref(),
            Some("weighted")
        );
    }

    #[test]
    fn admx_aliases_map_to_runtime_mcp_and_logging() {
        let mut cfg = Config::default();
        let mut b = PolicyBundle::empty();
        b.machine.insert(
            key("Network", "RemoteConfigUrlPin"),
            PolicyValue::String("https://config.example/spt.toml".into()),
        );
        b.machine
            .insert(key("Network", "McpEnabled"), PolicyValue::Bool(true));
        b.machine.insert(
            key("Observability", "LogLevel"),
            PolicyValue::String("debug".into()),
        );
        b.machine.insert(
            key("Security", "SecretBackend"),
            PolicyValue::String("keychain".into()),
        );
        PolicyOverlay::apply(&mut cfg, &b);
        assert_eq!(
            cfg.runtime
                .as_ref()
                .unwrap()
                .remote_config
                .as_ref()
                .unwrap()
                .url
                .as_deref(),
            Some("https://config.example/spt.toml")
        );
        assert_eq!(cfg.mcp.as_ref().unwrap().enabled, Some(true));
        assert_eq!(
            cfg.logging.as_ref().unwrap().level.as_deref(),
            Some("debug")
        );
        assert_eq!(
            cfg.secrets.as_ref().unwrap().backend.as_deref(),
            Some("keychain")
        );
    }
}
