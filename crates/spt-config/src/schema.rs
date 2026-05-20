//! TOML schema types for `spt`'s configuration file.
//!
//! Every type in this module corresponds 1:1 to a table in `spec.md` §8/§9.
//! Field-level documentation includes the spec section that defines the field.
//!
//! ### Design choices
//!
//! * **No `#[serde(deny_unknown_fields)]`.** Unknown keys are detected through
//!   `serde_ignored` in [`crate::load::load_str`]; in strict mode they become
//!   errors, otherwise warnings. This keeps a single struct tree for both
//!   modes.
//! * **`Option<T>` everywhere** for missing-vs-default disambiguation, paired
//!   with `#[serde(skip_serializing_if = "Option::is_none")]` so the rendered
//!   TOML stays minimal and `load → render → load` is the identity on
//!   round-trips.
//! * **Durations and sizes are stored as strings** (`String`) and parsed
//!   on-demand by validators in [`crate::validate()`]. This avoids materializing
//!   defaults into `Some(default_duration)` during deserialize, which would
//!   inflate canonical output. The `spt-core::duration` and `spt-core::size`
//!   helpers do the actual parsing.
//! * **No `toml::Spanned<T>`** in the schema. When span-level diagnostics are
//!   needed, [`crate::validate()`] re-parses the raw source through `toml_edit`.

use serde::{Deserialize, Serialize};
use spt_core::RedactedString;

// ---------------------------------------------------------------------------
// Top-level config (spec §8)
// ---------------------------------------------------------------------------

/// Top-level configuration file. Maps to the entire TOML document.
///
/// Spec: §8 "Configuration Format" — the TOML root.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Schema version. Spec §8 — currently the only supported value is `1`.
    pub version: u32,

    /// `[runtime]` table. Spec §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<Runtime>,

    /// `[logging]` table. Spec §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<Logging>,

    /// `[secrets]` table. Spec §9.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Secrets>,

    /// `[dns]` table. Spec §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,

    /// `[firewall]` table. Spec §9.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<Firewall>,

    /// `[network]` table. Interface, gateway, offload, and load-balance policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,

    /// `[observability]` group. Spec §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<Observability>,

    /// `[events]` group. Spec §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Events>,

    /// `[mcp]` table. Spec §9.8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<Mcp>,

    /// `[diagnostics]` table. Spec §9.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<Diagnostics>,

    /// `[benchmark]` table. Spec §9.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark: Option<Benchmark>,

    /// `[round_robin]` — endpoint cycling configuration. Plan §t4-e4.
    ///
    /// Disabled by default (`enabled = false`). When enabled, the supervisor
    /// picks endpoints via the configured [`crate::SelectionPolicy`] instead
    /// of the legacy priority/weight failover selector.
    #[serde(default, skip_serializing_if = "is_default_round_robin")]
    pub round_robin: crate::round_robin::RoundRobinConfig,

    /// `[status_api]` — read-only HTTP/JSON status API. Plan §t4-e5.
    ///
    /// Disabled by default (`enabled = false`). When enabled, the supervisor
    /// spawns an HTTP listener that exposes the same status snapshot used by
    /// `spt tunnel stats` over a stable JSON API.
    #[serde(default, skip_serializing_if = "is_default_status_api")]
    pub status_api: crate::status_api::StatusApiConfig,

    /// `[[profiles]]` array. Spec §9.11.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<Profile>,
}

// ---------------------------------------------------------------------------
// [runtime] — spec §9.1
// ---------------------------------------------------------------------------

/// `[runtime]` table. Spec §9.1.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Runtime {
    /// `state_dir` — directory for status, locks, counters, and history. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<String>,
    /// `required_profiles` — profiles whose failure marks the process unhealthy. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_profiles: Option<Vec<String>>,
    /// `shutdown_grace` — drain time before forced close. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shutdown_grace: Option<String>,
    /// `profile_start_parallelism` — max profiles started concurrently. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_start_parallelism: Option<u32>,
    /// `file_lock` — single-supervisor file lock. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_lock: Option<bool>,

    /// `[runtime.threads]` sub-table. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads: Option<RuntimeThreads>,
    /// `[runtime.reload]` sub-table. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload: Option<RuntimeReload>,
    /// `[runtime.remote_config]` sub-table. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_config: Option<RuntimeRemoteConfig>,
}

/// `[runtime.threads]`. Spec §9.1, §17.2.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuntimeThreads {
    /// Threading model: `multi_thread` or `single_thread_for_tests`. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Orchestrator thread count (production: exactly 1). §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orchestrator_threads: Option<u32>,
    /// Service supervision worker threads. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_threads: Option<u32>,
    /// Logging/rotation worker threads. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging_threads: Option<u32>,
    /// DNS worker threads. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_threads: Option<u32>,
    /// Observability worker threads. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability_threads: Option<u32>,
    /// Blocking workers (libssh2, fs, keychain, OS service). §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_worker_threads: Option<u32>,
    /// Idle tick interval. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_tick: Option<String>,
}

/// `[runtime.reload]`. Spec §9.1, §11.4.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuntimeReload {
    /// Reload mode: `none|signal|watch|service`. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// File-watch debounce. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debounce: Option<String>,
    /// Reject invalid new config and keep old running. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_valid_config: Option<bool>,
    /// Restart only changed profiles on reload. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_changed_profiles: Option<bool>,
}

/// `[runtime.remote_config]`. Spec §9.1, §14.3.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuntimeRemoteConfig {
    /// Enable remote-config retrieval. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// HTTPS-only remote config URL. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Required SHA-256 fingerprint of fetched body. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<String>,
    /// Local atomic cache file. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_file: Option<String>,
    /// Use cached config when fetch fails. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_cached_on_failure: Option<bool>,
    /// Refresh interval for services. §9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_interval: Option<String>,

    // ---------------- Pinned-TLS surface (t5-e2) ----------------
    /// SPKI SHA-256 pin set for the remote-config HTTPS endpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pin_spki_sha256: Vec<String>,
    /// Allow self-signed certificates. Requires a non-empty pin set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_self_signed: Option<bool>,
    /// Maximum certificate-chain depth. Omitted maps to
    /// `DEFAULT_CHAIN_DEPTH_CAP` (`Some(5)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cert_chain_depth: Option<u32>,
}

// ---------------------------------------------------------------------------
// [logging] — spec §9.2
// ---------------------------------------------------------------------------

/// `[logging]` table. Spec §9.2.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Logging {
    /// Log level (`trace|debug|info|warn|error`). §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Format: `compact|pretty|json`. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Active destinations. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destinations: Option<Vec<String>>,
    /// Path of file destination. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Rotation policy: `size|daily|hourly|none`. §9.2 / §13.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate: Option<String>,
    /// Max file size for size-based rotation. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<String>,
    /// Maximum retained rotated files. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_files: Option<u32>,
    /// Maximum age of rotated files. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<String>,
    /// Compress rotated files. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compress_rotated: Option<bool>,
    /// Rotation tick. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_check_interval: Option<String>,
    /// Redaction profile list. §9.2 / §13.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redact: Option<Vec<String>>,

    /// `[[logging.remote]]` sinks. §9.2 / §13.7.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote: Vec<LoggingRemote>,
}

/// `[[logging.remote]]` entry. Spec §9.2 / §13.7.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LoggingRemote {
    /// Sink name (unique). §9.2.
    pub name: String,
    /// Sink type: `syslog_udp|syslog_tcp|syslog_tls|https_jsonl|otlp`. §9.2.
    #[serde(rename = "type")]
    pub kind: String,
    /// Endpoint host:port or URL. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Syslog facility (0..23). §13.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility: Option<u8>,
    /// Syslog APP-NAME. §13.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    /// Syslog HOSTNAME. §13.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Syslog structured data enterprise ID. §13.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_id: Option<u32>,
    /// CA bundle file for TLS validation. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
    /// TLS SNI / verification name override. §13.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// TLS client certificate chain. §13.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<String>,
    /// TLS client private key. §13.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key: Option<String>,
    /// Disable TLS certificate verification. §13.7.
    ///
    /// **Deprecated:** renamed to `allow_self_signed`. The old name is
    /// still accepted but emits a deprecation warning via the validator;
    /// new configs should use `allow_self_signed` together with a
    /// non-empty `pin_spki_sha256` set (t5-e2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_invalid_certs: Option<bool>,
    /// Allow self-signed certificates. Requires a non-empty
    /// `pin_spki_sha256` set — `spt_trust::PinnedTlsConnector` refuses
    /// to build a fully-unauthenticated client. t5-e2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_self_signed: Option<bool>,
    /// SPKI SHA-256 pin set (each pin in `SHA256:<base64>` or hex form).
    /// Empty by default — strict system-roots verification still applies.
    /// t5-e2.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pin_spki_sha256: Vec<String>,
    /// Maximum permitted certificate-chain depth (intermediates between
    /// leaf and trust anchor). Omitted maps to
    /// [`spt_trust::DEFAULT_CHAIN_DEPTH_CAP`] at the runtime via
    /// `ChainDepthCap::from_option(...).or_default_if_unlimited_was_absent()`.
    /// t5-e2 / t5-e10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cert_chain_depth: Option<u32>,
    /// Auth secret reference. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// Per-batch timeout. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    /// Reconnect backoff for reliable transports. §13.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_backoff: Option<String>,
    /// Disk spool directory for reliable transports. §13.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spool_dir: Option<String>,
    /// Disk spool byte limit. §13.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spool_max_bytes: Option<String>,
    /// In-memory queue record limit. §13.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_max_records: Option<u32>,
    /// Records per batch. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<u32>,
    /// Whether sink failure must block forwarding. §9.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

// ---------------------------------------------------------------------------
// [secrets] — spec §9.3
// ---------------------------------------------------------------------------

/// `[secrets]` table. Spec §9.3.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Secrets {
    /// Backend: `auto|keychain|vault|env`. §9.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Local vault file path. §9.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_file: Option<String>,
    /// Encrypt-at-rest toggle. §9.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypt_at_rest: Option<bool>,
    /// Memory protection: `best_effort|strict|none`. §9.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_protection: Option<String>,
    /// Keychain namespace. §9.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keychain_namespace: Option<String>,
}

// ---------------------------------------------------------------------------
// [dns] — spec §9.4
// ---------------------------------------------------------------------------

/// `[dns]` table. Spec §9.4.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Dns {
    /// Enable transparent resolver. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Mode: `disabled|transparent_forwarder|synthetic_only|hosts_file`. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Listener bind. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    /// Default zone for synthesized records. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Default TTL. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Auto-derive records from forward `dns_names`. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_records: Option<bool>,
    /// Upstream resolvers. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<Vec<String>>,
    /// Hosts-file path. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts_file: Option<String>,
    /// Hosts-file mode: `render_only|apply|restore`. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts_file_mode: Option<String>,
    /// `[[dns.records]]` entries. §9.4.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<DnsRecord>,
}

/// `[[dns.records]]`. Spec §9.4.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Owner name (FQDN). §9.4.
    pub name: String,
    /// Record type: `A|AAAA|SRV|TXT`. §9.4.
    #[serde(rename = "type")]
    pub kind: String,
    /// Record value (IP for A/AAAA, target string for SRV/TXT). §9.4.
    pub value: String,
    /// Per-record TTL. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// SRV priority. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    /// SRV weight. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
    /// SRV port. §9.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

// ---------------------------------------------------------------------------
// [firewall] — spec §9.5
// ---------------------------------------------------------------------------

/// `[firewall]` table. Spec §9.5.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Firewall {
    /// Enable firewall planning. §9.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Manager: `auto|nftables|iptables|pf|windows_firewall|none`. §9.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
    /// Apply rules (otherwise plan-only). §9.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_rules: Option<bool>,
    /// Bind policy: `explicit|loopback_only|any`. §9.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_policy: Option<String>,
    /// Default interface name. §9.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_interface: Option<String>,
    /// Allow `0.0.0.0`/`::` binds. §9.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_all_interfaces: Option<bool>,
    /// `[firewall.platform]`. §9.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<FirewallPlatform>,
}

/// `[firewall.platform]`. Spec §9.5.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FirewallPlatform {
    /// Linux planner: `auto|nftables|iptables|none`. §9.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux: Option<String>,
    /// macOS planner: `pf|none`. §9.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos: Option<String>,
    /// Windows planner: `windows_firewall|none`. §9.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<String>,
}

// ---------------------------------------------------------------------------
// [network]
// ---------------------------------------------------------------------------

/// `[network]` table. Host network policy used by bind, gateway and
/// load-balancing decisions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Network {
    /// `[network.interface]` policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<NetworkInterface>,
    /// `[network.gateway]` policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<NetworkGateway>,
    /// `[network.offload]` socket/kernel offload policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offload: Option<NetworkOffload>,
    /// `[network.load_balance]` endpoint load-balancing defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balance: Option<NetworkLoadBalance>,
}

/// `[network.interface]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Default interface name used by auto-interface bind decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_interface: Option<String>,
    /// Interface allow-list. Enforced policies intersect with local config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_interfaces: Option<Vec<String>>,
    /// Interface deny-list. Operators use this to reject known-bad adapters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_interfaces: Option<Vec<String>>,
    /// Require every non-loopback forward to set `bind_interface` or
    /// `bind_interface_preference`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_explicit_interface: Option<bool>,
    /// Permit wildcard binds (`0.0.0.0`/`::`) when also acknowledged by
    /// per-forward `expose = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_all_interfaces: Option<bool>,
    /// Default IPv6 bind behavior: `auto|prefer|disable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_ipv6: Option<String>,
}

/// `[network.gateway]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkGateway {
    /// Default gateway address or route alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_gateway: Option<String>,
    /// Interface expected to own the selected gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Target host/IP used to check route selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_check_target: Option<String>,
    /// Require the chosen route to match `interface` before starting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_gateway_match: Option<bool>,
    /// Gateway policy: `disabled|default_route|interface_only|route_to_target`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

/// `[network.offload]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkOffload {
    /// Set `TCP_NODELAY` on TCP sockets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_nodelay: Option<bool>,
    /// Enable socket keepalive where supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_keepalive: Option<bool>,
    /// Request TCP Fast Open where supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_fast_open: Option<bool>,
    /// Reuse listener ports where the platform supports safe reuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse_port: Option<bool>,
    /// Permit io_uring-backed filesystem/network operations on Linux.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_uring: Option<bool>,
    /// Permit zero-copy send paths where available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zerocopy: Option<bool>,
    /// Permit sendfile-style transfer paths where available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sendfile: Option<bool>,
    /// Require/allow NIC checksum offload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_offload: Option<bool>,
    /// Require/allow large-send/TSO offload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub large_send_offload: Option<bool>,
}

/// `[network.load_balance]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkLoadBalance {
    /// Strategy: `priority|weighted|round_robin|least_connections|manual`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    /// Keep a client/session pinned to its selected endpoint while healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sticky_sessions: Option<bool>,
    /// Health check style: `tcp_connect|ssh_handshake|ssh_auth_preflight|ssh3_endpoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<String>,
    /// Consecutive failures before an endpoint leaves rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_after: Option<u32>,
    /// Delay before an endpoint is eligible for restore/failback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_after: Option<String>,
    /// Rebalance interval for strategies that actively redistribute sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebalance_interval: Option<String>,
}

// ---------------------------------------------------------------------------
// [observability] — spec §9.6
// ---------------------------------------------------------------------------

/// `[observability]` group. Spec §9.6.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Observability {
    /// `[observability.metrics]`. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<ObservabilityMetrics>,
    /// `[observability.snmp]`. §9.6 / §13.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snmp: Option<ObservabilitySnmp>,
    /// `[observability.windows_event]`. §9.6 / §13.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_event: Option<ObservabilityWindowsEvent>,
}

/// `[observability.metrics]`. Spec §9.6 / §13.8.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ObservabilityMetrics {
    /// Enable metrics. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Format: `prometheus|json`. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// State file path. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_file: Option<String>,
}

/// `[observability.snmp]`. Spec §9.6 / §13.9.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ObservabilitySnmp {
    /// Enable SNMP agent. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// SNMP version: must be `v3`. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Bind address. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    /// SNMP engine ID (hex). §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,
    /// IANA Private Enterprise Number used for the spt enterprise subtree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_id: Option<u32>,
    /// Trap sink names. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_sinks: Option<Vec<String>>,
    /// `[[observability.snmp.traps]]`. §9.6.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub traps: Vec<SnmpTrap>,
}

/// `[[observability.snmp.traps]]`. Spec §9.6.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SnmpTrap {
    /// Trap sink name (matches `trap_sinks`). §9.6.
    pub name: String,
    /// Trap destination (host:port). §9.6.
    pub endpoint: String,
    /// USM user. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// USM auth secret. §9.6.
    ///
    /// Wrapped in [`RedactedString`] so the value never leaks via the
    /// derived `Debug` of any containing struct and the heap allocation
    /// is zeroed on drop. Serialize/Deserialize remain transparent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_secret: Option<RedactedString>,
    /// USM privacy secret. §9.6.
    ///
    /// See [`Self::auth_secret`] for the redaction contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_secret: Option<RedactedString>,
}

/// `[observability.windows_event]`. Spec §9.6 / §13.10.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ObservabilityWindowsEvent {
    /// Enable Windows Event Log writes. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Event source name. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Channel: typically `Application`. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Auto-install event source. §9.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_source: Option<bool>,
}

// ---------------------------------------------------------------------------
// [events] — spec §9.7
// ---------------------------------------------------------------------------

/// `[events]` group. Spec §9.7.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Events {
    /// `[[events.bindings]]`. §9.7 / §13.11.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<EventBinding>,
    /// `[[events.sinks]]`. §9.7.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sinks: Vec<EventSink>,
    /// `[[events.commands]]`. §9.7.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<EventCommand>,
}

/// `[[events.bindings]]`. Spec §9.7.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EventBinding {
    /// Binding identifier. §9.7.
    pub name: String,
    /// Subscribed event categories (e.g. `profile.failed`). §9.7 / §13.2.
    pub on: Vec<String>,
    /// Sink/command names to fire. §9.7.
    pub actions: Vec<String>,
    /// Minimum severity. §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_level: Option<String>,
    /// Per-binding throttle. §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttle: Option<String>,
}

/// `[[events.sinks]]`. Spec §9.7.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EventSink {
    /// Sink name. §9.7.
    pub name: String,
    /// Sink type: `email|sms|push|http|webhook_post|snmp_trap|windows_event|mcp_notify|remote_log`. §9.7.
    #[serde(rename = "type")]
    pub kind: String,
    /// SMTP endpoint (for `email`). §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smtp: Option<String>,
    /// From address (for `email`). §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Recipient list. §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    /// Auth reference (`secret://…`). §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// Provider hint for SMS/push. §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Endpoint URL (push/http). §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Endpoint URL alias (push). §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// HTTP method. §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// HTTP content type. §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Per-call timeout. §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,

    // ---------------- WebPush (`kind = "webpush"`) ---------------- §9.7
    /// VAPID private key (base64url-no-padding-encoded 32-byte scalar).
    /// May also be a `secret://ns/name` reference resolved at runtime.
    ///
    /// Wrapped in [`RedactedString`] — see `spt-core::redacted_string`
    /// for the Debug/Drop/serde contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vapid_private_key: Option<RedactedString>,
    /// VAPID `sub` claim — usually a `mailto:` URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vapid_subject: Option<String>,
    /// Body template (a `{{var}}` template rendered against the event).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_template: Option<String>,
    /// Push subscriptions. Each entry is a JSON object with
    /// `endpoint`, `p256dh`, `auth` (the standard `PushSubscription` fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscriptions: Option<Vec<EventSinkSubscription>>,

    // ---------------- Pinned-TLS surface (t5-e2) ----------------
    /// SPKI SHA-256 pin set for the sink's HTTPS / SMTP endpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pin_spki_sha256: Vec<String>,
    /// Allow self-signed certificates for the sink endpoint. Requires
    /// a non-empty `pin_spki_sha256` set at runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_self_signed: Option<bool>,
    /// Maximum certificate-chain depth. Omitted maps to
    /// `DEFAULT_CHAIN_DEPTH_CAP` (`Some(5)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cert_chain_depth: Option<u32>,
}

/// Subset of a Push API `PushSubscription` we persist. §9.7.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EventSinkSubscription {
    /// Subscription endpoint URL.
    pub endpoint: String,
    /// Browser-supplied P256 ECDH key (base64url-no-padding).
    pub p256dh: String,
    /// Browser-supplied auth secret (base64url-no-padding, 16 bytes).
    ///
    /// Wrapped in [`RedactedString`] — this is the per-subscription
    /// shared secret used by the `WebPush` content-encoding key derivation
    /// (`RFC 8291` §3.2). Compromise of this byte string permits decrypting
    /// every push payload sent to that subscription.
    pub auth: RedactedString,
}

/// `[[events.commands]]`. Spec §9.7.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EventCommand {
    /// Command identifier. §9.7.
    pub name: String,
    /// Allow-listed executable path. §9.7.
    pub command: String,
    /// Argument template. §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Required to set `allow_exec = true` to fire. §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_exec: Option<bool>,
    /// Execution timeout. §9.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}

// ---------------------------------------------------------------------------
// [mcp] — spec §9.8
// ---------------------------------------------------------------------------

/// `[mcp]` table. Spec §9.8 / §16.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Mcp {
    /// Master enable. §9.8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Default mode: `read_only|read_write`. §9.8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_mode: Option<String>,
    /// Use stdio transport. §9.8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdio: Option<bool>,
    /// Loopback TCP listen address (empty = stdio only). §9.8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Allow secret reveal (must remain false). §9.8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_secret_reveal: Option<bool>,
    /// Allow-listed write tools. §9.8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_write_tools: Option<Vec<String>>,
    /// Emit audit events for tool calls. §9.8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_events: Option<bool>,
    /// Required for non-loopback binds. §9.8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose: Option<bool>,

    // ---------------- Pinned-TLS surface (t5-e2) ----------------
    /// SPKI SHA-256 pin set for any HTTPS endpoint the MCP-notify path
    /// posts to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pin_spki_sha256: Vec<String>,
    /// Allow self-signed certificates. Requires a non-empty pin set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_self_signed: Option<bool>,
    /// Maximum certificate-chain depth. Omitted maps to
    /// `DEFAULT_CHAIN_DEPTH_CAP` (`Some(5)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cert_chain_depth: Option<u32>,
}

// ---------------------------------------------------------------------------
// [diagnostics] — spec §9.9
// ---------------------------------------------------------------------------

/// `[diagnostics]` table. Spec §9.9.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Diagnostics {
    /// Bundle output directory. §9.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_dir: Option<String>,
    /// Include recent log tail. §9.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_recent_logs: Option<bool>,
    /// Include status snapshot. §9.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_status: Option<bool>,
    /// Include stats snapshot. §9.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_stats: Option<bool>,
    /// Include session details. §9.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_sessions: Option<bool>,
    /// Include service definition copies. §9.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_service_definitions: Option<bool>,
    /// Redact bundle by default. §9.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redact: Option<bool>,
    /// Maximum bundle size. §9.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bundle_size: Option<String>,
}

// ---------------------------------------------------------------------------
// [benchmark] — spec §9.10
// ---------------------------------------------------------------------------

/// `[benchmark]` table. Spec §9.10.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Benchmark {
    /// Master enable. §9.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Default test duration. §9.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_duration: Option<String>,
    /// Maximum allowed duration. §9.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration: Option<String>,
    /// Maximum concurrent test connections. §9.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    /// Maximum byte rate per direction. §9.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_second: Option<String>,
    /// Maximum packet rate. §9.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_packets_per_second: Option<u32>,
    /// Refuse benchmarks without `--target` profile/forward. §9.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_explicit_target: Option<bool>,
    /// Permit production-impacting tests. §9.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_production_impact: Option<bool>,
    /// Results directory. §9.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results_dir: Option<String>,
}

// ---------------------------------------------------------------------------
// [[profiles]] — spec §9.11
// ---------------------------------------------------------------------------

/// A profile entry. Spec §9.11 — `[[profiles]]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Profile id (must be unique). §9.11.
    pub name: String,
    /// Profile description. Optional convenience field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether this profile is started. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Protocol: `ssh2|ssh3`. §9.11 / §4.
    pub protocol: String,
    /// SSH2 host. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// SSH2 port (default 22). §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// SSH3 endpoint URL. §9.11 / §4.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// SSH3 experimental acknowledgement. §9.11 / §14.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledge_experimental: Option<bool>,
    /// Remote user. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Connection timeout (legacy top-level alias). §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<String>,
    /// DNS resolution policy: `per_attempt|once`. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_resolution: Option<String>,
    /// Force reconnect on network change. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_change_reconnect: Option<bool>,
    /// Startup behaviour: `eager|lazy`. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup: Option<String>,
    /// Failure policy: `retry|fail_profile|fail_process`. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_policy: Option<String>,
    /// Free-form tags. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// `[profiles.connection]`. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<Connection>,
    /// `[profiles.crypto]`. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto: Option<Crypto>,
    /// `[profiles.auth]`. §9.12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Auth>,
    /// `[profiles.trust]`. §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<Trust>,
    /// `[profiles.tls]`. §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
    /// `[profiles.ssh3]`. §9.11 / §4.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh3: Option<Ssh3>,
    /// `[profiles.keepalive]`. §11.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<Keepalive>,
    /// `[profiles.reconnect]`. §11.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect: Option<Reconnect>,
    /// `[profiles.instability]`. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instability: Option<Instability>,
    /// `[profiles.failover]`. §11.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failover: Option<Failover>,
    /// `[profiles.limits]`. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,

    /// `[[profiles.endpoints]]`. §9.11 / §11.5.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<Endpoint>,
    /// `[[profiles.hops]]`. §8.2 (multi-hop).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hops: Vec<Hop>,
    /// `[[profiles.forwards]]`. §9.14.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<Forward>,
}

/// `[profiles.connection]`. Spec §9.11.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)] // every field documented inline by spec section
pub struct Connection {
    /// TCP connect timeout. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<String>,
    /// SSH/QUIC auth timeout. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_timeout: Option<String>,
    /// Handshake timeout. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_timeout: Option<String>,
    /// Channel-open timeout. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_open_timeout: Option<String>,
    /// SSH channel window size. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_window_size: Option<String>,
    /// Maximum SSH channel packet size. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_max_packet_size: Option<String>,
    /// Set `TCP_NODELAY` on listeners. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_nodelay: Option<bool>,
    /// Enable socket-level keepalive. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_keepalive: Option<bool>,
    /// Idle time before keepalive. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_idle: Option<String>,
    /// Keepalive probe interval. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_interval: Option<String>,
    /// Keepalive retries before drop. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_retries: Option<u32>,
    /// Per-read timeout (`0s` = unbounded). §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_timeout: Option<String>,
    /// Per-write timeout (`0s` = unbounded). §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_timeout: Option<String>,
}

/// `[profiles.crypto]`. Spec §9.11.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Crypto {
    /// Policy: `modern|interop|legacy`. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Allow deprecated algorithms. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_deprecated: Option<bool>,
    /// Warn when deprecated algorithms negotiated. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_on_deprecated: Option<bool>,
    /// Cipher allow-list (empty = policy default). §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphers: Option<Vec<String>>,
    /// KEX allow-list. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kex_algorithms: Option<Vec<String>>,
    /// MAC allow-list. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macs: Option<Vec<String>>,
    /// Host-key algorithm allow-list. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_algorithms: Option<Vec<String>>,
    /// Compression list. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression: Option<Vec<String>>,
}

/// `[profiles.auth]`. Spec §9.12.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Auth {
    /// Auth method (see spec §9.12 for the full enumeration). §9.12.
    pub method: String,
    /// SSH2 identity file. §9.12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    /// Optional OpenSSH certificate. §9.12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_file: Option<String>,
    /// Identity passphrase reference. §9.12.
    ///
    /// Wrapped in [`RedactedString`]: a config value here is *usually* a
    /// `secret://…` reference (the cleartext lives in the keychain or
    /// vault) but plaintext is permitted for ephemeral test rigs. Either
    /// way the value must not leak via `Debug` and must zero on drop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<RedactedString>,
    /// SSH2 password reference. §9.12.
    ///
    /// See [`Self::passphrase`] for the redaction contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<RedactedString>,
    /// SSH3 bearer token reference. §9.12.
    ///
    /// See [`Self::passphrase`] for the redaction contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<RedactedString>,
    /// SSH2 agent flag. §9.12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<bool>,
    /// SSH2 agent identity hint. §9.12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_hint: Option<String>,
    /// SSH2 keyboard-interactive fallback. §9.12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyboard_interactive: Option<bool>,
    /// OIDC issuer (SSH3). §9.12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_issuer: Option<String>,
    /// OIDC client id (SSH3). §9.12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_client_id: Option<String>,
}

/// `[profiles.trust]`. Spec §9.13.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Trust {
    /// Trust mode: `known_hosts|pinned`. §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Path to `known_hosts`. §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_hosts_file: Option<String>,
    /// Strict verification. §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
    /// Accept unknown new keys. §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_new: Option<bool>,
    /// SHA-256 host-key pins. §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_sha256: Option<Vec<String>>,
}

/// `[profiles.tls]`. Spec §9.13.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Tls {
    /// SNI / verification name. §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// Use system root store. §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_roots: Option<bool>,
    /// Optional CA bundle file. §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
    /// SHA-256 cert pins. §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_sha256: Option<Vec<String>>,
    /// Allow self-signed (requires pin or `ca_file` in strict mode). §9.13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_self_signed: Option<bool>,
    /// Maximum permitted certificate-chain depth (number of intermediates
    /// between leaf and trust anchor). When omitted, the runtime applies
    /// `spt_trust::DEFAULT_CHAIN_DEPTH_CAP` (currently `5`). Set
    /// explicitly to `0` to disallow any intermediates, or to a higher
    /// value to relax the cap. §9.13 / t5-e10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cert_chain_depth: Option<u32>,
}

/// `[profiles.ssh3]`. Spec §9.11 / §4.2.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Ssh3 {
    /// Reference draft identifier. §4.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<String>,
    /// HTTP/3 protocol token (Extended CONNECT). §4.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_token: Option<String>,
    /// Enable QUIC datagrams (UDP forwarding). §4.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_datagrams: Option<bool>,
    /// QUIC idle timeout. §4.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,
    /// QUIC keepalive. §4.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<String>,
    /// QUIC max bidi streams. §4.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<u32>,
}

/// `[profiles.keepalive]`. Spec §11.3.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Keepalive {
    /// Interval between probes. §11.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// Per-probe timeout. §11.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    /// Maximum missed probes before session replace. §11.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_missed: Option<u32>,
}

/// `[profiles.reconnect]`. Spec §11.2.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Reconnect {
    /// First retry delay. §11.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_delay: Option<String>,
    /// Maximum delay (cap). §11.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delay: Option<String>,
    /// Jitter percentage. §11.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter: Option<String>,
    /// Reset backoff after this stable time. §11.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_after: Option<String>,
    /// Maximum retries (`0` = unlimited). §11.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_attempts: Option<u32>,
    /// Retry on auth failure. §11.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_auth_failures: Option<bool>,
}

/// `[profiles.instability]`. Spec §9.11.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Instability {
    /// Detection enabled. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Sliding window. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
    /// Max disconnects within window. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_disconnects: Option<u32>,
    /// Max keepalive misses. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_keepalive_misses: Option<u32>,
    /// Max p95 latency. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_latency_p95: Option<String>,
    /// Minimum healthy uptime to clear flag. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_successful_uptime: Option<String>,
    /// Action: `mark_degraded|failover|increase_keepalive|increase_backoff|emit_event|restart_session`. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

/// `[profiles.failover]`. Spec §11.5.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Failover {
    /// Mode: `priority|weighted|manual`. §11.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Health check style: `tcp_connect|ssh_handshake|ssh_auth_preflight|ssh3_endpoint`. §11.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<String>,
    /// Trigger after this many consecutive failures. §11.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_after: Option<u32>,
    /// Restore window before failback. §11.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_after: Option<String>,
}

/// `[profiles.limits]`. Spec §9.11.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    /// Active connections. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_active_connections: Option<u32>,
    /// Accept rate (per second). §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_new_connections_per_second: Option<u32>,
    /// Inbound byte rate. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_second_in: Option<String>,
    /// Outbound byte rate. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_second_out: Option<String>,
    /// Inbound bit-rate (display only). §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bits_per_second_in: Option<String>,
    /// Outbound bit-rate (display only). §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bits_per_second_out: Option<String>,
    /// Throttle algorithm. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttle_algorithm: Option<String>,
    /// Maximum connection lifetime. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connection_lifetime: Option<String>,
}

/// `[[profiles.endpoints]]`. Spec §9.11 / §11.5.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Endpoint identifier. §9.11.
    pub name: String,
    /// Hostname. §9.11.
    pub host: String,
    /// Port. §9.11.
    pub port: u16,
    /// Lower-is-better priority. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    /// Weighted-failover weight. §9.11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
}

/// `[[profiles.hops]]`. Spec §8.2.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Hop {
    /// Hop identifier. §8.2.
    pub name: String,
    /// Protocol used to reach this hop. §8.2.
    pub protocol: String,
    /// Hop hostname. §8.2.
    pub host: String,
    /// Hop port. §8.2.
    pub port: u16,
    /// Remote user on this hop. §8.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Hop-local `[profiles.hops.auth]`. Falls back to profile auth when unset. §8.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Auth>,
    /// Hop-local `[profiles.hops.trust]`. Falls back to profile trust when unset. §8.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<Trust>,
    /// Where to resolve names: `local|remote|previous-hop`. §8.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_resolve: Option<String>,
}

/// `[[profiles.forwards]]`. Spec §9.14.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Forward {
    /// Forward id (unique within profile). §9.14.
    pub name: String,
    /// `local` or `remote`. §9.14.
    #[serde(rename = "type")]
    pub kind: String,
    /// `tcp` or `udp`. §9.14.
    pub transport: String,
    /// Canonical bind. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    /// Bind mode: `loopback|specific_ip|specific_interface|all_interfaces|auto_interface`. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_mode: Option<String>,
    /// Bind interface name. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
    /// Interface preference list (auto). §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface_preference: Option<Vec<String>>,
    /// IPv6 behaviour: `auto|prefer|disable`. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_ipv6: Option<String>,
    /// Required for non-loopback binds. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose: Option<bool>,
    /// Canonical target. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Friendly alias for `bind`. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Friendly alias for `target`. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<String>,
    /// DNS names to register. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_names: Option<Vec<String>>,
    /// SNI hint for TLS clients. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni_name: Option<String>,
    /// Where to resolve target. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_resolve: Option<String>,
    /// Required vs degraded-allowed. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    /// Idle timeout (TCP/UDP). §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,
    /// Per-forward connection cap. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    /// Bind conflict policy: `fail|retry|next_port`. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_bind_conflict: Option<String>,
    /// Inbound byte rate. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_second_in: Option<String>,
    /// Outbound byte rate. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_second_out: Option<String>,
    /// Accept rate (per second). §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_new_connections_per_second: Option<u32>,
    /// Burst size inbound. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_burst_bytes_in: Option<String>,
    /// Burst size outbound. §9.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_burst_bytes_out: Option<String>,
    /// UDP per-flow idle. §10.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_idle_timeout: Option<String>,
    /// Maximum UDP datagram size. §10.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_datagram_size: Option<u32>,
    /// UDP packet rate. §10.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_packets_per_second: Option<u32>,
}

// ---------------------------------------------------------------------------
// `skip_serializing_if` helpers — keep canonical render minimal when the
// optional sub-tables are at their defaults (added by t4-Bwire).
// ---------------------------------------------------------------------------

fn is_default_round_robin(v: &crate::round_robin::RoundRobinConfig) -> bool {
    v == &crate::round_robin::RoundRobinConfig::default()
}

fn is_default_status_api(v: &crate::status_api::StatusApiConfig) -> bool {
    v == &crate::status_api::StatusApiConfig::default()
}
