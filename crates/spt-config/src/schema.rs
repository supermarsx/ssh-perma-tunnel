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
use spt_secrets::SecretRef;

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

    /// `[updater]` table. Embedded auto-updater (`spt update` + optional
    /// background polling thread). **Disabled by default** — every field
    /// has a sensible default that only matters once `enabled = true`.
    /// See `docs/updater.md` for the full schema reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updater: Option<Updater>,

    /// `[diagnostics]` table. Spec §9.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<Diagnostics>,

    /// `[benchmark]` table. Spec §9.10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark: Option<Benchmark>,

    /// `[capabilities]` table. Fleet/admin feature gates for optional
    /// protocol, proxy, filesystem, and Windows management surfaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,

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
    /// `spt_trust::DEFAULT_CHAIN_DEPTH_CAP` at the runtime via
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
    /// Subject-line template for `email` sinks ({{var}} rendered against the
    /// event, same engine as `body_template`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_template: Option<String>,
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
// [updater] — embedded auto-updater (off by default)
// ---------------------------------------------------------------------------

/// `[updater]` table. Drives the `spt update` CLI surface and the optional
/// background polling thread that the supervisor spawns when
/// `enabled = true`. Both the background thread and the auto-install path
/// are **off by default**: a fresh config file with no `[updater]` block
/// (or an empty one) gets zero update activity. The operator must
/// explicitly opt in.
///
/// See `docs/updater.md` for the full reference.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Updater {
    /// Master switch for the background polling thread. **Default: `false`**.
    /// When false, the supervisor does not spawn the updater task at all,
    /// but manual `spt update *` commands still work — they read this
    /// block for source/verification settings only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// What the background thread does when it ticks. **Default: `"off"`**.
    /// One of:
    ///
    /// * `"off"`    — supervisor refuses to spawn the thread even if
    ///   `enabled = true` (belt-and-braces).
    /// * `"check"`  — poll for new versions, expose via `spt update status`.
    /// * `"warn"`   — `check` + emit a `tracing::warn!` and an audit event
    ///   so operators see a banner in their log pipeline.
    /// * `"auto"`   — `warn` + download + verify + atomic install +
    ///   supervisor restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// 5-field cron expression for the polling schedule. Mutually exclusive
    /// with [`Self::interval`]. **Default: `"0 6 * * *"`** (06:00 UTC daily).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,

    /// `humantime`-parsed interval (e.g. `"24h"`, `"7d"`). Mutually
    /// exclusive with [`Self::schedule`]. When both are set, the
    /// load-time validator rejects the config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,

    /// Release source kind. **Default: `"github"`**.
    ///
    /// * `"github"` — query `api.github.com/repos/{repo}/releases/latest`.
    /// * `"url"`    — HTTPS GET on a configured release-manifest URL with
    ///   an SHA-256 pin (`url_fingerprint`).
    /// * `"static"` — `file://` directory (offline mirrors, smoke tests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// `<owner>/<repo>` for `source = "github"`. **Default:
    /// `"supermarsx/ssh-perma-tunnel"`**.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_repo: Option<String>,

    /// `"stable"` (skip pre-releases) or `"prerelease"` (include them).
    /// **Default: `"stable"`**.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_channel: Option<String>,

    /// HTTPS URL of the release manifest for `source = "url"`. Must include
    /// the literal `{version}` and `{target}` placeholders so the updater
    /// can synthesise per-artifact URLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// HTTPS URL of the release-manifest.json sibling for `source = "url"`.
    /// Defaults to deriving from [`Self::url`] by stripping the artifact
    /// pattern and appending `release-manifest.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_index: Option<String>,

    /// Required SHA-256 pin for the `release-manifest.json` body when
    /// `source = "url"`. Mirrors `[remote_config].fingerprint_sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_fingerprint: Option<String>,

    /// Local directory of release artifacts for `source = "static"`.
    /// Layout matches `dist/<version>/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_dir: Option<String>,

    /// `[updater.window]` — auto-install maintenance window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<UpdaterWindow>,

    /// `[updater.staging]` — where staged artifacts land + retention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staging: Option<UpdaterStaging>,

    /// `[updater.verify]` — artifact-verification policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<UpdaterVerify>,

    /// `[updater.action]` — post-install actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<UpdaterAction>,
}

/// `[updater.window]`. Auto-install only fires inside this window. Omit
/// the whole block (or set both `allow_from` and `allow_to` to `None`) to
/// allow install at any tick.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UpdaterWindow {
    /// HH:MM start (24-hour). Default: unset (any time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_from: Option<String>,
    /// HH:MM end (24-hour). Default: unset (any time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_to: Option<String>,
    /// IANA timezone for the window (`"UTC"`, `"America/Los_Angeles"`).
    /// **Default: `"UTC"`**.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// `[updater.staging]`. Where downloaded artifacts land before swap.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UpdaterStaging {
    /// Staging directory. **Default: `<state_dir>/updates`**.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// How many past staged builds to keep. **Default: `3`**.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_last: Option<u32>,
}

/// `[updater.verify]`. Signature + checksum requirements. Defaults are
/// strict — the operator can opt out for private mirrors that don't
/// replay signatures (the runtime emits a `tracing::warn!` whenever a
/// downloaded artifact is installed without a minisign check).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UpdaterVerify {
    /// Refuse to install without a valid minisign signature.
    /// **Default: `true`**. Operator can flip to `false` for mirrors that
    /// don't replay signatures, accepting weaker provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_minisign: Option<bool>,
    /// Path to the minisign public key the operator trusts.
    /// Required when `require_minisign = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minisign_pubkey: Option<String>,
    /// Refuse to install if the artifact's SHA-256 doesn't match
    /// `SHA256SUMS`. **Default: `true`**.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_sha256sums: Option<bool>,
    /// Optional GPG public key for the `SHA256SUMS.asc` detached
    /// signature. When present, GPG verification becomes mandatory too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpg_pubkey: Option<String>,
}

/// `[updater.action]`. What happens after a successful install.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UpdaterAction {
    /// Send the supervisor a `tunnel reload` (SIGHUP / MCP RPC) after a
    /// successful install so the new binary takes effect without manual
    /// intervention. **Default: `true`**.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_supervisor: Option<bool>,
    /// Emit a structured audit event on every install. **Default: `true`**.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_audit: Option<bool>,
    /// Optional executable run after install + restart. Receives the new
    /// version in `$SPT_UPDATE_VERSION` and the staged artifact path in
    /// `$SPT_UPDATE_ARTIFACT`. Default: unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_install_hook: Option<String>,
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
// [capabilities] — fleet feature gates
// ---------------------------------------------------------------------------

/// `[capabilities]` table.
///
/// These fields are intended to be controlled either in config or through the
/// Windows GPO overlay. They gate higher-risk optional surfaces while the core
/// tunnel runtime remains CLI/config-only.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Capabilities {
    /// SSH2 backend policy: `russh` (production target) or `libssh2` (legacy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh2_backend: Option<String>,
    /// Permit legacy libssh2 SSH2 backend during migration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_libssh2: Option<bool>,
    /// Permit SSH GSSAPI/Kerberos authentication and key exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_gssapi: Option<bool>,
    /// Permit Windows SSPI/Negotiate authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_sspi: Option<bool>,
    /// Permit GSSAPI credential delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_gssapi_delegation: Option<bool>,
    /// Permit NTLM fallback through SSPI/Negotiate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_ntlm_fallback: Option<bool>,
    /// Permit post-quantum SSH key exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_post_quantum_kex: Option<bool>,
    /// Permit ML-KEM hybrid SSH key exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_ml_kem: Option<bool>,
    /// Require post-quantum SSH key exchange for eligible SSH2 profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_post_quantum_kex: Option<bool>,
    /// Permit dynamic SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT proxy listeners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_dynamic_proxy: Option<bool>,
    /// Permit SFTP operations over SSH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_sftp: Option<bool>,
    /// Permit filesystem mounts backed by SFTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_filesystem_mounts: Option<bool>,
    /// Permit Windows drive-letter mounts backed by SFTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_windows_drive_mounts: Option<bool>,
    /// Permit writeback caching for mounted SFTP filesystems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_writeback_cache: Option<bool>,
    /// Permit Windows Event Log registration and writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_windows_event_log: Option<bool>,
    /// Permit CLI writes to the Windows GPO registry policy hive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_gpo_policy_writes: Option<bool>,
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
    /// `[[profiles.sftp_mounts]]`. SFTP-backed filesystem/drive mounts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sftp_mounts: Vec<SftpMount>,
    /// `[profiles.script]`. Rhai scripting hooks (t6-e7). Optional; when
    /// absent the scripting engine is not instantiated and all hook call
    /// sites in the session layer are no-ops with zero allocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<ScriptConfig>,
    /// `[profiles.transport]`. Obfuscation transport selection (t6-e13).
    /// Optional; when absent the plain TCP path is used and no
    /// `spt-obfs` machinery runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
}

/// `[profiles.transport]` — transport-layer selection. Spec t6-e13.
///
/// Currently exposes a single `obfuscation` knob; future transports
/// (`[profiles.transport.tls]`, `[profiles.transport.proxy]`, etc.) hang
/// off the same table. Mirrors `spt_obfs::ObfsConfig` on the schema side
/// so that `spt-config` need not depend on the obfuscation crate.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Transport {
    /// `[profiles.transport.obfuscation]`. Absent → plain TCP path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<ObfsConfig>,
}

/// Schema mirror of `spt_obfs::ObfsConfig`. `tag = "kind"` matches the
/// `[serde(tag = "kind")]` on the engine-side enum, so loaders can map
/// between the two without a hand-written conversion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ObfsConfig {
    /// Tor PT obfs4 bridge (t6-e13).
    Obfs4 {
        /// Hex-encoded 20-byte server node id (parsed by the loader).
        node_id: String,
        /// Hex-encoded 32-byte server identity public key.
        public_key: String,
        /// IAT mode (0 / 1 / 2).
        iat_mode: u8,
    },
    /// meek-style HTTPS-CONNECT fronting (t6-e13).
    MeekHttp {
        /// Fronting URL (HTTPS).
        url: String,
        /// Optional Host: header override (domain fronting).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        front_host: Option<String>,
        /// Optional explicit SNI override.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
    },
    /// SSH over a WebSocket upgrade (t6-e13).
    Websocket {
        /// Endpoint URL (`ws://` or `wss://`).
        url: String,
        /// Extra HTTP headers added to the upgrade request.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        headers: Vec<(String, String)>,
    },
    /// SSH over Shadowsocks AEAD framing (t6-e13).
    Shadowsocks {
        /// Cipher identifier (mirrors `SsMethod::as_str`).
        method: String,
        /// `secret://ns/name` reference to the pre-shared password.
        password: spt_secrets::SecretRef,
    },
}

/// `[profiles.script]` — Rhai scripting hook configuration. Spec t6-e7.
///
/// Mirrors `spt_scripting::ScriptConfig` for the on-disk surface. The
/// runtime mapper in `spt-bin` (Bwire) converts this schema struct into the
/// engine-facing struct so that `spt-config` remains free of a build-time
/// dependency on the engine crate.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScriptConfig {
    /// Filesystem path to the Rhai script. Resolved relative to the
    /// configuration file directory at validation time.
    pub path: String,
    /// Per-hook entry-point function names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<ScriptHooks>,
    /// Sandbox limits. Defaults are documented on [`ScriptLimits`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ScriptLimits>,
}

/// `[profiles.script.hooks]` — function names invoked at each lifecycle event.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScriptHooks {
    /// Function called before the SSH connect attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_connect: Option<String>,
    /// Function called after auth completes successfully.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_connect: Option<String>,
    /// Function called on every forward state-machine transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_forward_state: Option<String>,
    /// Function called when the session is disconnected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_disconnect: Option<String>,
    /// Catch-all function for any structured event payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_event: Option<String>,
}

/// `[profiles.script.limits]` — Rhai sandbox bounds.
///
/// Every field is `Option`-typed in the schema so absent keys take the
/// `Default` values defined by `spt_scripting::ScriptLimits`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)] // every limit is `max_*` by spec.
pub struct ScriptLimits {
    /// Maximum number of Rhai operations per hook invocation (default `1_000_000`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_operations: Option<u64>,
    /// Maximum call-stack depth (default 32).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_call_levels: Option<u64>,
    /// Maximum string size in bytes (default 65536).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_string_size: Option<u64>,
    /// Maximum array size in elements (default 4096).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_array_size: Option<u64>,
    /// Maximum number of modules loadable per session (default 0 = no module loading).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_modules: Option<u64>,
}

/// `[[profiles.sftp_mounts]]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SftpMount {
    /// Mount id, unique within the profile.
    pub name: String,
    /// Enable this mount entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Remote SFTP path to expose.
    pub remote_path: String,
    /// Local mount point for Unix/macOS/FUSE-style mounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_point: Option<String>,
    /// Windows drive letter, for example `S` or `S:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive_letter: Option<String>,
    /// Mount read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    /// Cache mode: `none|metadata|writeback`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<String>,
    /// Allow other local users to access the mounted tree when the platform
    /// mount helper supports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_other: Option<bool>,
    /// Treat mount failure as profile failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
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
    /// GSSAPI/Kerberos service principal hint, for example `host/server`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gssapi_service: Option<String>,
    /// GSSAPI/Kerberos client principal hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gssapi_principal: Option<String>,
    /// Permit GSSAPI credential delegation for this auth method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gssapi_delegate: Option<bool>,
    /// Windows SSPI/Negotiate service principal name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sspi_service: Option<String>,
    /// Windows SSPI client principal hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sspi_principal: Option<String>,
    /// Permit SSPI credential delegation for this auth method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sspi_delegate: Option<bool>,
    /// Permit NTLM fallback through SSPI/Negotiate for this auth method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sspi_allow_ntlm_fallback: Option<bool>,
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
    /// Username for this endpoint; falls back to the profile-level user when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Per-endpoint auth; fully overrides (not field-merges) the profile-level
    /// global [profiles.auth] for this endpoint when set. Falls back to the
    /// profile auth when unset (the global default case).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Auth>,
}

/// Hop transport kind. Added by t6-e3 for proxy-jump support.
///
/// * `Ssh` — open `direct-tcpip` to the next hop and re-launch an SSH session
///   (the historical behaviour, retained as the default).
/// * `Socks5` — speak RFC 1928 CONNECT (with optional RFC 1929 user/password
///   auth) over the channel to reach the next hop.
/// * `HttpConnect` — speak HTTP `CONNECT host:port HTTP/1.1` (with optional
///   `Proxy-Authorization: Basic …`) to reach the next hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HopKind {
    /// Re-establish an SSH session through this hop. Default.
    #[default]
    Ssh,
    /// SOCKS5 proxy hop (RFC 1928 + optional RFC 1929 user/pw auth).
    Socks5,
    /// HTTP `CONNECT` proxy hop (with optional Basic `Proxy-Authorization`).
    HttpConnect,
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
    /// Hop transport kind: `ssh` (default), `socks5`, `http-connect`. t6-e3.
    #[serde(default)]
    pub kind: HopKind,
    /// Optional proxy username for SOCKS5 / HTTP CONNECT proxies. t6-e3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_username: Option<RedactedString>,
    /// Optional `secret://` reference for the proxy password used by
    /// SOCKS5 / HTTP CONNECT proxies. t6-e3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_password_ref: Option<SecretRef>,
}

/// UDP forwarding mode for SSH2-backed UDP forwards. Added by t6-e1.
///
/// * `TcpFramed` (default; both libssh2 and russh backends) — UDP datagrams
///   are length-prefixed (`[u32_be len][bytes payload]`) and shipped through a
///   single `direct-tcpip` channel. Frames larger than 64 KiB are rejected.
/// * `UdsBridge` (russh only) — open a `direct-streamlocal@openssh.com`
///   channel to a UNIX-domain socket on the server; an operator-run
///   UDP↔UDS shim on the server side bridges datagrams. The libssh2 path
///   returns [`spt_core::Error::UnsupportedPlatform`] because `ssh2` 0.9
///   lacks `direct-streamlocal` support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdpMode {
    /// Length-prefixed `direct-tcpip` framing. Default; both backends.
    #[default]
    TcpFramed,
    /// `direct-streamlocal@openssh.com` to a remote UDS bridge. Russh only.
    UdsBridge,
}

/// `[[profiles.forwards]]`. Spec §9.14.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Forward {
    /// Forward id (unique within profile). §9.14.
    pub name: String,
    /// `local`, `remote`, or `dynamic`. §9.14.
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
    /// Dynamic proxy protocols accepted by `type = "dynamic"` forwards:
    /// `all|socks4|socks4a|socks5|http_connect`. Omitted means all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_protocols: Option<Vec<String>>,
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
    /// SSH2-only: UDP forwarding mode. Defaults to
    /// [`UdpMode::TcpFramed`] when absent. Added by t6-e1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_mode: Option<UdpMode>,
    /// Forward link kind selecting the wire flavour underneath the existing
    /// direction in [`Forward::kind`]. Recognised values (t6-e2):
    ///
    /// * `tcp` — RFC 4254 `direct-tcpip` / `tcpip-forward` (default when
    ///   absent — preserves all pre-t6 behaviour).
    /// * `local_uds` — OpenSSH non-standard `direct-streamlocal@openssh.com`
    ///   channel-open. Requires [`Forward::remote_socket_path`].
    /// * `remote_uds` — OpenSSH non-standard `streamlocal-forward@openssh.com`
    ///   global request. Requires [`Forward::local_socket_path`] (the local
    ///   UDS the client binds, only valid on `cfg(unix)` targets) and
    ///   [`Forward::remote_socket_path`] (the server-side socket the
    ///   peer is asked to listen on).
    ///
    /// The TOML key is `kind` (the Rust name avoids collision with
    /// [`Forward::kind`] which is `type` in TOML).
    #[serde(default, rename = "kind", skip_serializing_if = "Option::is_none")]
    pub link_kind: Option<String>,
    /// Server-side UNIX socket path for `local_uds` (the remote socket the
    /// client opens a `direct-streamlocal` channel to) or for `remote_uds`
    /// (the path the server is asked to listen on). t6-e2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_socket_path: Option<String>,
    /// Client-side UNIX socket path for `local_uds` (the local UDS the client
    /// binds and accepts on, then forwards into the SSH channel) or for
    /// `remote_uds` (the local UDS the client connects to for each accepted
    /// `forwarded-streamlocal` channel from the server). Unix-only. t6-e2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_socket_path: Option<String>,
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

// ---------------------------------------------------------------------------
// t6-e3: HopKind round-trip + Hop proxy-field defaults
// ---------------------------------------------------------------------------

#[cfg(test)]
mod hop_kind_tests {
    use super::*;

    #[test]
    fn hopkind_all_three_round_trip_through_toml() {
        for (variant, repr) in [
            (HopKind::Ssh, "ssh"),
            (HopKind::Socks5, "socks5"),
            (HopKind::HttpConnect, "http-connect"),
        ] {
            // TOML round-trip in context.
            let toml_str = format!(
                "name = \"h\"\nprotocol = \"ssh\"\nhost = \"x\"\nport = 22\nkind = \"{repr}\"\n",
            );
            let hop: Hop = toml::from_str(&toml_str).unwrap();
            assert_eq!(hop.kind, variant, "deserialise `{repr}`");
            // And re-serialise: the `kind` field should round-trip back to
            // its kebab-case form.
            let rendered = toml::to_string(&hop).unwrap();
            assert!(
                rendered.contains(&format!("kind = \"{repr}\"")),
                "expected `kind = \"{repr}\"` in: {rendered}"
            );
        }
    }

    #[test]
    fn hop_kind_defaults_to_ssh_when_unspecified() {
        // No `kind` field present — must default to Ssh.
        let toml_str = "name = \"h\"\nprotocol = \"ssh\"\nhost = \"x\"\nport = 22\n";
        let hop: Hop = toml::from_str(toml_str).unwrap();
        assert_eq!(hop.kind, HopKind::Ssh);
        assert!(hop.proxy_username.is_none());
        assert!(hop.proxy_password_ref.is_none());
    }

    #[test]
    fn hop_proxy_fields_round_trip() {
        let toml_str = "\
name = \"jump\"
protocol = \"ssh\"
host = \"proxy.example.com\"
port = 1080
kind = \"socks5\"
proxy_username = \"alice\"
proxy_password_ref = \"secret://proxies/alice\"
";
        let hop: Hop = toml::from_str(toml_str).unwrap();
        assert_eq!(hop.kind, HopKind::Socks5);
        assert!(hop.proxy_username.is_some());
        let pw = hop.proxy_password_ref.expect("ref present");
        assert_eq!(pw.ns(), "proxies");
        assert_eq!(pw.name(), "alice");
    }
}

#[cfg(test)]
mod event_sink_subject_template_tests {
    use super::*;

    #[test]
    fn subject_template_some_round_trips_through_toml() {
        let toml_str = "\
name = \"mailer\"
type = \"email\"
subject_template = \"[{{severity}}] {{kind}}\"
";
        let sink: EventSink = toml::from_str(toml_str).unwrap();
        assert_eq!(
            sink.subject_template.as_deref(),
            Some("[{{severity}}] {{kind}}")
        );
        let rendered = toml::to_string(&sink).unwrap();
        assert!(
            rendered.contains("subject_template = \"[{{severity}}] {{kind}}\""),
            "expected subject_template in: {rendered}"
        );
    }

    #[test]
    fn subject_template_none_is_omitted_on_serialize() {
        let sink = EventSink {
            name: "mailer".into(),
            kind: "email".into(),
            ..Default::default()
        };
        assert!(sink.subject_template.is_none());
        let rendered = toml::to_string(&sink).unwrap();
        assert!(
            !rendered.contains("subject_template"),
            "unset subject_template must be omitted; got: {rendered}"
        );
    }
}

// ---------------------------------------------------------------------------
// multi-auth Phase 1: per-endpoint `user` + `auth` round-trip + back-compat
// ---------------------------------------------------------------------------

#[cfg(test)]
mod endpoint_auth_tests {
    use super::*;

    #[test]
    fn endpoint_inline_user_and_auth_round_trip() {
        // An endpoint carrying its own `user` plus a full inline `[auth]`
        // block must deserialise into `Some(..)` and re-serialise verbatim.
        let toml_str = "\
name = \"primary\"
host = \"a.example.com\"
port = 22
user = \"alice\"

[auth]
method = \"public_key\"
identity_file = \"/home/alice/.ssh/id_ed25519\"
password = \"secret://hosts/alice\"
";
        let ep: Endpoint = toml::from_str(toml_str).unwrap();
        assert_eq!(ep.user.as_deref(), Some("alice"));
        let auth = ep.auth.as_ref().expect("inline auth present");
        assert_eq!(auth.method, "public_key");
        assert_eq!(
            auth.identity_file.as_deref(),
            Some("/home/alice/.ssh/id_ed25519")
        );

        // Re-serialise: the inline values survive the round-trip.
        let rendered = toml::to_string(&ep).unwrap();
        let reparsed: Endpoint = toml::from_str(&rendered).unwrap();
        assert_eq!(reparsed, ep, "endpoint must round-trip byte-stably");
        assert!(rendered.contains("user = \"alice\""));
        assert!(rendered.contains("method = \"public_key\""));
    }

    #[test]
    fn endpoint_without_auth_omits_keys_and_inherits_globally() {
        // The zero-config / global-default case: no `user`, no `auth`.
        // Both must deserialise to `None` and serialise with NO `user`/`auth`
        // keys, keeping configs byte-identical to the pre-feature layout.
        let toml_str = "name = \"e\"\nhost = \"h\"\nport = 22\n";
        let ep: Endpoint = toml::from_str(toml_str).unwrap();
        assert!(ep.user.is_none());
        assert!(ep.auth.is_none());

        let rendered = toml::to_string(&ep).unwrap();
        assert!(
            !rendered.contains("user"),
            "no `user` key expected, got: {rendered}"
        );
        assert!(
            !rendered.contains("auth"),
            "no `auth` key expected, got: {rendered}"
        );
        // Exact byte-identical serialisation against a struct built without
        // the new fields (proves purely-additive, skip-when-none behaviour).
        let expected = toml::to_string(&Endpoint {
            name: "e".into(),
            host: "h".into(),
            port: 22,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(rendered, expected);
    }
}

// ---------------------------------------------------------------------------
// t6-e1: UdpMode round-trip + default behaviour on `Forward`
// ---------------------------------------------------------------------------

#[cfg(test)]
mod udp_mode_tests {
    use super::*;

    #[test]
    fn udp_mode_both_variants_round_trip_through_toml() {
        for (variant, repr) in [
            (UdpMode::TcpFramed, "tcp-framed"),
            (UdpMode::UdsBridge, "uds-bridge"),
        ] {
            let toml_str = format!(
                "name = \"f\"\ntype = \"local\"\ntransport = \"udp\"\nudp_mode = \"{repr}\"\n",
            );
            let fwd: Forward = toml::from_str(&toml_str).unwrap();
            assert_eq!(fwd.udp_mode, Some(variant), "deserialise `{repr}`");
            let rendered = toml::to_string(&fwd).unwrap();
            assert!(
                rendered.contains(&format!("udp_mode = \"{repr}\"")),
                "expected `udp_mode = \"{repr}\"` in: {rendered}"
            );
        }
    }

    #[test]
    fn udp_mode_defaults_to_tcp_framed_when_absent() {
        // No `udp_mode` field present — must deserialise as None, which is
        // interpreted as `UdpMode::default()` (i.e. `TcpFramed`) at the
        // dispatch site (`spt-forward::udp_ssh2::resolve_udp_mode`).
        let toml_str = "name = \"f\"\ntype = \"local\"\ntransport = \"udp\"\n";
        let fwd: Forward = toml::from_str(toml_str).unwrap();
        assert!(fwd.udp_mode.is_none());
        // The conventional "resolved" mode is then the enum default.
        assert_eq!(fwd.udp_mode.unwrap_or_default(), UdpMode::TcpFramed);
    }
}

// ---------------------------------------------------------------------------
// t6-e2: Forward.link_kind / remote_socket_path / local_socket_path round-trip
// ---------------------------------------------------------------------------

#[cfg(test)]
mod uds_kind_tests {
    use super::*;

    /// All three documented `kind` link variants must round-trip through TOML:
    /// `tcp`, `local_uds`, `remote_uds`.
    #[test]
    fn link_kind_three_variants_round_trip_through_toml() {
        for repr in ["tcp", "local_uds", "remote_uds"] {
            let toml_str = format!(
                "name = \"f\"\ntype = \"local\"\ntransport = \"tcp\"\nkind = \"{repr}\"\n",
            );
            let fwd: Forward = toml::from_str(&toml_str).unwrap();
            assert_eq!(
                fwd.link_kind.as_deref(),
                Some(repr),
                "deserialise link_kind=`{repr}`"
            );
            let rendered = toml::to_string(&fwd).unwrap();
            assert!(
                rendered.contains(&format!("kind = \"{repr}\"")),
                "expected `kind = \"{repr}\"` in: {rendered}"
            );
        }
    }

    #[test]
    fn link_kind_defaults_to_none_meaning_tcp() {
        // No `kind` (link kind) field — defaults to None, dispatchers treat
        // that as the implicit `tcp` link kind (preserving pre-t6 behaviour).
        let toml_str = "name = \"f\"\ntype = \"local\"\ntransport = \"tcp\"\n";
        let fwd: Forward = toml::from_str(toml_str).unwrap();
        assert!(fwd.link_kind.is_none());
        assert!(fwd.remote_socket_path.is_none());
        assert!(fwd.local_socket_path.is_none());
    }

    #[test]
    fn uds_socket_paths_round_trip() {
        let toml_str = "\
name = \"db\"
type = \"local\"
transport = \"tcp\"
kind = \"local_uds\"
remote_socket_path = \"/run/db.sock\"
local_socket_path = \"/tmp/db.sock\"
";
        let fwd: Forward = toml::from_str(toml_str).unwrap();
        assert_eq!(fwd.link_kind.as_deref(), Some("local_uds"));
        assert_eq!(fwd.remote_socket_path.as_deref(), Some("/run/db.sock"));
        assert_eq!(fwd.local_socket_path.as_deref(), Some("/tmp/db.sock"));
        let rendered = toml::to_string(&fwd).unwrap();
        assert!(rendered.contains("remote_socket_path = \"/run/db.sock\""));
        assert!(rendered.contains("local_socket_path = \"/tmp/db.sock\""));
    }
}
