# Configuration Reference

This is the field-level reference for every TOML table in an `spt`
configuration file. Fields are derived directly from
`crates/spt-config/src/schema.rs`. For high-level discovery, precedence,
and env-var overrides see [Configuration Overview](configuration-overview.md).

**Type notation used in tables:**

| Notation | Meaning |
|----------|---------|
| `string` | TOML string |
| `bool` | TOML boolean |
| `integer` | TOML integer |
| `float` | TOML float |
| `[string]` | TOML array of strings |
| `duration` | String parsed by the `spt-core` duration parser, e.g. `"30s"`, `"2m"`, `"1h 30m"` |
| `bytesize` | String parsed by the `spt-core` size parser, e.g. `"64MiB"`, `"1GiB"` |

All optional fields default to absent (`None`) unless a specific default
is shown. Duration and bytesize strings must be valid or the validator
returns a hard error.

Validation codes shown in the tables identify the `code` field emitted
by `spt config validate`. Codes marked **E** are errors that block
startup; codes marked **W** are warnings. Fields noted as
**not wired** are parsed and validated but have no runtime consumer in
this build.

---

## Top-level `Config`

```toml
version = 1
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `version` | `integer` | — (required) | Must be `1`. Any other value → **E** `version_unsupported` |
| `runtime` | table | absent | See `[runtime]` |
| `logging` | table | absent | See `[logging]` |
| `secrets` | table | absent | See `[secrets]` |
| `dns` | table | absent | See `[dns]` |
| `firewall` | table | absent | See `[firewall]` |
| `network` | table | absent | See `[network]` |
| `observability` | table | absent | See `[observability]` |
| `events` | table | absent | See `[events]` |
| `mcp` | table | absent | See `[mcp]` |
| `mem_hygiene` | table | absent | See `[mem_hygiene]` |
| `updater` | table | absent | See `[updater]` |
| `diagnostics` | table | absent | See `[diagnostics]` |
| `benchmark` | table | absent | See `[benchmark]` |
| `capabilities` | table | absent | See `[capabilities]` |
| `service` | table | absent | See `[service]` |
| `round_robin` | table | defaults | See `[round_robin]` |
| `status_api` | table | defaults | See `[status_api]` |
| `profiles` | `[[array]]` | empty | See `[[profiles]]` |

---

## `[runtime]`

Controls the state directory, process-level file lock, shutdown grace
period, threading model, config reload policy, and remote-config
polling.

```toml
[runtime]
state_dir = "/var/lib/spt"
required_profiles = ["edge-prod"]
shutdown_grace = "20s"
profile_start_parallelism = 4
file_lock = true
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `state_dir` | `string` | platform dir | Directory for lock files, status snapshots, event spools, and counters |
| `required_profiles` | `[string]` | absent | Profile names whose failure marks the process unhealthy |
| `shutdown_grace` | `duration` | runtime default | Drain time before forced close on stop signal |
| `profile_start_parallelism` | `integer` | 1 | Maximum profiles started concurrently at startup |
| `file_lock` | `bool` | absent | Single-supervisor file lock under `state_dir` |

### `[runtime.threads]`

```toml
[runtime.threads]
model = "multi_thread"
orchestrator_threads = 1
service_threads = 4
blocking_worker_threads = 32
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `model` | `string` | `"multi_thread"` | `multi_thread` or `single_thread_for_tests` → **E** on invalid |
| `orchestrator_threads` | `integer` | 1 | Orchestrator task count; production always 1 |
| `service_threads` | `integer` | runtime default | Service supervision workers |
| `logging_threads` | `integer` | runtime default | Log rotation workers |
| `dns_threads` | `integer` | runtime default | DNS resolver workers |
| `observability_threads` | `integer` | runtime default | Metrics / SNMP workers |
| `blocking_worker_threads` | `integer` | runtime default | Blocking workers (fs, keychain, OS service) |
| `idle_tick` | `duration` | runtime default | Tokio idle tick interval |

### `[runtime.reload]`

```toml
[runtime.reload]
mode = "signal"
debounce = "1s"
require_valid_config = true
restart_changed_profiles = true
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `mode` | `string` | `"none"` | `none`, `signal` (SIGHUP), `watch` (inotify/FSEvents/ReadDirectoryChangesW), or `service` (systemd ExecReload / SCM ParamChange) → **E** on invalid |
| `debounce` | `duration` | `"1s"` | File-watch debounce before re-loading |
| `require_valid_config` | `bool` | `true` | Reject invalid new config and keep old running |
| `restart_changed_profiles` | `bool` | `false` | Restart only profiles whose config changed on reload |

### `[runtime.remote_config]`

Enables polling of a remote TOML config over HTTPS. The fetched body
replaces the local config on each tick. Requires `enabled = true` plus
a valid HTTPS URL and a SHA-256 body fingerprint.

```toml
[runtime.remote_config]
enabled = true
url = "https://config.example.com/spt/spt.toml"
fingerprint_sha256 = "sha256:<hex>"
cache_file = "/var/lib/spt/remote-config-cache.toml"
allow_cached_on_failure = true
poll_interval = "5m"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Enable remote-config retrieval |
| `url` | `string` | absent | HTTPS-only URL → **E** if empty or non-HTTPS when enabled |
| `fingerprint_sha256` | `string` | absent | Required SHA-256 of the fetched body → **W** `remote_config_no_pin` if unset |
| `cache_file` | `string` | absent | Local atomic cache file written after each successful fetch |
| `allow_cached_on_failure` | `bool` | `false` | Fall back to cache when fetch fails |
| `poll_interval` | `duration` | runtime default | Refresh interval; minimum 30 s → **E** `remote_config_poll_too_frequent` if below |
| `pin_spki_sha256` | `[string]` | empty | SPKI SHA-256 pin set for the HTTPS endpoint |
| `allow_self_signed` | `bool` | `false` | Allow self-signed certs; requires non-empty `pin_spki_sha256` |
| `max_cert_chain_depth` | `integer` | 5 | Maximum certificate chain depth |
| `encryption_key_from` | `string` | absent | Secret reference for decrypting a sealed `SPTENC1` body |
| `require_encrypted` | `bool` | `false` | Reject cleartext bodies when encryption is expected |
| `signing_pubkey` | `string` | absent | Ed25519 public key (base64) or secret reference for body authenticity |
| `require_signature` | `bool` | `false` | Reject bodies whose signature does not verify against `signing_pubkey` |

---

## `[logging]`

Controls the local logging pipeline: level, format, file rotation, and
remote sinks.

```toml
[logging]
level = "info"
format = "json"
destinations = ["file"]
file = "/var/log/spt/spt.jsonl"
rotate = "daily"
max_files = 30
max_size = "100MiB"
max_age = "30d"
compress_rotated = true
rotation_check_interval = "1m"
redact = ["secrets", "auth"]
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `level` | `string` | `"info"` | `trace`, `debug`, `info`, `warn`, `error`, `off`, or full `EnvFilter` directive → **E** on unrecognised bare token |
| `format` | `string` | `"compact"` | `compact`, `text`, `pretty`, or `json` → **E** on invalid |
| `destinations` | `[string]` | `["stderr"]` | Any of `stderr`, `console`, `file`, `journald` → **E** on invalid entry |
| `file` | `string` | absent | Path for the `file` destination |
| `rotate` | `string` | `"none"` | `size`, `daily`, `hourly`, `none`, or `never` → **E** on invalid |
| `max_size` | `bytesize` | absent | Maximum file size for size-based rotation |
| `max_files` | `integer` | absent | Maximum retained rotated files |
| `max_age` | `duration` | absent | Maximum age of retained rotated files |
| `compress_rotated` | `bool` | `false` | Gzip-compress rotated files |
| `rotation_check_interval` | `duration` | `"1m"` | Rotation check tick |
| `redact` | `[string]` | absent | Redaction profiles applied to all log lines |

### `[[logging.remote]]`

Remote log sinks for forwarding to SIEM, syslog servers, or OTLP
collectors. Each entry is a named sink with its own transport settings.

```toml
[[logging.remote]]
name = "siem"
type = "syslog_tls"
endpoint = "siem.example.com:6514"
ca_file = "/etc/ssl/certs/ca.pem"
server_name = "siem.example.com"
facility = 16
app_name = "spt"
spool_dir = "/var/lib/spt/spool/siem"
spool_max_bytes = "64MiB"
queue_max_records = 10000
reconnect_backoff = "1s"
required = true
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | Unique sink identifier → **E** on duplicate |
| `type` | `string` | — (required) | `syslog_udp`, `syslog_tcp`, `syslog_tls`, `https_jsonl`, or `otlp` → **E** on invalid |
| `endpoint` | `string` | — (required) | `host:port` or full URL → **E** if absent or empty |
| `facility` | `integer` | absent | Syslog facility (0–23) → **E** if outside range |
| `app_name` | `string` | `"spt"` | Syslog APP-NAME field |
| `hostname` | `string` | absent | Syslog HOSTNAME override |
| `enterprise_id` | `integer` | absent | Syslog structured data enterprise ID |
| `ca_file` | `string` | absent | CA bundle for TLS validation |
| `server_name` | `string` | absent | TLS SNI / verification name override |
| `client_cert` | `string` | absent | TLS client certificate chain (mutual TLS) |
| `client_key` | `string` | absent | TLS client private key; must be set together with `client_cert` → **E** if only one is set |
| `allow_self_signed` | `bool` | `false` | Allow self-signed certs (syslog_tls only); requires non-empty `pin_spki_sha256` → **E** if pin set is empty |
| `allow_invalid_certs` | `bool` | `false` | **Deprecated** — use `allow_self_signed` + `pin_spki_sha256` → **W** `remote_log_allow_invalid_certs_deprecated` |
| `pin_spki_sha256` | `[string]` | empty | SPKI SHA-256 pin set |
| `max_cert_chain_depth` | `integer` | 5 | Maximum certificate chain depth |
| `auth` | `string` | absent | Secret reference for bearer token / API key |
| `timeout` | `duration` | absent | Per-batch delivery timeout |
| `reconnect_backoff` | `duration` | absent | Reconnect delay for reliable transports |
| `spool_dir` | `string` | absent | On-disk spool directory; must be unique across sinks → **E** on duplicate |
| `spool_max_bytes` | `bytesize` | absent | Maximum spool disk usage |
| `queue_max_records` | `integer` | absent | Maximum in-memory queue depth → **E** if `0` |
| `batch_size` | `integer` | absent | Records per delivery batch |
| `required` | `bool` | `false` | Block forwarding on sink delivery failure |

---

## `[secrets]`

Selects and configures the secrets backend. Secret references in the
form `secret://namespace/name` are resolved through this backend at
session start. See [Secrets](secrets.md) for the full resolution
priority and vault operations.

```toml
[secrets]
backend = "vault"
vault_file = "/var/lib/spt/vault.spt"
encrypt_at_rest = true
memory_protection = "strict"
keychain_namespace = "spt"

[secrets.file]
root = "/run/secrets"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `backend` | `string` | `"auto"` | `auto`, `keychain`, `vault`, or `env` → **E** on invalid |
| `vault_file` | `string` | absent | Path to the local AES-256-GCM vault file |
| `encrypt_at_rest` | `bool` | `false` | Enforce encrypted storage; requires `vault` or `keychain` backend → **E** with `env` or `auto` |
| `memory_protection` | `string` | `"best_effort"` | `best_effort`, `strict`, or `none` → **E** on invalid |
| `keychain_namespace` | `string` | `"spt"` | Keychain service name for the OS credential store |

### `[secrets.file]`

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `root` | `string` | `<state_dir>/secrets` | Root directory for the file backend; `secret://ns/name` resolves to `<root>/ns/name` |

---

## `[dns]`

Configures the built-in DNS resolver. The resolver runs as a transparent
forwarder, a synthetic-records-only server, or a hosts-file manager.

```toml
[dns]
enabled = true
mode = "transparent_forwarder"
bind = "127.0.0.1:5353"
zone = "tunnel.local"
ttl = "60s"
auto_records = true
upstream = ["1.1.1.1:53", "8.8.8.8:53"]
hosts_file = "/etc/hosts"
hosts_file_mode = "apply"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Enable the built-in resolver |
| `mode` | `string` | `"disabled"` | `disabled`, `transparent_forwarder`, `synthetic_only`, or `hosts_file` → **E** on invalid |
| `bind` | `string` | absent | Listener bind address; privileged port < 1024 → **W** `dns_privileged_port` |
| `zone` | `string` | absent | Default DNS zone for synthesized records |
| `ttl` | `duration` | `"60s"` | Default TTL for synthetic records |
| `auto_records` | `bool` | `false` | Auto-derive A/AAAA records from `[[profiles.forwards]].dns_names` |
| `upstream` | `[string]` | system resolvers | Upstream resolvers for transparent forwarder mode |
| `hosts_file` | `string` | `/etc/hosts` | Hosts file path (hosts_file mode) |
| `hosts_file_mode` | `string` | `"render_only"` | `render_only`, `apply`, or `restore` |

### `[[dns.records]]`

Static DNS records injected into the managed zone.

```toml
[[dns.records]]
name = "db.tunnel.local"
type = "A"
value = "127.0.0.1"
ttl = "30s"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | Owner name (FQDN) |
| `type` | `string` | — (required) | `A`, `AAAA`, `SRV`, or `TXT` → **E** on invalid |
| `value` | `string` | — (required) | Record value (IP for A/AAAA, target for SRV/TXT) |
| `ttl` | `duration` | zone default | Per-record TTL override |
| `priority` | `integer` | absent | SRV priority |
| `weight` | `integer` | absent | SRV weight |
| `port` | `integer` | absent | SRV port |

---

## `[firewall]`

Controls the optional firewall planner. The planner generates and
optionally applies OS-level firewall rules derived from the set of
active forwards and their bind policies.

```toml
[firewall]
enabled = true
manager = "auto"
apply_rules = false
bind_policy = "explicit"
default_interface = "eth0"
allow_all_interfaces = false

[firewall.platform]
linux = "nftables"
macos = "pf"
windows = "windows_firewall"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Enable the firewall planner |
| `manager` | `string` | `"auto"` | `auto`, `nftables`, `iptables`, `pf`, `windows_firewall`, or `none` |
| `apply_rules` | `bool` | `false` | Apply generated rules; `false` = plan-only (print/log only) |
| `bind_policy` | `string` | `"explicit"` | `explicit`, `loopback_only`, or `any` |
| `default_interface` | `string` | absent | Default interface for rule generation |
| `allow_all_interfaces` | `bool` | `false` | Allow wildcard (`0.0.0.0`/`::`) binds in plan output |

### `[firewall.platform]`

Per-platform planner override. Setting a planner for a different OS → **W** `firewall_platform_mismatch`.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `linux` | `string` | `"auto"` | `auto`, `nftables`, `iptables`, or `none` |
| `macos` | `string` | `"pf"` | `pf` or `none` |
| `windows` | `string` | `"windows_firewall"` | `windows_firewall` or `none` |

---

## `[network]`

Host-level networking policy that applies across all profiles: interface
selection, gateway routing policy, socket/kernel offload, and
load-balancing strategy defaults.

### `[network.interface]`

```toml
[network.interface]
default_interface = "eth0"
allowed_interfaces = ["eth0", "wg0"]
denied_interfaces = []
require_explicit_interface = false
allow_all_interfaces = false
bind_ipv6 = "auto"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `default_interface` | `string` | absent | Default interface for auto-interface bind decisions |
| `allowed_interfaces` | `[string]` | absent | Interface allow-list; intersected with per-forward policy |
| `denied_interfaces` | `[string]` | absent | Interface deny-list; conflicts with allow-list → **E** on overlap |
| `require_explicit_interface` | `bool` | `false` | Require every non-loopback forward to set `bind_interface` |
| `allow_all_interfaces` | `bool` | `false` | Permit wildcard binds |
| `bind_ipv6` | `string` | `"auto"` | `auto`, `prefer`, or `disable` → **E** on invalid |

### `[network.gateway]`

> **Not wired at runtime.** This table is parsed and format-validated but
> has no runtime consumer. `require_gateway_match = true` does not act as
> a routing safety gate. Any set field emits **W** `network_gateway_not_enforced`.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `default_gateway` | `string` | absent | Default gateway address or route alias |
| `interface` | `string` | absent | Interface expected to own the gateway |
| `route_check_target` | `string` | absent | Target host used to verify route selection |
| `require_gateway_match` | `bool` | `false` | (not wired) Require chosen route to match `interface`; requires `interface` to be set → **E** if `interface` absent |
| `policy` | `string` | absent | `disabled`, `default_route`, `interface_only`, or `route_to_target` → **E** on invalid |

### `[network.offload]`

Socket and kernel offload options. Only `tcp_nodelay` and
`socket_keepalive` have runtime consumers; all others emit
**W** `network_offload_flag_unsupported` if set to `true`.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `tcp_nodelay` | `bool` | `false` | Set `TCP_NODELAY` on TCP sockets — **wired** |
| `socket_keepalive` | `bool` | `false` | Enable socket-level keepalive — **wired** |
| `tcp_fast_open` | `bool` | `false` | TCP Fast Open — **not wired**, **W** if `true` |
| `reuse_port` | `bool` | `false` | `SO_REUSEPORT` — **not wired**, **W** if `true` |
| `io_uring` | `bool` | `false` | io_uring on Linux — **not wired**, **W** if `true` |
| `zerocopy` | `bool` | `false` | Zero-copy send — **not wired**, **W** if `true` |
| `sendfile` | `bool` | `false` | sendfile paths — **not wired**, **W** if `true` |
| `checksum_offload` | `bool` | `false` | NIC checksum offload — **not wired**, **W** if `true` |
| `large_send_offload` | `bool` | `false` | TSO/LSO — **not wired**, **W** if `true` |

### `[network.load_balance]`

Endpoint load-balancing defaults used when no per-profile `[failover]`
overrides are present. The active consumer is the `[round_robin]`
endpoint selector.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `strategy` | `string` | `"priority"` | `priority`, `weighted`, `round_robin`, `least_connections`, or `manual` → **E** on invalid; `least_connections` is **not wired** → **W** |
| `sticky_sessions` | `bool` | `false` | **Not wired** by the endpoint selector → **W** `network_load_balance_sticky_sessions_ignored`; use `[round_robin] policy = "sticky"` instead |
| `health_check` | `string` | absent | `tcp_connect`, `ssh_handshake`, `ssh_auth_preflight`, or `ssh3_endpoint` → **E** on invalid |
| `fail_after` | `integer` | absent | Consecutive failures before an endpoint is removed → **E** if `0` |
| `restore_after` | `duration` | absent | Cooldown before failback |
| `rebalance_interval` | `duration` | absent | **Not wired** → **W** `network_load_balance_rebalance_interval_ignored` |

---

## `[observability]`

### `[observability.metrics]`

Prometheus metrics exporter. The exporter writes a text-format snapshot
to `state_file` periodically and optionally to `/v1/metrics` when the
`[status_api]` is enabled.

```toml
[observability.metrics]
enabled = true
format = "prometheus"
state_file = "/var/lib/spt/metrics.prom"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Enable the metrics exporter |
| `format` | `string` | `"prometheus"` | `prometheus` or `json` |
| `state_file` | `string` | absent | Path where metrics are written |

### `[observability.snmp]`

SNMPv3 agent and trap dispatcher. Requires a registered IANA Private
Enterprise Number (PEN). Only SNMPv3 with USM security is supported.

```toml
[observability.snmp]
enabled = true
version = "v3"
bind = "127.0.0.1:10161"
enterprise_id = 12345
engine_id = "0x8000000006010203"
trap_sinks = ["manager1"]
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Enable the SNMP agent |
| `version` | `string` | `"v3"` | Must be `v3` → **E** on any other value |
| `bind` | `string` | `"127.0.0.1:10161"` | Agent listener bind address |
| `enterprise_id` | `integer` | absent | IANA PEN → **E** if absent when enabled, if `0`, if `99999` (placeholder), or if `32473` (RFC doc) |
| `engine_id` | `string` | absent | Hex-encoded authoritative engine ID (RFC 3411: 5–32 octets) → **E** on malformed hex or out-of-range length |
| `trap_sinks` | `[string]` | absent | Names referencing `[[observability.snmp.traps]]` entries → **W** for unknown names |

### `[[observability.snmp.users]]`

USM users the SNMP agent accepts inbound requests from. Security level
is derived from which secrets are present (noAuthNoPriv / authNoPriv /
authPriv).

```toml
[[observability.snmp.users]]
name = "monitor"
auth_protocol = "hmac_sha256"
auth_secret = "secret://snmp/monitor/auth"
priv_protocol = "aes256"
privacy_secret = "secret://snmp/monitor/priv"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | USM security name → **E** if empty or duplicate |
| `auth_protocol` | `string` | absent | `hmac_md5`, `hmac_sha1`, or `hmac_sha256` → **E** on invalid |
| `auth_secret` | `string` | absent | Secret reference for the auth key → **E** if `auth_protocol` set but absent; **W** if present without `auth_protocol` |
| `priv_protocol` | `string` | absent | `aes128`, `aes256`, or `des` → **E** on invalid; **E** if set without `auth_protocol` |
| `privacy_secret` | `string` | absent | Secret reference for the privacy key → **E** if `priv_protocol` set but absent |

### `[[observability.snmp.traps]]`

Trap destination sinks referenced by name in `trap_sinks`.

```toml
[[observability.snmp.traps]]
name = "manager1"
endpoint = "192.0.2.10:162"
user = "trapuser"
auth_secret = "secret://snmp/trap/auth"
privacy_secret = "secret://snmp/trap/priv"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | Trap sink name |
| `endpoint` | `string` | — (required) | Destination `host:port` |
| `user` | `string` | absent | USM user for trap messages |
| `auth_secret` | `string` | absent | Secret reference for USM auth key |
| `privacy_secret` | `string` | absent | Secret reference for USM privacy key |

### `[observability.windows_event]`

Writes structured events to the Windows Event Log. Requires
`capabilities.allow_windows_event_log = true`.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Enable Windows Event Log writes |
| `source` | `string` | `"spt"` | Event source name registered with the Event Log |
| `channel` | `string` | `"Application"` | Target log channel |
| `install_source` | `bool` | `false` | Auto-install the event source on startup |

---

## `[events]`

The event bus carries structured events from the tunnel runtime to
configurable sinks (email, SMS, push, HTTP, SNMP traps, Windows Event
Log, MCP notifications, exec commands). The bus is a broadcast ring;
slow consumers that fall behind by `ring_capacity` slots receive a
`Lagged` error and miss events.

```toml
[events]
ring_capacity = 1024
retry_interval = "30s"
spool_dir = "/var/lib/spt/event-spool"
spool_max_bytes = "64MiB"
default_min_level = "info"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `ring_capacity` | `integer` | 1024 | Broadcast ring capacity → **E** if `0` |
| `retry_interval` | `duration` | `"30s"` | Dispatcher spool-retry cadence → **E** if zero-length |
| `spool_dir` | `string` | `"event-spool"` | Spool root; one subdirectory per sink |
| `spool_max_bytes` | `bytesize` | spool default | Disk spool byte cap per sink |
| `default_min_level` | `string` | absent | Default severity floor: `trace`, `debug`, `info`, `warn`, `error`, or `critical` → **E** on invalid |

### `[[events.bindings]]`

A binding subscribes to one or more event categories and routes matched
events to named sinks or commands.

```toml
[[events.bindings]]
name = "profile-alerts"
on = ["profile.failed", "profile.degraded"]
actions = ["oncall-email", "ops-webhook"]
min_level = "warn"
throttle = "5m"

[events.bindings.dedupe]
key = "kind"
window = "5m"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | Binding identifier → **E** on duplicate |
| `on` | `[string]` | — (required) | Event categories to subscribe to; must be non-empty → **E** if empty |
| `actions` | `[string]` | — (required) | Sink/command names to fire → **E** for unknown names or empty list |
| `min_level` | `string` | `default_min_level` | Minimum severity to process → **E** on invalid |
| `throttle` | `duration` | absent | Minimum time between deliveries for this binding |
| `dedupe` | table | absent | Deduplication policy (see below) |

#### `[[events.bindings]].dedupe`

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `key` | `string` | `"kind\|profile_id\|forward_id"` | Field path(s) forming the dedupe key |
| `window` | `duration` | `"60s"` | Suppression window for duplicate events |

### `[[events.sinks]]`

A sink defines a delivery target for events. Supported types: `email`,
`sms`, `push`, `webpush`, `http`, `webhook_post`, `snmp_trap`,
`windows_event`, `mcp_notify`, `remote_log`, `command`.

```toml
[[events.sinks]]
name = "oncall-email"
type = "email"
smtp = "smtp://smtp.example.com:587"
from = "spt@example.com"
to = ["oncall@example.com"]
auth = "secret://smtp/relay/token"
timeout = "10s"

[[events.sinks]]
name = "ops-webhook"
type = "webhook_post"
url = "https://hooks.example.com/spt"
auth = "secret://webhook/ops/token"
timeout = "5s"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | Unique sink name → **E** on duplicate |
| `type` | `string` | — (required) | One of the listed sink types → **E** on invalid |
| `smtp` | `string` | absent | SMTP endpoint URI (email sinks) |
| `from` | `string` | absent | From address (email sinks) |
| `to` | `[string]` | absent | Recipient list (email/SMS sinks) |
| `auth` | `string` | absent | Secret reference for authentication |
| `provider` | `string` | absent | Provider hint for SMS/push sinks |
| `url` | `string` | absent | Endpoint URL (push/HTTP sinks) |
| `endpoint` | `string` | absent | Endpoint URL alias (push sinks) |
| `method` | `string` | `"POST"` | HTTP method |
| `content_type` | `string` | absent | HTTP content type |
| `timeout` | `duration` | absent | Per-call timeout |
| `vapid_private_key` | `string` | absent | VAPID private key (base64url) or secret reference (webpush) |
| `vapid_subject` | `string` | absent | VAPID `sub` claim, e.g. `mailto:` URL (webpush) |
| `body_template` | `string` | absent | `{{var}}` body template rendered against the event |
| `subject_template` | `string` | absent | `{{var}}` subject template for email sinks |
| `subscriptions` | array | absent | Push subscription objects (`endpoint`, `p256dh`, `auth`) |
| `pin_spki_sha256` | `[string]` | empty | SPKI SHA-256 pin set for HTTPS endpoint |
| `allow_self_signed` | `bool` | `false` | Allow self-signed TLS cert; requires non-empty pin set |
| `max_cert_chain_depth` | `integer` | 5 | Maximum certificate chain depth |

### `[[events.commands]]`

An exec command that fires when a binding routes to it. Requires
`allow_exec = true` to fire; without it the command is **inert** and
a **W** `event_command_exec_disabled` is emitted.

```toml
[[events.commands]]
name = "restart-hook"
command = "/usr/local/bin/spt-restart.sh"
args = ["--profile", "{{profile_id}}"]
allow_exec = true
timeout = "30s"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | Unique command name → **E** on duplicate |
| `command` | `string` | — (required) | Absolute path to executable → **E** if empty |
| `args` | `[string]` | absent | Argument list; `{{var}}` templates rendered against the event |
| `allow_exec` | `bool` | `false` | Must be `true` to execute → **W** if absent or `false` |
| `timeout` | `duration` | absent | Execution timeout |

---

## `[mcp]`

The MCP server exposes `spt` control and status over the Model Context
Protocol. Non-loopback binds require `expose = true`.

```toml
[mcp]
enabled = true
default_mode = "read_only"
stdio = true
listen = "127.0.0.1:7878"
allow_secret_reveal = false
allow_write_tools = []
audit_events = true
expose = false
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Enable the MCP server |
| `default_mode` | `string` | `"read_only"` | `read_only` or `read_write` |
| `stdio` | `bool` | `false` | Expose over standard input/output |
| `listen` | `string` | absent | TCP bind address for the MCP server |
| `allow_secret_reveal` | `bool` | `false` | Must remain `false` → **E** `mcp_secret_reveal_disallowed` if `true` |
| `allow_write_tools` | `[string]` | empty | Explicit list of write tools to permit |
| `audit_events` | `bool` | `false` | Emit a structured audit event for each tool call |
| `expose` | `bool` | `false` | Required for non-loopback `listen` → **E** `mcp_non_loopback_requires_expose` if absent |
| `pin_spki_sha256` | `[string]` | empty | SPKI SHA-256 pin set for outbound MCP notify HTTPS |
| `allow_self_signed` | `bool` | `false` | Allow self-signed certs; requires non-empty pin set |
| `max_cert_chain_depth` | `integer` | 5 | Maximum certificate chain depth |

---

## `[mem_hygiene]`

Opt-in runtime memory-growth monitor. **Disabled by default** — the
supervisor never spawns the sampling task unless `enabled = true`. When
enabled it samples process RSS at `interval` and emits a
`memory.leak_suspected` event when sustained monotonic growth is
detected.

```toml
[mem_hygiene]
enabled = true
interval = "60s"
window_samples = 30
growth_threshold = "64MiB"
growth_rate_per_min = "2MiB"
min_rising_fraction = 0.8
rss_high = "1GiB"
cgroup_watch = true
cgroup_pressure_pct = 90.0
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Spawn the RSS sampling task |
| `interval` | `duration` | `"60s"` | Sampling cadence → **E** if zero-length (would panic the interval task) |
| `window_samples` | `integer` | 30 | Sliding-window sample count → **E** if `0` |
| `growth_threshold` | `bytesize` | `"64MiB"` | Net growth floor; window first→last delta must exceed this |
| `growth_rate_per_min` | `bytesize` | `"2MiB"` | Average growth rate floor per minute |
| `min_rising_fraction` | `float` | `0.8` | Fraction of adjacent sample pairs that must be non-decreasing, in `(0, 1]` → **E** outside range |
| `rss_high` | `bytesize` | absent | Absolute RSS high-water mark; crossing emits a high-water event |
| `cgroup_pressure_pct` | `float` | absent | cgroup `memory.max` pressure threshold `(0, 100]`; requires `cgroup_watch = true` → **E** outside range; **W** if set without `cgroup_watch` |
| `cgroup_watch` | `bool` | `false` | Enable cgroup memory watching on Linux |

---

## `[updater]`

Embedded auto-updater. **Disabled by default** — the supervisor never
spawns the update polling thread unless `enabled = true`. Manual `spt
update check|status|download|apply|now` commands always work regardless
of this setting.

```toml
[updater]
enabled = true
mode = "warn"
schedule = "0 6 * * *"
source = "github"
github_repo = "supermarsx/ssh-perma-tunnel"
github_channel = "stable"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Spawn the background polling thread |
| `mode` | `string` | `"off"` | `off`, `check`, `warn`, or `auto` → **E** on invalid; **W** `updater_auto_but_disabled` when `"auto"` without `enabled = true` |
| `schedule` | `string` | `"0 6 * * *"` | 5-field cron expression (UTC); mutually exclusive with `interval` → **E** if both set |
| `interval` | `duration` | absent | Humantime polling interval, e.g. `"24h"`; mutually exclusive with `schedule` |
| `source` | `string` | `"github"` | `github`, `url`, or `static` → **E** on invalid |
| `github_repo` | `string` | `"supermarsx/ssh-perma-tunnel"` | `<owner>/<repo>` for `source = "github"` |
| `github_channel` | `string` | `"stable"` | `stable` (skip pre-releases) or `prerelease` |
| `url` | `string` | absent | HTTPS release-manifest URL for `source = "url"` → **E** if absent when needed |
| `url_index` | `string` | absent | URL of the `release-manifest.json` sibling |
| `url_fingerprint` | `string` | absent | SHA-256 pin for the manifest body → **E** if absent for `source = "url"` |
| `static_dir` | `string` | absent | Local artifact directory for `source = "static"` → **E** if absent when needed |

### `[updater.window]`

Auto-install only fires inside this time window. Omit the block to
allow install at any tick.

```toml
[updater.window]
allow_from = "02:00"
allow_to   = "06:00"
timezone   = "UTC"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `allow_from` | `string` | absent | HH:MM start of maintenance window (24-hour) |
| `allow_to` | `string` | absent | HH:MM end of maintenance window (24-hour) |
| `timezone` | `string` | `"UTC"` | IANA timezone for window evaluation |

### `[updater.staging]`

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `dir` | `string` | `<state_dir>/updates` | Staging directory for downloaded artifacts |
| `keep_last` | `integer` | 3 | Number of past staged builds to retain |

### `[updater.verify]`

Signature and checksum requirements. Defaults are strict.

```toml
[updater.verify]
require_minisign = true
minisign_pubkey  = "/etc/spt/minisign.pub"
require_sha256sums = true
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `require_minisign` | `bool` | `true` | Require valid minisign signature → **W** `updater_minisign_disabled` if `false` |
| `minisign_pubkey` | `string` | absent | Path to the trusted minisign public key → **E** if absent when `require_minisign = true` |
| `require_sha256sums` | `bool` | `true` | Require SHA-256 checksum verification |
| `gpg_pubkey` | `string` | absent | GPG public key path for `SHA256SUMS.asc` verification; when present, GPG verification is mandatory |

### `[updater.action]`

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `restart_supervisor` | `bool` | `true` | Send the supervisor a reload signal after a successful install |
| `notify_audit` | `bool` | `true` | Emit a structured audit event on every install |
| `post_install_hook` | `string` | absent | Executable run after install; receives `$SPT_UPDATE_VERSION` and `$SPT_UPDATE_ARTIFACT` |

---

## `[diagnostics]`

Controls the default settings for `spt diagnose bundle`.

```toml
[diagnostics]
bundle_dir = "/var/lib/spt/diag"
include_recent_logs = true
include_status = true
include_stats = true
include_sessions = false
include_service_definitions = true
redact = true
max_bundle_size = "50MiB"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `bundle_dir` | `string` | `<state_dir>/diag` | Output directory for diagnostic bundles |
| `include_recent_logs` | `bool` | `true` | Include a recent log tail |
| `include_status` | `bool` | `true` | Include a status snapshot |
| `include_stats` | `bool` | `true` | Include a stats snapshot |
| `include_sessions` | `bool` | `false` | Include per-session detail |
| `include_service_definitions` | `bool` | `false` | Include generated service unit copies |
| `redact` | `bool` | `true` | Redact secrets and auth material from the bundle |
| `max_bundle_size` | `bytesize` | absent | Cap on total bundle size |

---

## `[benchmark]`

Controls the `spt benchmark` subcommand and guards against accidental
production impact.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Master enable for the benchmark surface |
| `default_duration` | `duration` | `"30s"` | Default test run duration |
| `max_duration` | `duration` | `"5m"` | Maximum allowed test duration |
| `max_connections` | `integer` | absent | Maximum concurrent test connections |
| `max_bytes_per_second` | `bytesize` | absent | Maximum throughput per direction |
| `max_packets_per_second` | `integer` | absent | Maximum packet rate |
| `require_explicit_target` | `bool` | `true` | Refuse benchmark without `--target` profile/forward |
| `allow_production_impact` | `bool` | `false` | Permit tests that may degrade live traffic |
| `results_dir` | `string` | absent | Directory for benchmark result files |

---

## `[capabilities]`

Fleet and admin feature gates. These fields can be set in config or
enforced through Windows Group Policy Object (GPO) bindings. They gate
higher-risk optional surfaces while keeping the core tunnel runtime
minimal.

> **Deprecated keys:** `ssh2_backend` and `allow_libssh2` are stripped
> by `spt config migrate --to 2`. libssh2 was removed in t7-Phase0;
> `russh` is the only SSH2 backend.

```toml
[capabilities]
allow_gssapi             = false
allow_sspi               = false
allow_gssapi_delegation  = false
allow_ntlm_fallback      = false
allow_post_quantum_kex   = false
allow_ml_kem             = false
require_post_quantum_kex = false
allow_dynamic_proxy      = true
allow_sftp               = true
allow_filesystem_mounts  = false
allow_windows_drive_mounts = false
allow_writeback_cache    = false
allow_windows_event_log  = false
allow_gpo_policy_writes  = false
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `allow_gssapi` | `bool` | `false` | Permit GSSAPI/Kerberos authentication and key exchange (Unix) |
| `allow_sspi` | `bool` | `false` | Permit Windows SSPI/Negotiate authentication |
| `allow_gssapi_delegation` | `bool` | `false` | Permit GSSAPI credential delegation globally |
| `allow_ntlm_fallback` | `bool` | `false` | Permit NTLM fallback through SSPI/Negotiate |
| `allow_post_quantum_kex` | `bool` | `false` | Permit post-quantum SSH KEX algorithms (`mlkem*`, `sntrup761*`) |
| `allow_ml_kem` | `bool` | `false` | Permit ML-KEM hybrid SSH KEX specifically; requires `allow_post_quantum_kex` |
| `require_post_quantum_kex` | `bool` | `false` | Require PQ KEX for eligible SSH2 profiles; requires `allow_post_quantum_kex = true` |
| `allow_dynamic_proxy` | `bool` | `false` | Permit dynamic SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT proxy listeners |
| `allow_sftp` | `bool` | `false` | Permit SFTP operations over SSH |
| `allow_filesystem_mounts` | `bool` | `false` | Permit SFTP-backed filesystem mounts (FUSE/macFUSE/WinFsp) |
| `allow_windows_drive_mounts` | `bool` | `false` | Permit Windows drive-letter mounts backed by SFTP |
| `allow_writeback_cache` | `bool` | `false` | Permit writeback caching for SFTP mounts; requires `allow_filesystem_mounts` |
| `allow_windows_event_log` | `bool` | `false` | Permit Windows Event Log registration and writes |
| `allow_gpo_policy_writes` | `bool` | `false` | Permit CLI writes to the Windows GPO registry policy hive |

---

## `[service]`

Shapes `spt service install` from config instead of only CLI flags.
Every field is optional; absent fields preserve the existing
CLI-flag-driven behaviour.

```toml
[service]
description = "spt tunnel supervisor"
user = "spt"
group = "spt"
restart_policy = "on-failure"
sd_notify = true
stdout = "/var/log/spt/stdout.log"
stderr = "/var/log/spt/stderr.log"
watchdog_sec = 30

[service.env]
RUST_LOG = "info"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `description` | `string` | absent | Service description string |
| `user` | `string` | absent | User to run as (system scope) |
| `group` | `string` | absent | Group to run as (system scope) |
| `env` | table | absent | Extra environment variables baked into the generated unit |
| `restart_policy` | `string` | absent | `always`, `on-failure`, or `never` |
| `sd_notify` | `bool` | absent | Enable systemd `Type=notify` and `sd_notify(3)` (Linux only) |
| `stdout` | `string` | absent | Standard-output log path (launchd / SysV) |
| `stderr` | `string` | absent | Standard-error log path (launchd / SysV) |
| `watchdog_sec` | `integer` | absent | systemd `WatchdogSec=` in seconds; omit to disable watchdog |

---

## `[round_robin]`

Endpoint-cycling policy. **Disabled by default** (`enabled = false`).
When enabled the supervisor picks endpoints using the configured
`policy` instead of the legacy priority/weight failover selector.

The table is only serialised when it differs from the defaults, keeping
canonical configs minimal.

```toml
[round_robin]
enabled = true
policy = "weighted"
dns_round_robin = false
dns_refresh_interval = "60s"
cooldown_after_failure = "30s"
sticky_session_ttl = "5m"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Enable endpoint cycling |
| `policy` | `string` | `"round-robin"` | `round-robin`, `random`, `weighted`, `sticky`, or `least-errors` |
| `dns_round_robin` | `bool` | `false` | Expand endpoint hostnames into A/AAAA records and cycle those too — **not implemented** → **W** `dns_round_robin_not_active` |
| `dns_refresh_interval` | `duration` | `"60s"` | How often to re-resolve endpoint hostnames |
| `cooldown_after_failure` | `duration` | `"30s"` | Skip a failing endpoint for at least this long after a failure |
| `sticky_session_ttl` | `duration` | `"5m"` | Pin duration for `policy = "sticky"` before advancing to the next endpoint |

---

## `[status_api]`

Read-only HTTP/JSON status API. **Disabled by default** (`enabled =
false`). Exposes the same status snapshot as `spt tunnel stats` over a
stable JSON endpoint. Non-loopback binds require TLS and an
authenticated auth mode. Anonymous (`mode = "none"`) on non-loopback
binds → **W** `status_api_anonymous_non_loopback` (the server crate
refuses to start unless explicitly overridden).

```toml
[status_api]
enabled = true
bind = "127.0.0.1:9617"
read_only = true
expose_metrics = true
rate_limit_rps = 1.0

[status_api.tls]
enabled = false
cert_file = ""
key_file = ""

[status_api.auth]
mode = "bearer"
token_from = "secret://status/api-token"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Start the status API server |
| `bind` | `string` | `"127.0.0.1:9617"` | TCP bind address |
| `read_only` | `bool` | `true` | Reserved; no write paths are wired — currently a no-op |
| `expose_metrics` | `bool` | `true` | Expose `/v1/metrics` (Prometheus format) |
| `rate_limit_rps` | `float` | `1.0` | Per-client (per remote IP) rate limit in requests/second |

### `[status_api.tls]`

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Enable rustls server-side TLS → **E** `status_api_tls_missing_cert` / `status_api_tls_missing_key` if enabled but paths empty |
| `cert_file` | `string` | `""` | PEM certificate chain path |
| `key_file` | `string` | `""` | PEM private key path |

### `[status_api.auth]`

Authentication mode, selected by the `mode` field. The `mode` field and
its per-mode parameters are flattened into the same `[status_api.auth]`
table.

> **Known gap (E5-F13):** Unknown keys inside `[status_api.auth]` escape
> the `serde_ignored` unknown-key detector because the mode enum is
> internally tagged and flattened. Typos in this table are silently
> ignored rather than reported. Use `spt config validate --strict` and
> verify auth works after any change.

| `mode` value | Extra fields | Notes |
|-------------|-------------|-------|
| `none` | — | Anonymous; server refuses non-loopback binds unless overridden → **W** |
| `bearer` | `token_from` (secret ref) | Bearer token via `Authorization: Bearer` header |
| `basic` | `user` (string), `password_from` (secret ref) | HTTP basic auth |
| `mtls` | `ca_bundle` (path), `allowed_subjects` ([string]) | mTLS; requires `tls.enabled = true` → **E**; empty `allowed_subjects` → **E** |

---

## `[[profiles]]`

A profile groups all configuration for one persistent SSH tunnel: the
SSH2/SSH3 connection parameters, authentication, trust, cryptography,
keepalive, reconnect policy, failover endpoints, forwards, SFTP mounts,
scripting hooks, and obfuscation transport.

All profiles in a config share the singleton global tables. Profile
names must be unique across the merged config.

```toml
[[profiles]]
name     = "edge-prod"
enabled  = true
protocol = "ssh2"
host     = "bastion.example.com"
port     = 22
user     = "tunnel"
connect_timeout = "10s"
dns_resolution  = "per_attempt"
network_change_reconnect = true
startup  = "eager"
failure_policy = "retry"
tags = ["prod", "edge"]
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | Unique profile identifier → **E** on duplicate |
| `description` | `string` | absent | Free-form human-readable description |
| `enabled` | `bool` | `true` | Whether the supervisor starts this profile |
| `protocol` | `string` | — (required) | `ssh2` or `ssh3` → **E** on invalid |
| `host` | `string` | absent | SSH2 target hostname → **E** if absent for SSH2 profiles |
| `port` | `integer` | `22` | SSH2 port |
| `endpoint` | `string` | absent | SSH3 endpoint URL → **E** if absent for SSH3 profiles |
| `acknowledge_experimental` | `bool` | `false` | Required for SSH3 → **E** `ssh3_missing_experimental_ack` if not set |
| `user` | `string` | absent | Remote user name |
| `connect_timeout` | `duration` | absent | Legacy top-level alias for `connection.connect_timeout` |
| `dns_resolution` | `string` | `"per_attempt"` | `per_attempt` (re-resolve on every connect) or `once` |
| `network_change_reconnect` | `bool` | `false` | Force reconnect when a network change event is detected |
| `startup` | `string` | `"eager"` | `eager` (start immediately) or `lazy` (start on first client connection) |
| `failure_policy` | `string` | `"retry"` | `retry`, `fail_profile`, or `fail_process` |
| `tags` | `[string]` | absent | Free-form tags used for filtering and grouping |

### `[profiles.connection]`

Per-profile TCP and SSH channel parameters. These override the global
`[network.offload]` defaults for this profile.

```toml
[profiles.connection]
connect_timeout      = "10s"
auth_timeout         = "15s"
handshake_timeout    = "15s"
channel_open_timeout = "10s"
channel_window_size  = "2MiB"
channel_max_packet_size = "32KiB"
tcp_nodelay          = true
socket_keepalive     = true
keepalive_idle       = "30s"
keepalive_interval   = "10s"
keepalive_retries    = 3
read_timeout         = "0s"
write_timeout        = "0s"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `connect_timeout` | `duration` | runtime default | TCP connect timeout |
| `auth_timeout` | `duration` | runtime default | SSH authentication timeout |
| `handshake_timeout` | `duration` | runtime default | SSH key exchange timeout |
| `channel_open_timeout` | `duration` | runtime default | SSH channel open timeout |
| `channel_window_size` | `bytesize` | backend default | SSH channel receive window size |
| `channel_max_packet_size` | `bytesize` | backend default | Maximum SSH channel packet size |
| `tcp_nodelay` | `bool` | `false` | Set `TCP_NODELAY` on the tunnel socket |
| `socket_keepalive` | `bool` | `false` | Enable OS-level socket keepalive |
| `keepalive_idle` | `duration` | OS default | Idle time before first keepalive probe |
| `keepalive_interval` | `duration` | OS default | Interval between keepalive probes |
| `keepalive_retries` | `integer` | OS default | Probes before giving up and closing |
| `read_timeout` | `duration` | `"0s"` | Per-read timeout (`0s` = unbounded) |
| `write_timeout` | `duration` | `"0s"` | Per-write timeout (`0s` = unbounded) |

### `[profiles.crypto]`

SSH2 algorithm allow-lists. Empty lists defer to the backend defaults.

```toml
[profiles.crypto]
policy = "modern"
allow_deprecated = false
warn_on_deprecated = true
kex_algorithms = [
  "mlkem768x25519-sha256",
  "curve25519-sha256",
]
ciphers = ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"]
macs = ["hmac-sha2-256-etm@openssh.com"]
host_key_algorithms = ["ssh-ed25519"]
compression = ["none"]
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `policy` | `string` | `"modern"` | `modern`, `interop`, or `legacy` |
| `allow_deprecated` | `bool` | `false` | Allow deprecated algorithms (e.g. SHA-1 MACs) |
| `warn_on_deprecated` | `bool` | `true` | Warn when deprecated algorithms are negotiated |
| `ciphers` | `[string]` | absent | Cipher allow-list |
| `kex_algorithms` | `[string]` | absent | Key exchange allow-list; PQ-KEX names require `capabilities.allow_post_quantum_kex = true` |
| `macs` | `[string]` | absent | MAC algorithm allow-list |
| `host_key_algorithms` | `[string]` | absent | Host key algorithm allow-list |
| `compression` | `[string]` | absent | Compression allow-list |

### `[profiles.auth]`

SSH authentication method and credentials for this profile. Secret
values (`passphrase`, `password`, `token`) accept `secret://`,
`env:`, or `file:` references and are never emitted in `spt config
render` output without `--redacted`.

```toml
[profiles.auth]
method = "public_key"
identity_file = "~/.ssh/id_ed25519"
passphrase = "secret://ssh/edge/passphrase"
agent = false
keyboard_interactive = false
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `method` | `string` | — (required) | Auth method: `public_key`, `password`, `agent`, `bearer_token`, `keyboard_interactive`, `kerberos` (alias `gssapi`, `gssapi-with-mic`), or `sspi` (alias `negotiate`) |
| `identity_file` | `string` | absent | Path to SSH2 private key file |
| `certificate_file` | `string` | absent | Path to OpenSSH certificate for the identity |
| `passphrase` | `string` | absent | Private key passphrase (secret reference or inline) |
| `password` | `string` | absent | SSH2 password (secret reference or inline) |
| `token` | `string` | absent | SSH3 bearer token (secret reference or inline) |
| `agent` | `bool` | `false` | Offer keys from the SSH agent |
| `identity_hint` | `string` | absent | Agent key identity hint |
| `keyboard_interactive` | `bool` | `false` | Allow keyboard-interactive fallback |
| `gssapi_service` | `string` | absent | GSSAPI service principal, e.g. `host/server.example.com` |
| `gssapi_principal` | `string` | absent | GSSAPI client principal hint |
| `gssapi_delegate` | `bool` | `false` | Permit GSSAPI credential delegation for this profile |
| `sspi_service` | `string` | absent | Windows SSPI service principal name |
| `sspi_principal` | `string` | absent | Windows SSPI client principal hint |
| `sspi_delegate` | `bool` | `false` | Permit SSPI credential delegation |
| `sspi_allow_ntlm_fallback` | `bool` | `false` | Permit NTLM fallback through SSPI/Negotiate |
| `oidc_issuer` | `string` | absent | OIDC issuer URL (SSH3) |
| `oidc_client_id` | `string` | absent | OIDC client ID (SSH3) |

### `[profiles.trust]`

Host key verification policy.

```toml
[profiles.trust]
mode = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict = true
accept_new = false
pin_sha256 = ["SHA256:AAAA..."]
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `mode` | `string` | `"known_hosts"` | `known_hosts` or `pinned` |
| `known_hosts_file` | `string` | `~/.ssh/known_hosts` | Path to the `known_hosts` file |
| `strict` | `bool` | `true` | Reject unknown or changed host keys |
| `accept_new` | `bool` | `false` | Trust-on-first-use: accept unknown keys and add them to the file |
| `pin_sha256` | `[string]` | absent | SHA-256 host-key pins in `SHA256:<base64>` format; all pins must match |

### `[profiles.tls]`

TLS settings for SSH3 profiles (QUIC transport layer).

```toml
[profiles.tls]
server_name = "edge.example.com"
system_roots = true
ca_file = "/etc/ssl/certs/internal-ca.pem"
pin_sha256 = ["SHA256:AAAA..."]
allow_self_signed = false
max_cert_chain_depth = 5
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `server_name` | `string` | absent | SNI / certificate verification name |
| `system_roots` | `bool` | `true` | Trust system root CA store |
| `ca_file` | `string` | absent | Additional PEM CA bundle |
| `pin_sha256` | `[string]` | absent | SHA-256 certificate pins |
| `allow_self_signed` | `bool` | `false` | Allow self-signed certificates |
| `max_cert_chain_depth` | `integer` | 5 | Maximum intermediates between leaf and trust anchor |

### `[profiles.ssh3]`

SSH3-specific QUIC and HTTP/3 parameters. Only used when
`protocol = "ssh3"`.

```toml
[profiles.ssh3]
draft = "michel-remote-terminal-http3-00"
protocol_token = "remote-terminal"
enable_datagrams = true
idle_timeout = "30s"
keepalive = "10s"
max_streams = 128
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `draft` | `string` | absent | HTTP/3 reference draft identifier |
| `protocol_token` | `string` | absent | Extended CONNECT protocol token |
| `enable_datagrams` | `bool` | `false` | Enable QUIC datagrams for UDP forwarding |
| `idle_timeout` | `duration` | absent | QUIC connection idle timeout |
| `keepalive` | `duration` | absent | QUIC keepalive ping interval |
| `max_streams` | `integer` | absent | Maximum concurrent QUIC bidirectional streams |

### `[profiles.keepalive]`

SSH-level application keepalive (distinct from TCP socket keepalive
which is in `[profiles.connection]`).

```toml
[profiles.keepalive]
interval   = "20s"
timeout    = "5s"
max_missed = 3
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `interval` | `duration` | `"60s"` | Interval between SSH keepalive probes sent to the server |
| `timeout` | `duration` | `"10s"` | Per-probe response timeout |
| `max_missed` | `integer` | 3 | Consecutive missed probes before the session is replaced |

### `[profiles.reconnect]`

Exponential backoff policy for reconnect attempts after session loss.

```toml
[profiles.reconnect]
initial_delay  = "1s"
max_delay      = "2m"
jitter         = "30%"
reset_after    = "5m"
max_attempts   = 0
retry_auth_failures = false
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `initial_delay` | `duration` | `"1s"` | First retry delay |
| `max_delay` | `duration` | `"5m"` | Maximum delay cap |
| `jitter` | `string` | `"20%"` | Percentage jitter applied to each delay |
| `reset_after` | `duration` | `"10m"` | Reset backoff after this stable uptime |
| `max_attempts` | `integer` | `0` | Maximum retry count; `0` = unlimited |
| `retry_auth_failures` | `bool` | `false` | Retry on authentication failure (not just network failures) |

### `[profiles.instability]`

Heuristic instability detector. When triggered it takes a configured
action such as failover or increased keepalive frequency.

```toml
[profiles.instability]
enabled              = true
window               = "10m"
max_disconnects      = 4
max_keepalive_misses = 2
max_latency_p95      = "500ms"
min_successful_uptime = "3m"
action               = "failover"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | `bool` | `false` | Enable instability detection |
| `window` | `duration` | `"10m"` | Sliding window for event counting |
| `max_disconnects` | `integer` | absent | Maximum disconnects within the window before triggering |
| `max_keepalive_misses` | `integer` | absent | Maximum keepalive misses within the window |
| `max_latency_p95` | `duration` | absent | Maximum acceptable p95 round-trip latency |
| `min_successful_uptime` | `duration` | absent | Minimum stable uptime required to clear the instability flag |
| `action` | `string` | `"emit_event"` | `mark_degraded`, `failover`, `increase_keepalive`, `increase_backoff`, `emit_event`, or `restart_session` |

### `[profiles.failover]`

Controls how the supervisor selects among the profile's `[[endpoints]]`
when the current connection is unhealthy.

```toml
[profiles.failover]
mode         = "priority"
health_check = "ssh_handshake"
fail_after   = 3
restore_after = "2m"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `mode` | `string` | `"priority"` | `priority`, `weighted`, or `manual` |
| `health_check` | `string` | `"tcp_connect"` | `tcp_connect`, `ssh_handshake`, `ssh_auth_preflight`, or `ssh3_endpoint` |
| `fail_after` | `integer` | 3 | Consecutive failures before failover |
| `restore_after` | `duration` | `"30s"` | Minimum stable window on a recovered primary before failback |

### `[profiles.limits]`

Per-profile rate and connection limits.

```toml
[profiles.limits]
max_active_connections        = 1000
max_new_connections_per_second = 100
max_bytes_per_second_in       = "100MiB"
max_bytes_per_second_out      = "100MiB"
max_connection_lifetime       = "24h"
throttle_algorithm            = "token_bucket"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `max_active_connections` | `integer` | absent | Maximum simultaneous forwarded connections |
| `max_new_connections_per_second` | `integer` | absent | Accept rate cap |
| `max_bytes_per_second_in` | `bytesize` | absent | Inbound byte-rate cap |
| `max_bytes_per_second_out` | `bytesize` | absent | Outbound byte-rate cap |
| `max_bits_per_second_in` | `string` | absent | Inbound bit-rate (display label only, not enforced separately) |
| `max_bits_per_second_out` | `string` | absent | Outbound bit-rate (display label only) |
| `throttle_algorithm` | `string` | absent | Throttle algorithm hint for the rate limiter |
| `max_connection_lifetime` | `duration` | absent | Maximum lifetime before forced close |

### `[[profiles.endpoints]]`

Named endpoints for failover and round-robin selection. Each endpoint
overrides the profile-level `host`/`port` for its slot. When a profile
has one or more endpoints the failover selector uses them; the
profile-level `host` acts as a last-resort fallback.

```toml
[[profiles.endpoints]]
name     = "primary"
host     = "bastion-us-west.example.com"
port     = 22
priority = 0
weight   = 100
user     = "tunnel"

[[profiles.endpoints]]
name     = "dr"
host     = "bastion-us-east.example.com"
port     = 22
priority = 10
weight   = 50
```

Each endpoint may also carry its own `[auth]` sub-table with the same
fields as `[profiles.auth]`. When present it fully overrides (not
field-merges) the profile-level auth for that endpoint.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | Unique endpoint identifier within the profile → **E** on duplicate |
| `host` | `string` | — (required) | Endpoint hostname |
| `port` | `integer` | — (required) | Endpoint port |
| `priority` | `integer` | absent | Lower value = higher priority for `failover.mode = "priority"` |
| `weight` | `integer` | absent | Weight for `failover.mode = "weighted"` or `policy = "weighted"` |
| `user` | `string` | profile user | Per-endpoint username override |
| `auth` | table | absent | Full `[profiles.auth]`-structured override; falls back to profile auth if absent |

### `[[profiles.hops]]`

Multi-hop SSH chain (SSH ProxyJump equivalent). Each hop opens a
`direct-tcpip` channel through the previous session to reach the next
host. SOCKS5 and HTTP CONNECT proxies are also supported as hop kinds.

```toml
[[profiles.hops]]
name     = "jump1"
protocol = "ssh2"
host     = "jump.example.com"
port     = 22
user     = "ops"
kind     = "ssh"
target_resolve = "previous-hop"
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | Hop identifier |
| `protocol` | `string` | — (required) | `ssh2` |
| `host` | `string` | — (required) | Hop hostname |
| `port` | `integer` | — (required) | Hop port |
| `user` | `string` | absent | Remote user on this hop |
| `kind` | `string` | `"ssh"` | `ssh` (nested SSH session), `socks5` (RFC 1928 CONNECT), or `http-connect` (HTTP CONNECT) |
| `proxy_username` | `string` | absent | Proxy username for `socks5` / `http-connect` hops |
| `proxy_password_ref` | `string` | absent | `secret://` reference for the proxy password |
| `target_resolve` | `string` | absent | Where to resolve the next hop's hostname: `local`, `remote`, or `previous-hop` |
| `auth` | table | profile auth | Per-hop `[auth]` block; falls back to profile auth if absent |
| `trust` | table | profile trust | Per-hop `[trust]` block; falls back to profile trust if absent |

### `[[profiles.forwards]]`

Port forwards created inside the SSH session. Each forward has a
direction (`type`), a transport layer (`transport`), a bind address,
and a target.

```toml
[[profiles.forwards]]
name           = "api"
type           = "local"
transport      = "tcp"
bind           = "127.0.0.1:18080"
target         = "api.internal:8080"
target_resolve = "remote"
required       = true
idle_timeout   = "10m"
max_connections = 256
```

**Aliases:** `listen` is accepted as an alias for `bind`; `connect` is
an alias for `target`.

**Non-loopback binds** require `expose = true` → **E**
`non_loopback_bind_without_expose`.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | Unique forward name within the profile → **E** on duplicate |
| `type` | `string` | — (required) | `local`, `remote`, or `dynamic` → **E** on invalid |
| `transport` | `string` | — (required) | `tcp` or `udp`; UDP requires `protocol = "ssh3"` → **E** for SSH2 + UDP (except `tcp-framed` mode) |
| `bind` | `string` | absent | Bind address in `host:port` form |
| `listen` | `string` | absent | Alias for `bind` |
| `bind_mode` | `string` | `"loopback"` | `loopback`, `specific_ip`, `specific_interface`, `all_interfaces`, or `auto_interface` |
| `bind_interface` | `string` | absent | Specific network interface name |
| `bind_interface_preference` | `[string]` | absent | Ordered preference list for auto-interface selection |
| `bind_ipv6` | `string` | profile default | `auto`, `prefer`, or `disable` |
| `expose` | `bool` | `false` | Required for non-loopback binds |
| `target` | `string` | absent | Target address |
| `connect` | `string` | absent | Alias for `target` |
| `target_resolve` | `string` | `"remote"` | Where to resolve `target`: `local` or `remote` |
| `required` | `bool` | `false` | Forward failure marks the profile degraded |
| `dns_names` | `[string]` | absent | DNS names registered in the built-in resolver for this forward's local port |
| `sni_name` | `string` | absent | TLS SNI hint passed to TLS clients connecting through this forward |
| `idle_timeout` | `duration` | absent | Close idle TCP connections after this duration |
| `max_connections` | `integer` | absent | Per-forward connection cap |
| `on_bind_conflict` | `string` | `"fail"` | `fail`, `retry`, or `next_port` |
| `max_bytes_per_second_in` | `bytesize` | absent | Per-forward inbound rate cap |
| `max_bytes_per_second_out` | `bytesize` | absent | Per-forward outbound rate cap |
| `max_burst_bytes_in` | `bytesize` | absent | Inbound burst size |
| `max_burst_bytes_out` | `bytesize` | absent | Outbound burst size |
| `max_new_connections_per_second` | `integer` | absent | Accept rate cap for this forward |
| `proxy_protocols` | `[string]` | all | Accepted proxy protocols for `type = "dynamic"`: `all`, `socks4`, `socks4a`, `socks5`, `http_connect` |
| `allow_targets` | `[string]` | absent | Destination allow-list for dynamic forwards (host globs or CIDR/IP rules); absent = allow all |
| `deny_targets` | `[string]` | absent | Destination deny-list for dynamic forwards; deny rules win over allow rules |
| `udp_idle_timeout` | `duration` | `"30s"` | Per-flow idle timeout for UDP forwards |
| `max_datagram_size` | `integer` | absent | Maximum UDP datagram size |
| `max_packets_per_second` | `integer` | absent | Maximum UDP packet rate |
| `udp_mode` | `string` | `"tcp-framed"` | SSH2 UDP framing mode: `tcp-framed` (length-prefixed `direct-tcpip`) or `uds-bridge` (`direct-streamlocal`; russh only, Unix only) |
| `kind` | `string` | absent | Link kind override: `tcp`, `local_uds`, or `remote_uds` |
| `remote_socket_path` | `string` | absent | Server-side UNIX socket path for `local_uds` or `remote_uds` link kinds |
| `local_socket_path` | `string` | absent | Client-side UNIX socket path (Unix only) for `local_uds` or `remote_uds` link kinds |

### `[[profiles.sftp_mounts]]`

SFTP-backed filesystem and drive mounts. Requires
`capabilities.allow_sftp = true` and
`capabilities.allow_filesystem_mounts = true`. Windows drive-letter
mounts additionally require `capabilities.allow_windows_drive_mounts =
true`.

```toml
[[profiles.sftp_mounts]]
name        = "data"
enabled     = true
remote_path = "/srv/data"
mount_point = "/mnt/spt-data"
read_only   = true
cache       = "metadata"
allow_other = false
required    = false
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | `string` | — (required) | Mount identifier, unique within the profile |
| `enabled` | `bool` | `true` | Whether to mount on profile connect |
| `remote_path` | `string` | — (required) | Remote SFTP path to mount |
| `mount_point` | `string` | absent | Local mount point (Unix/macOS/FUSE); mutually exclusive with `drive_letter` |
| `drive_letter` | `string` | absent | Windows drive letter, e.g. `S:` (requires `allow_windows_drive_mounts`) |
| `read_only` | `bool` | `false` | Mount as read-only |
| `cache` | `string` | `"none"` | `none`, `metadata`, or `writeback` (writeback requires `allow_writeback_cache = true`) |
| `allow_other` | `bool` | `false` | Allow other local users to access the mount (FUSE `allow_other`) |
| `required` | `bool` | `false` | Treat mount failure as a profile failure |

### `[profiles.script]`

Rhai scripting hooks invoked at profile lifecycle events. When absent
the scripting engine is not instantiated and all hook call sites are
no-ops with zero allocation overhead. See [Scripting](scripting.md).

```toml
[profiles.script]
path = "/etc/spt/hooks.rhai"

[profiles.script.hooks]
pre_connect      = "before_dial"
post_connect     = "after_auth"
on_forward_state = "on_forward"
on_disconnect    = "after_disconnect"
on_event         = "any_event"

[profiles.script.limits]
max_operations  = 1_000_000
max_call_levels = 32
max_string_size = 65_536
max_array_size  = 4_096
max_modules     = 0
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `path` | `string` | — (required) | Filesystem path to the Rhai script |
| `hooks.pre_connect` | `string` | absent | Function name called before SSH connect attempt |
| `hooks.post_connect` | `string` | absent | Function name called after auth completes |
| `hooks.on_forward_state` | `string` | absent | Function name called on forward state-machine transitions |
| `hooks.on_disconnect` | `string` | absent | Function name called on session disconnect |
| `hooks.on_event` | `string` | absent | Catch-all function called for any structured event payload |
| `limits.max_operations` | `integer` | 1,000,000 | Maximum Rhai operations per hook invocation |
| `limits.max_call_levels` | `integer` | 32 | Maximum call-stack depth |
| `limits.max_string_size` | `integer` | 65,536 | Maximum string size in bytes |
| `limits.max_array_size` | `integer` | 4,096 | Maximum array size in elements |
| `limits.max_modules` | `integer` | 0 | Maximum modules loadable per session; `0` disables module loading |

### `[profiles.transport]`

Transport-layer selection. Absent = plain TCP. When present, the
`obfuscation` sub-table selects an obfuscation mode and its
configuration. See [Transports](transports.md) for runtime wiring.

```toml
[profiles.transport.obfuscation]
kind = "obfs4"
node_id    = "<hex-20-bytes>"
public_key = "<hex-32-bytes>"
iat_mode   = 0
```

The `kind` field is the discriminator. Available variants:

#### `kind = "obfs4"` (Tor PT obfs4 bridge)

| Field | Type | Notes |
|-------|------|-------|
| `node_id` | `string` | Hex-encoded 20-byte server node ID |
| `public_key` | `string` | Hex-encoded 32-byte server identity public key |
| `iat_mode` | `integer` | IAT mode: `0`, `1`, or `2` |

#### `kind = "meek-http"` (meek-style HTTPS-CONNECT fronting)

| Field | Type | Notes |
|-------|------|-------|
| `url` | `string` | Fronting HTTPS URL |
| `front_host` | `string` | Optional `Host:` header override (domain fronting) |
| `sni` | `string` | Optional explicit SNI override |

#### `kind = "websocket"` (SSH over WebSocket)

| Field | Type | Notes |
|-------|------|-------|
| `url` | `string` | Endpoint URL (`ws://` or `wss://`) |
| `headers` | array | Extra HTTP headers as `[["Name", "Value"], ...]` |

#### `kind = "shadowsocks"` (Shadowsocks AEAD framing)

| Field | Type | Notes |
|-------|------|-------|
| `method` | `string` | Cipher identifier (e.g. `aes-256-gcm`) |
| `password` | `string` | `secret://ns/name` reference for the pre-shared password |

---

## Examples

The repository ships several annotated examples under `examples/`:

| File | Demonstrates |
|------|-------------|
| `minimal.toml` | Single profile, single local TCP forward, agent auth |
| `jump-host.toml` | Two-hop SSH chain |
| `reverse.toml` | Remote (reverse) forward |
| `ha-failover.toml` | Two endpoints with priority failover and instability detection |
| `zero-trust-https.toml` | Vault-resolved pubkey, host pinning, lazy startup |
| `ssh3.toml` | SSH3 profile with UDP forward over QUIC datagrams |
| `observability.toml` | OTLP logs, Prometheus, syslog-TLS, email + webhook events |
| `updater.toml` | Embedded auto-updater in warn-only mode |
| `mcp.toml` | MCP server with read-only policy |
| `dns-split-horizon.toml` | Split-horizon DNS resolver with synthetic records |
| `multi-profile-fleet.toml` | Multi-bastion fleet with per-profile crypto |
| `headless-ci.toml` | Environment-only secrets for CI/CD pipelines |
| `smtp-relay.toml` | SMTP relay via a local bind |
| `observability-otel.toml` | Full OTLP + Prometheus + remote syslog-TLS stack |
| `remote-config-encrypted.toml` | Remote config with encryption and signature verification |

Validate any example:
```
spt config validate --config examples/ha-failover.toml --strict
```
