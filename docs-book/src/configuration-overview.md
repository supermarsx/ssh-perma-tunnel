# Configuration Overview

`spt` is entirely config-file-driven. Every tunnel, forward, secret
reference, and runtime policy lives in a single TOML file (or a directory
of TOML files). This chapter explains how `spt` finds that file, what the
top-level structure looks like, how validation works, and how to use the
`spt config` subcommands effectively.

For the exhaustive field-by-field reference see
[Configuration Reference](configuration-reference.md). For secret
resolution rules see [Secrets](secrets.md). For the CLI surface see
[CLI Reference](cli-reference.md).

---

## File discovery and precedence

`spt` resolves the active config file in this order:

1. **`--config <PATH>`** explicit flag on every subcommand.
2. **`SPT_CONFIG` environment variable** — same effect as `--config`.
3. **Service-install defaults** when running as an OS service:

   | Platform | Default path |
   |----------|--------------|
   | Linux    | `/etc/spt/spt.toml` |
   | macOS    | `/usr/local/etc/spt/spt.toml` |
   | Windows  | `%PROGRAMDATA%\spt\spt.toml` |

The first source that resolves wins; no merging occurs between sources.

### Directory mode (`--config-dir`)

Pass `--config-dir <DIR>` to load every `*.toml` file in a directory.
Files are processed in lexical filename order. The first file (lowest
lex name) is the **base**: it owns all singleton top-level tables
(`[runtime]`, `[logging]`, `[secrets]`, `[dns]`, `[firewall]`,
`[observability]`, `[events]`, `[mcp]`, `[diagnostics]`, `[benchmark]`).

Every subsequent file may **only** contribute additional `[[profiles]]`
entries. If a non-base file declares any singleton table the loader fails
with a clear diagnostic naming the offending file and table. Profile names
must remain unique across the merged set. All files must declare the same
`version` number.

A typical fleet layout:

```
/etc/spt/conf.d/
  00-global.toml    # [runtime], [logging], [secrets], ...
  10-edge.toml      # [[profiles]] name = "edge-us-west"
  20-db.toml        # [[profiles]] name = "db-replica"
```

---

## `version` field and schema migration

Every config file must begin with a `version` integer at the document
root. The only supported value in this release is `1`. The validator
rejects any other value with the error code `version_unsupported`.

```toml
version = 1
```

### Migration to version 2

`spt config migrate --to 2` rewrites a v1 file in place (or to `--out`)
by removing the two deprecated `[capabilities]` keys that were eliminated
in t7-Phase0:

- `capabilities.ssh2_backend`
- `capabilities.allow_libssh2`

libssh2 was removed from the codebase; `russh` is the only SSH2 backend.
Old configs continue to load and validate without error, but
`spt config validate` emits the deprecation warning
`capabilities_ssh2_backend_deprecated_t7` when either key is present.
Running `spt config migrate --to 2` strips them and bumps `version` to `2`.
The migration is idempotent: v2 input passes through unchanged.

---

## Top-level structure

A complete `spt` config file contains singleton global tables followed
by one or more `[[profiles]]` array entries:

```toml
version = 1

[runtime]          # §9.1 — state dir, threading, reload policy
[logging]          # §9.2 — level, format, destinations, rotation, remote sinks
[secrets]          # §9.3 — backend selection, vault, keychain
[dns]              # §9.4 — built-in resolver, synthetic records, hosts file
[firewall]         # §9.5 — planner platform and ruleset hooks
[network]          # host-level interface, gateway, offload, load-balance policy
[observability]    # §9.6 — metrics, SNMP, Windows Event Log
[events]           # §9.7 — bus scalars, bindings, sinks, commands
[mcp]              # §9.8 — Model Context Protocol server
[mem_hygiene]      # opt-in RSS memory-growth monitor (disabled by default)
[updater]          # embedded auto-updater (disabled by default)
[diagnostics]      # §9.9 — `spt diagnose` bundle defaults
[benchmark]        # §9.10 — `spt benchmark` defaults and guards
[capabilities]     # fleet/admin feature gates (GSSAPI, SFTP, PQ-KEX, …)
[service]          # shapes `spt service install` from config
[round_robin]      # endpoint-cycling policy (disabled by default)
[status_api]       # read-only HTTP/JSON status API (disabled by default)

[[profiles]]       # §9.11 — one or more tunnel profiles
```

Every table is optional except `version` and at least one `[[profiles]]`
entry. Absent tables pick safe defaults.

The `[round_robin]` and `[status_api]` tables are omitted from
serialised output when they are at their defaults (`enabled = false`),
keeping canonical configs minimal.

---

## Environment variable overrides

| Variable | Effect |
|----------|--------|
| `SPT_CONFIG` | Equivalent to `--config <PATH>` |
| `SPT_STATE_DIR` | Overrides `runtime.state_dir` |
| `SPT_LOG_LEVEL` | Overrides `logging.level` |
| `SPT_LOG_FORMAT` | Overrides `logging.format` |
| `SPT_SSPI_USER` | Windows SSPI initiator username |
| `SPT_SSPI_PASS` | Windows SSPI initiator password |
| `SPT_SSPI_KDC_URL` | Windows SSPI KDC URL override |

Environment variables take effect before config-file values where
documented, but the explicit `--config` flag and in-file settings
for non-secret fields generally win over environment values. Secret
credential references (`secret://ns/name`, `env:NAME`, `file:PATH`)
are resolved at session start by the secrets subsystem described in
[Secrets](secrets.md).

---

## Validation: errors vs warnings

`spt config validate` runs the full semantic validator over the config
without starting any tunnel. It prints each diagnostic with its error
code and field path:

```
$ spt config validate --config /etc/spt/spt.toml
✓ valid (0 errors, 2 warnings)

  W  remote_config_no_pin
     runtime.remote_config.fingerprint_sha256 is unset; unattended fetch
     will be refused
```

**Errors** (`E`) block the process from starting. Examples:
- `version_unsupported` — `version` is not `1`
- `duplicate_profile_name` — two profiles share a name
- `remote_config_not_https` — `remote_config.url` must be HTTPS
- `mcp_secret_reveal_disallowed` — `mcp.allow_secret_reveal` must be
  `false`
- `snmp_enterprise_id_required` — SNMP enabled without a PEN
- `updater_minisign_pubkey_required` — minisign required but key unset
- `secrets_encrypt_at_rest_requires_encrypted_backend` — the `env` and
  `auto` backends write secrets in plaintext; `vault` or `keychain`
  required

**Warnings** (`W`) allow startup but surface in the logs. Examples:
- `dns_privileged_port` — DNS listener on a port below 1024
- `firewall_platform_mismatch` — firewall planner set for a different OS
- `network_gateway_default_not_ip` — `[network.gateway].default_gateway`
  is not an IP literal, so it cannot be matched against the live route;
  the gateway guard is otherwise enforced fail-closed at runtime (a
  `require_gateway_match` mismatch refuses the connection)
- `network_offload_flag_unsupported` — only `tcp_nodelay` and
  `socket_keepalive` take effect; other offload flags are inert
- `round_robin_dns_round_robin_not_active` — DNS A/AAAA expansion of
  endpoint hostnames is not implemented
- `network_load_balance_least_connections_inert` — `least_connections`
  strategy has no live connection-count signal and is ignored
- `event_command_exec_disabled` — an event command will not fire until
  `allow_exec = true`
- `updater_auto_but_disabled` — `mode = "auto"` without
  `enabled = true` never installs anything

**Strict mode** (`--strict`) promotes any unrecognised TOML key to an
error. This is the recommended CI gate:

```
spt config validate --config /etc/spt/spt.toml --strict
```

---

## `spt config` subcommands

| Subcommand | Purpose |
|------------|---------|
| `spt config validate` | Semantic validation; `--strict` for unknown-key gate |
| `spt config render` | Emit canonical TOML; `--redacted` masks secret values |
| `spt config diff` | Structural diff between two config files |
| `spt config migrate` | Rewrite to a newer schema version (`--to 2`) |
| `spt config encrypt` | Seal the file in an `SPTENC1` authenticated-encryption envelope |
| `spt config decrypt` | Unseal a sealed config file |
| `spt config edit` | In-place encrypted edit (unseal → `$EDITOR` → re-seal) |
| `spt config crypt rotate` | Re-seal under a new key without decrypting to disk |
| `spt config init` | Scaffold a new config from a built-in template |

Full flags and examples are in [CLI Reference](cli-reference.md).

---

## Portable mode

Pass `--portable` to confine every on-disk artifact to a directory next
to the executable. No user directories, OS keychain, journald, or Windows
Event Log are touched.

```
<exe-dir>/spt[.exe]
<exe-dir>/data/state/        # locks, status snapshots
<exe-dir>/data/vault/        # master.key + vault.spt
<exe-dir>/data/logs/spt.log  # file log sink
<exe-dir>/data/config/       # operator config (--config-dir default)
```

| Subsystem | Default | Portable |
|-----------|---------|----------|
| State dir | `BaseDirs::data_local_dir()/spt` | `<exe-dir>/data/state/` |
| Secrets resolver | keychain → vault → env → file | vault → env → file |
| Vault master key | OS keychain | `<exe-dir>/data/vault/master.key` |
| Log file | `<state_dir>/spt.log` | `<exe-dir>/data/logs/spt.log` |
| `~/.ssh/config` | read for `-J` chains | never read |
| journald | available | not installed |
| Windows Event Log | configured writer | no-op |

`spt diagnose` reports `portable_mode = true` and the resolved root in
its top-level summary.

---

## Secret references

Fields that accept secrets (passwords, passphrases, tokens, keys) take
a **secret reference string** rather than inline cleartext:

| Form | Source |
|------|--------|
| `secret://namespace/name` | Resolved by the configured secrets backend |
| `env:VARIABLE_NAME` | Read from the named environment variable |
| `file:/path/to/secret` | Read from a file at that path |

The secrets backend (configured in `[secrets]`) handles `secret://`
references at runtime. `env:` and `file:` forms bypass the backend. See
[Secrets](secrets.md) for the resolver priority, vault operations, and
keychain integration.

The schema uses a `RedactedString` newtype for all secret-bearing fields.
`RedactedString` values are zeroed on drop and never appear in `Debug`
output or `spt config render` without `--redacted`.

---

## Sealed configs (`SPTENC1`)

A config file can be stored on disk in an authenticated-encryption
envelope produced by `spt config encrypt`. The file format begins with
the 8-byte magic `SPTENC1\n` and contains an AES-256-GCM sealed body
with one of three key derivation modes:

- **Passphrase** (Argon2id, m=64 MiB, t=3, p=4 by default)
- **Vault master** (the process vault's 32-byte master key)
- **X25519 recipients** (per-recipient ECDH shared secret)

`spt_config::load` auto-detects the magic bytes. For interactive use the
loader prompts for a passphrase on the terminal. For headless callers
(CI, supervised reloads) use `load_with_key` or supply the key source
via `--passphrase-from env:NAME`.

Remote-config bodies fetched via `[runtime.remote_config]` also support
sealed envelopes when `encryption_key_from` is set.

---

## Full annotated example

The following example covers the most commonly used tables. Every
production config should be validated with `spt config validate --strict`
before deployment.

```toml
# Schema version — the only supported value is 1.
version = 1

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
[runtime]
# Directory for lock files, status snapshots, event spools, and counters.
state_dir = "/var/lib/spt"

# Profiles whose failure marks the entire process unhealthy (systemd
# notifies, health-check endpoints return 503, process exits non-zero).
required_profiles = ["edge-prod"]

# Drain time before forced close on SIGTERM / service stop.
shutdown_grace = "20s"

# Start at most N profiles concurrently on startup.
profile_start_parallelism = 4

# Single-instance file lock under state_dir.
file_lock = true

[runtime.threads]
model = "multi_thread"
orchestrator_threads = 1
service_threads = 4
blocking_worker_threads = 32

[runtime.reload]
# "signal" = SIGHUP (Unix), "watch" = file-watch, "service" = SCM/systemd,
# "none" = restart required.
mode = "signal"
debounce = "1s"
require_valid_config = true   # keep old config running on parse error
restart_changed_profiles = true

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
[logging]
level = "info"
format = "json"          # compact | pretty | json
destinations = ["file"]
file = "/var/log/spt/spt.jsonl"
rotate = "daily"         # size | daily | hourly | none
max_files = 30
compress_rotated = true
redact = ["secrets", "auth"]

# Remote syslog-TLS sink with disk spool for reliability.
[[logging.remote]]
name = "siem"
type = "syslog_tls"
endpoint = "siem.example.com:6514"
ca_file = "/etc/ssl/certs/internal-ca.pem"
server_name = "siem.example.com"
facility = 16
app_name = "spt"
spool_dir = "/var/lib/spt/spool/siem"
spool_max_bytes = "64MiB"
queue_max_records = 10000
reconnect_backoff = "1s"
required = true

# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
[secrets]
backend = "auto"           # auto | keychain | vault | env
keychain_namespace = "spt"

# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------
[observability.metrics]
enabled = true
format = "prometheus"
state_file = "/var/lib/spt/metrics.prom"

# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
[events]
ring_capacity  = 1024
retry_interval = "30s"
spool_dir      = "/var/lib/spt/event-spool"
spool_max_bytes = "64MiB"
default_min_level = "info"

[[events.sinks]]
name = "oncall-webhook"
type = "webhook_post"
url  = "https://hooks.example.com/spt"
auth = "secret://webhook/ops/token"

[[events.bindings]]
name = "profile-alerts"
on   = ["profile.failed", "profile.degraded"]
actions = ["oncall-webhook"]
min_level = "warn"
throttle  = "5m"

# ---------------------------------------------------------------------------
# MCP server (Model Context Protocol)
# ---------------------------------------------------------------------------
[mcp]
enabled       = true
default_mode  = "read_only"
stdio         = true
listen        = "127.0.0.1:7878"
allow_secret_reveal = false   # must remain false
audit_events  = true

# ---------------------------------------------------------------------------
# Capabilities (fleet feature gates)
# ---------------------------------------------------------------------------
[capabilities]
allow_gssapi          = false
allow_sspi            = false
allow_dynamic_proxy   = true
allow_sftp            = true
allow_filesystem_mounts = false
allow_post_quantum_kex = false
allow_ml_kem           = false
require_post_quantum_kex = false

# ---------------------------------------------------------------------------
# Profile: edge-prod
# ---------------------------------------------------------------------------
[[profiles]]
name     = "edge-prod"
enabled  = true
protocol = "ssh2"
host     = "bastion.example.com"
port     = 22
user     = "tunnel"
failure_policy = "retry"
network_change_reconnect = true

[profiles.connection]
connect_timeout      = "10s"
auth_timeout         = "15s"
handshake_timeout    = "15s"
tcp_nodelay          = true
socket_keepalive     = true

[profiles.crypto]
policy           = "modern"
allow_deprecated = false

[profiles.auth]
method        = "public_key"
identity_file = "/etc/spt/id_ed25519"
# Passphrase resolved at runtime from the configured secrets backend.
passphrase    = "secret://ssh/edge-prod/passphrase"

[profiles.trust]
mode             = "known_hosts"
known_hosts_file = "/etc/spt/known_hosts"
strict           = true
accept_new       = false

[profiles.keepalive]
interval    = "20s"
timeout     = "5s"
max_missed  = 3

[profiles.reconnect]
initial_delay = "1s"
max_delay     = "2m"
jitter        = "30%"
reset_after   = "5m"
max_attempts  = 0      # 0 = unlimited

[profiles.instability]
enabled              = true
window               = "10m"
max_disconnects      = 4
max_keepalive_misses = 2
action               = "failover"
min_successful_uptime = "3m"

[profiles.failover]
mode         = "priority"
health_check = "ssh_handshake"
fail_after   = 3
restore_after = "2m"

# Primary and DR endpoints for failover.
[[profiles.endpoints]]
name     = "primary"
host     = "bastion-primary.example.com"
port     = 22
priority = 0
weight   = 100

[[profiles.endpoints]]
name     = "dr"
host     = "bastion-dr.example.com"
port     = 22
priority = 10
weight   = 50

# Local TCP forward.
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
max_bytes_per_second_in  = "50MiB"
max_bytes_per_second_out = "50MiB"
```

Run `spt config validate --config /etc/spt/spt.toml --strict` after
any edit. Use `spt config render --config /etc/spt/spt.toml` to emit
the canonical round-tripped form and detect unknown fields before strict
mode catches them at process start.
