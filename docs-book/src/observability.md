# Observability

`spt` emits structured logs, metrics, lifecycle events, SNMP traps, and Windows Event Log entries. All output passes through a byte-level redaction layer before reaching any sink. This chapter covers each signal type, the configuration tables that control them, and the CLI surface for reading them.

## Logging

### Levels and formats

Configure logging under `[logging]`:

```toml
[logging]
level = "info"          # trace | debug | info | warn | error
format = "json"         # compact | pretty | json
destinations = ["file", "stderr"]
file = "/var/log/spt/spt.jsonl"
rotate = "daily"        # none | hourly | daily | size
max_files = 30
max_age = "90d"
max_size = "256MiB"     # used with rotate = "size"
compress_rotated = true
redact = ["secrets", "auth"]
```

`destinations` is a list. Valid values are `stderr`, `file`, and `journald` (Linux only). Each destination is an independent sink; all run concurrently and share the same formatter output.

File rotation is handled by `spt-observability`. When `rotate = "size"`, `max_size` triggers a rotation. When `rotate = "daily"` or `"hourly"`, the rotation fires on the clock boundary. `max_files` keeps at most that many rotated files; older files are deleted. `max_age` deletes files older than the specified duration regardless of count. `compress_rotated = true` gzips rotated files.

The tracing subscriber wraps its `EnvFilter` in a reload handle, so the active log filter can be changed without restarting:

1. **`SPT_LOG` environment variable** — parsed as a `tracing` `EnvFilter` directive at boot. Example: `SPT_LOG=info,spt_supervisor=debug`.
2. **SIGHUP** — on Unix, the supervisor re-reads `<state_dir>/log-filter` and installs its contents as the new filter. A parse failure is logged and the previous filter is retained.
3. **MCP `log_set_level` tool** — a write-gated MCP tool that accepts a `target` (module path) and a `level`. See [mcp.md](mcp.md) for details and the `allow_write_tools` gate.

### Redaction tiers

Every sink passes its formatted bytes through `spt_core::redact` before writing them. Three modes are available, corresponding to spec §13.3:

| Mode | What is scrubbed |
|---|---|
| `None` | Nothing. Intended for local debugging only; the runtime must not use it for any sink that leaves the process. |
| `Standard` | Bearer tokens, HTTP Basic credentials, `password=`, `passphrase=`, `key=`, `secret=`, `token=`, `api_key=` key-value pairs, and PEM private-key blocks. This is the default. |
| `Strict` | Everything in `Standard` plus IPv4 addresses, IPv6 addresses, and email addresses. Use when hostname or identity redaction is required. |

The `redact` field in `[logging]` is a list of profile names. `"secrets"` selects `Standard`; `"auth"` adds auth-method fields. The redaction wrapper buffers complete lines and processes each through the mode-appropriate regex set before forwarding to the underlying writer, so no partial redaction can occur.

### Remote sinks

Remote sinks are declared as `[[logging.remote]]` entries. Each entry has a `name`, a `type`, and type-specific fields.

```toml
[[logging.remote]]
name = "otel-collector"
type = "otlp"
endpoint = "https://otel.example.com:4318/v1/logs"
ca_file = "/etc/ssl/certs/internal-ca.pem"
auth = "secret://otlp/edge/bearer"
batch_size = 256
timeout = "5s"
required = false
```

Available sink types:

| Type | Transport | Framing |
|---|---|---|
| `syslog_udp` | UDP | RFC 5424 best-effort datagrams. No acknowledgement; no spool. |
| `syslog_tcp` | TCP | RFC 6587 octet-counted framing with reconnect and disk spool. |
| `syslog_tls` | TLS over TCP | RFC 5425 framing over rustls with full certificate verification by default. Reconnect and disk spool. |
| `https_jsonl` | HTTPS | One JSON object per line, batched and posted. Reconnect and disk spool. |
| `otlp` | HTTPS (gRPC/proto) | OpenTelemetry Protocol log export. Feature-gated on the `otlp` cargo feature in `spt-observability`. |

Reliable transports (`syslog_tcp`, `syslog_tls`, `https_jsonl`) spool undelivered records to disk under `spool_dir` with a `spool_max_bytes` cap. The spool retries on a `reconnect_backoff` schedule. `queue_max_records` bounds the in-memory queue between the formatter and the disk-flush path.

`required = true` causes a sink failure to block the log fan-out path: the supervisor will not consider the log write complete until the required sink accepts the record. Use this for SIEM sinks where record loss is unacceptable; leave it `false` for OTLP and best-effort UDP paths.

#### Pinned TLS for remote sinks

Every HTTPS-bearing remote sink (`syslog_tls`, `https_jsonl`) supports three optional fields for certificate pinning (spec t5-e2):

| Field | Type | Default | Meaning |
|---|---|---|---|
| `pin_spki_sha256` | array of strings | `[]` | SPKI SHA-256 pins in `SHA256:<base64>` or hex form. A non-empty set enables leaf-cert pinning. |
| `allow_self_signed` | bool | `false` | Skip WebPKI verification; the pin set becomes the sole trust anchor. Requires a non-empty pin set. |
| `max_cert_chain_depth` | integer | `5` | Maximum intermediates between leaf and trust anchor. Set to `0` to disallow all intermediates. |

The legacy `allow_invalid_certs` field on `syslog_tls` is still accepted for back-compat but emits a deprecation warning from `spt config validate`. Migrate to `allow_self_signed` with a non-empty `pin_spki_sha256`. The OTLP exporter exposes the same schema-level fields but does not yet route through the pinned TLS connector (tonic-rustls wiring is deferred to a follow-up).

For trust anchors, CA bundles, and SPKI pin management see [trust.md](trust.md).

## The event bus

The event subsystem fans typed lifecycle events to a configurable set of sinks. It is fully wired into `spt tunnel run`: at startup the binary constructs an `EventBus`, builds the sink registry, spawns the `Dispatcher`, and threads an `EventBus` handle into the supervisor so profile and forward lifecycle transitions emit canonical `Event` payloads.

### Event shape

Each `Event` carries:

- `kind` — a dot-namespaced string such as `profile.degraded`, `forward.bind_failed`, `auth.failed`, `mcp.tool_called`, `memory.leak_suspected`.
- `severity` — `info`, `warn`, or `error`.
- `fields` — a string-keyed map of event-specific data. Fields are already redacted when they reach the bus.
- `timestamp_ms` — Unix epoch milliseconds.

### Pipeline tuning

Top-level `[events]` scalars tune the bus and dispatcher:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `ring_capacity` | integer | `1024` | Event-bus broadcast ring buffer capacity. Slow consumers that lag beyond this receive `Lagged`. Must be `> 0`. |
| `retry_interval` | duration | `30s` | How often the dispatcher retries failed spooled deliveries. |
| `spool_dir` | path | `<state_dir>/events` | Root for per-sink disk spools. |
| `spool_max_bytes` | bytesize | spool default | Maximum total spool size; oldest entries are dropped first. |
| `default_min_level` | severity | none | Severity floor for bindings that do not set their own `min_level`. |

### Bindings

A binding matches events and dispatches them to named sinks or commands:

```toml
[[events.bindings]]
name = "degraded-to-oncall"
on   = ["profile.degraded", "profile.failed"]
actions = ["oncall-mcp", "oncall-email", "ops-webhook"]
min_level = "warn"
throttle = "5m"

[events.bindings.dedupe]
key    = "profile_id"   # field to dedupe on; omit for the default (kind|profile_id|forward_id)
window = "5m"           # suppression window; default 60s
```

`on` is a list of event kind strings. `actions` is a list of sink or command names. Multiple keys in `on` OR together; multiple fields in a `match` predicate AND together. `min_level` overrides `[events].default_min_level` for this binding. `throttle` drops re-fires of the same binding within the duration, independently of dedupe.

The optional `dedupe` table suppresses repeat fires within `window`:
- `key` — a single field path. When omitted, the dispatcher's default composite key (`kind|profile_id|forward_id`) is used.
- `window` — suppression duration; default `60s`.

After a flag fires within a suppression window, subsequent identical events are silently dropped until the window expires. This prevents alert storms during extended outages.

### Sinks

Sinks are declared as `[[events.sinks]]` entries:

```toml
[[events.sinks]]
name = "ops-webhook"
type = "webhook_post"
url  = "https://hooks.example.com/spt"
method = "POST"
content_type = "application/json"
auth = "secret://webhook/ops/token"
timeout = "5s"
```

Available sink types:

| Type | What it does |
|---|---|
| `http` / `webhook_post` | HTTP POST to a URL. Supports TLS pinning. |
| `email` | SMTP delivery. Subject line and body are templated. |
| `sms` | SMS via a configured provider. |
| `push` / `webpush` | Web Push API delivery to configured subscriptions using VAPID. |
| `command` | Runs a named `[[events.commands]]` entry as a subprocess. |
| `mcp_notify` | Publishes each event as a `spt/event` JSON-RPC frame on the MCP broadcast channel. |

All sink kinds fire at runtime. A per-sink build failure at startup is logged loudly and that one sink is skipped; other sinks continue unaffected.

Failed deliveries are spooled to `<state_dir>/spool/<sink>/` and retried with exponential backoff. The spool size is bounded by `[events].spool_max_bytes`.

#### Templates

Sink `template` fields use Mustache-like `{{field}}` substitution over the event's `fields` map. Unknown fields render as the empty string; a `null` field renders empty rather than the literal string `"null"`. The `email` sink additionally supports `subject_template`, which defaults to `"[{{severity}}] {{kind}}"` when absent.

```toml
[[events.sinks]]
name = "slack"
type = "webhook_post"
url  = "https://hooks.slack.com/..."
template = "{{kind}} on {{profile_id}}: {{message}}"
```

#### The command sink

A `command` sink executes an allow-listed subprocess when a bound event fires:

```toml
[[events.commands]]
name    = "restart-upstream"
command = "/usr/local/bin/notify-ops.sh"
args    = ["--profile", "{{profile_id}}", "--event", "{{kind}}"]
allow_exec = true
timeout = "10s"
```

`allow_exec = true` is required; the dispatcher refuses to run a command entry that omits it. Arguments are rendered through the same template engine as sink bodies. Execution is sandboxed by the process's existing permissions; `spt` does not drop privileges for command sinks.

#### The `mcp_notify` sink

The `mcp_notify` sink publishes events end-to-end to connected MCP clients via the `events_subscribe` streaming tool. Each event is broadcast as a `spt/event` JSON-RPC frame on the loopback MCP channel; every subscribed client receives it verbatim. When no client is subscribed the frame is dropped (broadcast semantics) and dispatch is unaffected. See [mcp.md](mcp.md) for client subscription details.

#### Pinned TLS for event sinks

HTTPS sinks (`http`, `webhook_post`, `webpush`, `push`, `sms`) support the same `pin_spki_sha256` / `allow_self_signed` / `max_cert_chain_depth` fields as remote log sinks. SMTP (`email`) exposes the same schema fields but does not yet route through the pinned connector (the `lettre 0.11.19` transport does not surface a custom-verifier hook; a raw `tokio-rustls` wrapper is a follow-up).

### Delivery and replay

```
spt event replay --since 1h --binding degraded-to-oncall
```

Re-runs historical events from the ring through one binding, useful for testing new sink configurations. See [cli-reference.md](cli-reference.md) for the full `spt event` command reference.

## Metrics

`[observability.metrics]` enables a Prometheus-format metrics exporter:

```toml
[observability.metrics]
enabled    = true
format     = "prometheus"
state_file = "/var/lib/spt/metrics.prom"
```

The exporter writes a `metrics.prom` file under the state directory on a configurable interval using an atomic rename, so scrapers never see a partial file. Read it with:

```
spt observe metrics
```

or scrape `<state_file>` directly from Prometheus using a `file_sd_config` or a `textfile` collector node exporter job.

OTLP metric export shares the same `[[logging.remote]] type = "otlp"` endpoint as log export — an OTLP collector receives both signals over a single connection. The OTLP metrics path is feature-gated on the `otlp` cargo feature in `spt-observability` and is enabled at build time with `--features spt-observability/otlp`.

The stats subsystem (see below) feeds the counters and sliding-window aggregates that back the exported metrics. Profile-state codes, forward-state codes, bytes-transferred, error counts, session counts, and connection-table sizes are all present in the Prometheus output.

## SNMP

`[observability.snmp]` enables an in-process SNMPv3 agent (`spt observe snmp serve`). The agent implements USM (RFC 3414) with AES-128-CFB privacy (RFC 3826) and HMAC-SHA-256 authentication (RFC 7860). It has no dependencies on `spt-*` crates and no `unsafe` code.

```toml
[observability.snmp]
enabled       = true
version       = "v3"
bind          = "127.0.0.1:161"
enterprise_id = 12345   # your IANA Private Enterprise Number
engine_id     = ""      # auto-generated when absent

[[observability.snmp.users]]
name          = "monitor"
auth_protocol = "hmac_sha256"
auth_secret   = "secret://snmp/agent/auth"
priv_protocol = "aes128"
privacy_secret = "secret://snmp/agent/priv"

[[observability.snmp.traps]]
name     = "nms"
endpoint = "nms.example.com:162"
user     = "trap-sender"
auth_secret    = "secret://snmp/trap/auth"
privacy_secret = "secret://snmp/trap/priv"
```

### USM users

`[[observability.snmp.users]]` defines the users the agent accepts inbound GET / GETNEXT / GETBULK requests from. Each entry maps to an `spt_snmp::UsmUser`. Security level is derived from which fields are present:

| Combination | Security level |
|---|---|
| `name` only | `noAuthNoPriv` |
| `name` + `auth_protocol` + `auth_secret` | `authNoPriv` |
| All six fields | `authPriv` |

Supported `auth_protocol` values: `hmac_md5`, `hmac_sha1`, `hmac_sha256`. Supported `priv_protocol` values: `aes128`, `aes256`, `des`. `auth_secret` and `privacy_secret` are secret references resolved at runtime; they are wrapped in `RedactedString` so they never appear in `Debug` output and are zeroed on drop.

### Traps

`[[observability.snmp.traps]]` configures destinations that receive SNMPv3 traps when profile or forward lifecycle events occur. Traps are sent via UDP to the named `endpoint`. The trap sender uses the same USM credential fields as the agent users.

### SPT-MIB

The project MIB ships at `mibs/SPT-MIB.txt`. The `enterprise_id` field in `[observability.snmp]` must be set to the operator's registered IANA Private Enterprise Number. The checked-in `32473` subtree is the RFC 5612 / RFC 9371 documentation PEN used as a placeholder; the agent startup path rejects `32473` and the old `99999` placeholder unless a test fixture explicitly opts in. After receiving a PEN from IANA, run `scripts/swap-pen.sh <NEW_PEN>` (or `swap-pen.ps1` on Windows) to update both the MIB and the crate constant in a single step.

### CLI

```
spt observe snmp serve   # start the agent in the foreground
spt observe metrics      # print the current Prometheus metrics file
spt observe status       # print the status snapshot JSON
```

See [cli-reference.md](cli-reference.md) for the full `spt observe` surface.

## Windows Event Log

`[observability.windows_event]` writes structured events to the Windows Event Log:

```toml
[observability.windows_event]
enabled        = true
source         = "spt"
channel        = "Application"
install_source = true
```

`install_source = true` registers the event source under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<channel>\<source>` at service install time (requires elevation). When disabled, Event Viewer displays the raw message text rather than a formatted description. Windows Event Log integration requires `[capabilities].allow_windows_event_log = true`.

## The stats subsystem

`spt-stats` provides the counters, sliding windows, and session/connection tables that back both the Prometheus exporter and the `spt stats` CLI command.

### Counters and sliding windows

`RollingCounter` maintains bucketed counts over configurable time windows. `SlidingWindow` aggregates bytes transferred, connection counts, and error counts across a rolling time span. `Ewma` maintains exponentially-weighted moving averages for throughput, used in the rate displays in `spt stats` and in the TUI.

All time-aware structures accept a `Clock` trait, so integration tests inject a fake clock and drive the windows deterministically.

### Session and connection tables

`SessionTable` and `ConnectionTable` are `dashmap`-backed concurrent maps that track the lifecycle of every active SSH session and every forwarded connection. The session table records the session state, the elected endpoint, authentication method, connect time, and byte counters. The connection table records per-connection state, port numbers, and idle timers.

Both tables are visible in:

```
spt stats sessions
spt stats connections
spt status
```

The `status.json` file under `<state_dir>` is the source-of-truth document for `spt tunnel status` and external health monitors. It is written atomically on every state change.

### CLI

```
spt stats               # print all counters and window aggregates
spt stats sessions      # session table
spt stats connections   # connection table
spt status              # full status snapshot (JSON or human)
spt log tail            # follow the rotating log file
spt event replay --since 1h --binding <name>
```

See [cli-reference.md](cli-reference.md) for full syntax.

## The status snapshot

`<state_dir>/status.json` serializes a `StatusSnapshot` on every profile state change. It includes:

- Per-profile state name, current endpoint, consecutive failures, instability flag, and timestamps.
- Per-forward state and bind address.
- Session table summary.
- Subsystem status blocks (memory monitor, updater, event bus lag).

When `[mem_hygiene]` is enabled the snapshot includes a `memory_monitor` block showing the last RSS sample, number of samples taken, growth-episode flag, and sampling interval.

`spt status` renders this snapshot in a human-readable format by default; `spt status --json` emits the raw JSON. External monitors (Nagios, Datadog agents, custom scripts) can scrape `status.json` directly without spawning a subprocess.

## Example: full observability stack

The following is the `examples/observability.toml` configuration shipped with `spt`. It wires OTLP log export, syslog over TLS, a Prometheus metrics file, an email event sink, and an `mcp_notify` sink:

```toml
version = 1

[logging]
level = "info"
format = "json"
destinations = ["file"]
file = "/var/log/spt/spt.jsonl"
rotate = "daily"
max_files = 30
compress_rotated = true
redact = ["secrets", "auth"]

[[logging.remote]]
name = "otel-logs"
type = "otlp"
endpoint = "https://otel.example.com:4318/v1/logs"
ca_file = "/etc/ssl/certs/internal-ca.pem"
auth = "secret://otlp/edge/bearer"
batch_size = 256
timeout = "5s"
required = false

[[logging.remote]]
name = "siem-syslog"
type = "syslog_tls"
endpoint = "siem.example.com:6514"
ca_file = "/etc/ssl/certs/internal-ca.pem"
server_name = "siem.example.com"
facility = 16
spool_dir = "/var/lib/spt/spool/syslog-tls"
spool_max_bytes = "64MiB"
queue_max_records = 10000
reconnect_backoff = "1s"
required = true

[observability.metrics]
enabled = true
format = "prometheus"
state_file = "/var/lib/spt/metrics.prom"

[[events.sinks]]
name = "oncall-mcp"
type = "mcp_notify"

[[events.sinks]]
name = "oncall-email"
type = "email"
smtp = "smtp://smtp.example.com:587"
from = "spt@example.com"
to   = ["oncall@example.com"]
auth = "secret://smtp/relay/token"
timeout = "10s"

[[events.sinks]]
name = "ops-webhook"
type = "webhook_post"
url  = "https://hooks.example.com/spt"
method = "POST"
content_type = "application/json"
auth = "secret://webhook/ops/token"
timeout = "5s"

[[events.bindings]]
name = "degraded-to-oncall"
on   = ["profile.degraded", "profile.failed"]
actions = ["oncall-mcp", "oncall-email", "ops-webhook"]
min_level = "warn"
throttle = "5m"
```

For an OTLP-only deployment see `examples/observability-otel.toml`, which routes logs and events through an OpenTelemetry collector and omits the syslog sinks.

## TUI observability surfaces

The TUI (`spt tui`) exposes live views of:

- Profile and forward state (colour-coded by state name).
- Per-profile byte counters and EWMA throughput.
- Event log panel with level filtering.
- Session and connection tables.

The Events page in the TUI supports editing `http`, `webhook_post`, `command`, and `mcp_notify` sinks and their bindings. Editing `email`, `sms`, and `push` sinks in the TUI is deferred to a later release; configure those kinds directly in TOML and they will deliver at runtime. See [tui.md](tui.md).

## Related pages

- [resilience.md](resilience.md) — the events emitted by the supervisor state machine
- [mcp.md](mcp.md) — `events_subscribe`, `log_set_level`, and the MCP write-tool gate
- [secrets.md](secrets.md) — resolving `secret://` references in sink credentials
- [trust.md](trust.md) — CA bundles, SPKI pins, and TLS configuration for remote sinks
- [security.md](security.md) — redaction guarantees and the security model
- [service.md](service.md) — systemd integration and `sd_notify`
- [cli-reference.md](cli-reference.md) — full syntax for `spt log`, `spt observe`, `spt event`, `spt stats`, and `spt status`
- [troubleshooting.md](troubleshooting.md) — diagnosing log delivery failures and SNMP configuration
