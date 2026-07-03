# Model Context Protocol Server

`spt` embeds a Model Context Protocol (MCP) server: 16 read-only resources and
36 tools (18 read-only, 18 requiring explicit allow-listing), JSON-RPC 2.0 over
stdio or loopback TCP. The server is **disabled by default**, **read-only by
default**, and **never returns plaintext secrets**.

## Two deployment modes

**Loopback MCP server (inside `tunnel run`)** — resources and read-only tools
are backed by real `ConfigSource` and `StateSource` adapters wired to the live
config, status snapshot, and event/log state. Mutating tools route through the
live `Controller` and produce real side effects. This is the mode to use when
you need live data or real mutations.

**Standalone `spt mcp serve`** — the server starts without a running supervisor
and builds a Noop controller and Noop sources instead. Resource reads return
empty or placeholder documents; mutating tools respond plan-only
(`{ "applied": false, "planned": ... }`) and perform no side effects. Use this
for client-side integration testing.

The `--enable` CLI flag is sufficient to start the standalone server on its
own — it does not require `[mcp].enabled = true` in the config file as a second
confirmation. Failures from policy or transport map to exit code 26
(`McpFailed`).

## Configuration

```toml
[mcp]
enabled = true
default_mode = "read_only"        # read_only | read_write
stdio = true
listen = ""                       # loopback TCP listen address; empty = stdio only
allow_secret_reveal = false       # validator rejects true
allow_write_tools = []            # explicit allow-list (see Tool catalog below)
audit_events = true               # route audit events through spt-events
expose = false                    # validator rejects true; non-loopback unsupported
```

`allow_secret_reveal = true` and `expose = true` are rejected by the config
validator. The server never binds or accepts non-loopback peers.

A stale `mcp-listen.json` sidecar from a previous run is best-effort deleted
at startup before rebinding.

### Example

From [`examples/mcp.toml`](https://github.com/supermarsx/ssh-perma-tunnel/blob/main/examples/mcp.toml):

```toml
[mcp]
enabled = true
default_mode = "read_only"
stdio = true
listen = ""
allow_secret_reveal = false
allow_write_tools = ["forward.add", "tunnel.failover"]
audit_events = true
```

## Transports

| Transport   | Status |
|-------------|--------|
| `--stdio`   | Implemented. Line-delimited JSON-RPC 2.0 over stdin/stdout. |
| `--listen`  | Implemented. Loopback TCP only. Non-loopback binds and peers are refused. |

Protocol conformance notes:

- A malformed JSON frame is answered with JSON-RPC error `-32700` per frame;
  the connection is not torn down.
- Failed `initialize` attempts are capped per connection.
- The server echoes the negotiated protocol version.

## Resource catalog

All 16 resources are URI-addressed under the `spt://` scheme. Reads never call
mutating code paths; the policy gate redacts every response before it leaves the
server.

| URI | Purpose |
|-----|---------|
| `spt://config/effective` | Strict-redacted effective config (TOML). |
| `spt://config/redacted` | Pre-redaction view, still secret-safe. |
| `spt://profiles` | Profile list with state. |
| `spt://forwards` | Forward list with state. |
| `spt://status` | `StatusSnapshot` document. |
| `spt://stats/summary` | Aggregated stats (counters, rates, percentiles). |
| `spt://sessions/current` | Active SSH sessions. |
| `spt://events/recent` | Recent events (redacted). |
| `spt://logs/recent` | Tail of `<state_dir>/spt.log`. |
| `spt://metrics` | Prometheus exposition (text format). |
| `spt://diagnostics/recent` | Last `diagnose run` report. |
| `spt://benchmarks/recent` | Last benchmark report. |
| `spt://dns/records` | Managed DNS records (synthetic + declared). |
| `spt://snmp/mib` | SPT-MIB definition. |
| `spt://service/definition` | Rendered service-manager definition. |
| `spt://policy/mcp` | Live MCP policy (read-only / write allow-list). |

## Tool catalog

36 tools are dispatched through the policy gate. Mutating tools (`WRITE_TOOLS`)
are denied unless their name appears in `allow_write_tools`. The loopback MCP
server honours `allow_write_tools` and `default_mode` — it does not
force-allow every write tool.

### Read-only tools (18)

`config_validate`, `config_doctor`, `config_render`, `profile_list`,
`profile_show`, `forward_list`, `forward_explain`, `tunnel_status`,
`stats_summary`, `stats_export`, `session_list`, `session_show`,
`dns_query`, `log_tail`, `observe_metrics`, `service_render`, `secret_list`,
`key_inspect`.

### Mutating tools — allow-list required (18)

| Tool | Effect |
|------|--------|
| `profile_set` | Patch a profile (writes back through `spt-config`). |
| `forward_add` | Add a forward to a profile. |
| `forward_remove` | Remove a forward. |
| `tunnel_reload` | Trigger a hot reload (same as SIGHUP). |
| `tunnel_failover` | Force a manual failover. |
| `diagnose_run` | Run diagnostics (writes a report). |
| `diagnose_bundle` | Build a support bundle (writes to disk). |
| `benchmark_run` | Start a benchmark (refused without `--target`). |
| `benchmark_report_export` | Export a benchmark report. |
| `dns_record_add` | Add a managed DNS record. |
| `dns_record_remove` | Remove a managed DNS record. |
| `event_test` | Emit a synthetic test event. |
| `secret_set_ref` | Store a `secret://` reference (never plaintext). |
| `session_close` | Close a single session (live-bridge). |
| `session_drain` | Drain a session gracefully (live-bridge). |
| `stats_subscribe` | Subscribe to streaming stats (live-bridge). |
| `events_subscribe` | Subscribe to live `spt/event` notifications (live-bridge). |
| `log_set_level` | Override the process-wide tracing filter at runtime. |

`diagnose_run`, `diagnose_bundle`, `benchmark_report_export`, and `event_test`
produce side effects or write files and therefore require allow-listing even
though they feel read-adjacent.

`secret_set_ref` accepts only `secret://` references; secret material is never
sent over the wire. Attempting to set `allow_secret_reveal = true` in `[mcp]`
is rejected by the validator.

## Streaming subscriptions (loopback only)

Two tools register a server-to-client notification stream:

- `stats_subscribe` streams `notifications/stats/tick` frames carrying live
  `StatsTick` payloads from the supervisor.
- `events_subscribe` streams `spt/event` frames. The `mcp_notify` event sink
  pushes each routed event onto a process-local broadcast channel; every
  connected client that has called `events_subscribe` receives the frame. With
  no subscriber attached the frame is dropped (broadcast semantics) and event
  dispatch is unaffected.

Both tools relay one task per subscription and terminate cleanly when the client
disconnects. On the stdio transport, which has no notification channel, both
tools return `InvalidParams`.

## Audit

Every tool invocation produces exactly one `AuditEvent`, regardless of outcome
(success, denied, errored). When `audit_events = true`, the server bridges
these events onto the workspace events bus via an `McpAuditSink`, so each call
also fans out to the configured `[[events.bindings]]`. Without `audit_events`,
the sink is a no-op.

## Policy redaction

Responses pass through the policy redaction gate. The redactor inspects object
keys (`password`, `token`, `secret`, `api_key`, `private_key`, `bearer`,
`credential`, and others in `SENSITIVE_KEY_HINTS`) and replaces the matching
scalar value with `"***"`.

`secret://...` reference strings are preserved verbatim — they are references,
not values, so masking them would lose useful information without exposing any
secret material. Keys named exactly `ref` or `secret_ref` are likewise treated
as references and are not redacted. The gate is applied centrally to every
resource read, tool result, and audit-event argument set.

## CLI

See [CLI Reference](cli-reference.md) for the `spt mcp` command group, including
`spt mcp serve --stdio` (standalone server) and flags for transport selection.

## Security

See [Security](security.md) for the security model and threat analysis around
the MCP server surface. Key points:

- The server is opt-in and disabled by default.
- Non-loopback exposure is unsupported and rejected by the validator.
- Secrets are never returned in tool results or resource reads.
- Every mutation is audit-logged.
