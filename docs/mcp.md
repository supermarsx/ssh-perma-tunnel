# MCP

`spt` embeds a Model Context Protocol (MCP) server: 16 read-only resources +
35 tools (31 from spec §16, plus 3 live-bridge tools and the `log_set_level`
live-control tool), JSON-RPC 2.0 over stdio. The server is **disabled by
default**, **read-only by default**, and **never returns plaintext secrets**.

Resources and read-only tools are backed by **real** `ConfigSource` /
`StateSource` adapters over the live config, status snapshot, and event/log
state (the earlier NoopSources fixtures are gone). Mutating tools route
through the live `Controller`.

## Enabling

The `[mcp]` config table opts in:

```toml
[mcp]
enabled = true
default_mode = "read_only"        # read_only | read_write
stdio = true
listen = ""                       # loopback TCP listen address (empty = stdio only)
allow_secret_reveal = false       # MUST stay false; validator rejects true
allow_write_tools = []            # explicit allow-list (see "Tools" below)
audit_events = true               # route audit events through `spt-events`
expose = false                    # MUST stay false; `expose = true` is rejected (non-loopback unsupported)
```

Start the standalone server with `spt mcp serve --stdio`. Enablement is
satisfied by **either** the `--enable` CLI flag **or** `[mcp].enabled =
true` in config — the standalone serve path treats the flag as sufficient
on its own (it is *not* a mandatory "second confirmation" on top of the
config flag). Failures from policy or transport map to `McpFailed`
(exit code 26).

## Transports

| Transport   | Status                                                   |
|-------------|----------------------------------------------------------|
| `--stdio`   | implemented (line-delimited JSON-RPC 2.0)                |
| `--listen`  | loopback TCP only. Non-loopback binds/peers are refused; `expose = true` is rejected as **unsupported**. A stale `mcp-listen.json` sidecar is best-effort deleted at startup before rebinding. |

Protocol conformance: a malformed JSON frame is answered with JSON-RPC
`-32700` per-frame (the connection is not torn down); failed `initialize`
attempts are capped per connection; the server echoes the negotiated
protocol version.

## Resource catalog

All 16 resources are URI-addressed under the `spt://` scheme. Reads never call
mutating code paths; the policy gate redacts every response before it leaves
the server. Source: [`crates/spt-mcp/src/resources.rs`](../crates/spt-mcp/src/resources.rs).

| URI                          | Purpose                                            |
|------------------------------|----------------------------------------------------|
| `spt://config/effective`     | Strict-redacted effective config (TOML).           |
| `spt://config/redacted`      | Pre-redaction view, still secret-safe.             |
| `spt://profiles`             | Profile list with state.                           |
| `spt://forwards`             | Forward list with state.                           |
| `spt://status`               | `StatusSnapshot` document.                         |
| `spt://stats/summary`        | Aggregated stats (counters, rates, percentiles).   |
| `spt://sessions/current`     | Active SSH sessions.                               |
| `spt://events/recent`        | Recent events (redacted).                          |
| `spt://logs/recent`          | Tail of `<state_dir>/spt.log`.                     |
| `spt://metrics`              | Prometheus exposition (text format).               |
| `spt://diagnostics/recent`   | Last `diagnose run` report.                        |
| `spt://benchmarks/recent`    | Last benchmark report.                             |
| `spt://dns/records`          | Managed DNS records (synthetic + declared).        |
| `spt://snmp/mib`             | SPT-MIB definition.                                |
| `spt://service/definition`   | Rendered service-manager definition.               |
| `spt://policy/mcp`           | Live MCP policy (read-only / write allow-list).    |

## Tool catalog

35 tools dispatched through the policy gate. Mutating tools (`WRITE_TOOLS`)
are denied unless their name appears in `allow_write_tools`. The live MCP
loopback honours `allow_write_tools` / `default_mode` — it does **not**
force-allow every write tool. Source:
[`crates/spt-mcp/src/tools.rs`](../crates/spt-mcp/src/tools.rs)
(`ALL_TOOL_NAMES`) and [`crates/spt-mcp/src/policy.rs`](../crates/spt-mcp/src/policy.rs)
(`WRITE_TOOLS`).

### Read-only (18)

`config_validate`, `config_doctor`, `config_render`, `profile_list`,
`profile_show`, `forward_list`, `forward_explain`, `tunnel_status`,
`stats_summary`, `stats_export`, `session_list`, `session_show`,
`dns_query`, `log_tail`, `observe_metrics`, `service_render`, `secret_list`,
`key_inspect`.

### Mutating / allow-list required (`WRITE_TOOLS`, 17)

| Tool                      | Effect                                              |
|---------------------------|-----------------------------------------------------|
| `profile_set`             | Patch a profile (writes back through `spt-config`). |
| `forward_add`             | Add a forward to a profile.                         |
| `forward_remove`          | Remove a forward.                                   |
| `tunnel_reload`           | Trigger a hot reload (same as SIGHUP).              |
| `tunnel_failover`         | Force a manual failover.                            |
| `diagnose_run`            | Run diagnostics (writes a report) — **write tool**. |
| `diagnose_bundle`         | Build a support bundle (writes to disk) — **write**.|
| `benchmark_run`           | Start a benchmark (refused without `--target`).     |
| `benchmark_report_export` | Export a benchmark report — **write tool**.         |
| `dns_record_add`          | Add a managed DNS record.                           |
| `dns_record_remove`       | Remove a managed DNS record.                        |
| `event_test`              | Emit a synthetic test event — **write tool**.       |
| `secret_set_ref`          | Store a `secret://` reference (never plaintext).    |
| `session_close`           | Close a single session (live-bridge).               |
| `session_drain`           | Drain a session gracefully (live-bridge).           |
| `stats_subscribe`         | Subscribe to streaming stats (live-bridge).         |
| `log_set_level`           | Override the process-wide tracing filter at runtime.|

Note: `diagnose_run`, `diagnose_bundle`, `benchmark_report_export`, and
`event_test` are classified as **write tools** (they produce side effects /
files) and therefore require allow-listing — they are not free read-only
calls.

`secret_set_ref` accepts only references; secret material is never sent over
the wire. `allow_secret_reveal = true` in `[mcp]` is rejected by the
validator.

## Audit

Every tool invocation produces exactly one `AuditEvent`, regardless of
outcome (success, denied, errored). When `audit_events = true`, the server
bridges audit events onto the workspace events bus via an `McpAuditSink`
(analogous to the scripting `ScriptAuditBridge`), so each call also fans out
to the configured `[[events.bindings]]`. Without `audit_events`, the sink is
a no-op.

## Policy redaction

Responses pass through the policy redaction gate. The redactor inspects
object keys (`password`, `token`, `secret`, `api_key`, `private_key`,
`bearer`, `credential`, … — see `SENSITIVE_KEY_HINTS`) and replaces the
matching scalar value with the token **`"***"`**.

`secret://…` reference strings are **preserved verbatim** — they are
references, not values, so masking them would lose useful information without
exposing any secret. Keys named exactly `ref` / `secret_ref` are likewise
treated as references and not redacted. The gate is applied centrally to
every resource read, tool result, and audit-event argument set.

## Examples

- [`examples/mcp.toml`](../examples/mcp.toml) — read-only with a small
  write allow-list.
- [`examples/observability-otel.toml`](../examples/observability-otel.toml) —
  MCP-notify event sink wired to a binding.

## Reference

- `crates/spt-mcp/src/server.rs` — entry point.
- `crates/spt-mcp/src/resources.rs` — resource registry.
- `crates/spt-mcp/src/tools.rs` — tool registry.
- `crates/spt-mcp/src/policy.rs` — policy + redaction gate.
- `crates/spt-mcp/src/audit.rs` — audit sink trait.
