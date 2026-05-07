# MCP

`spt` embeds a Model Context Protocol (MCP) server: 16 read-only resources +
33 tools (31 specified in spec §16, plus 2 live-bridge tools), JSON-RPC 2.0
over stdio. The server is **disabled by default**, **read-only by default**,
and **never returns plaintext secrets**.

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
expose = false                    # required true for non-loopback `listen`
```

`spt mcp serve --enable --stdio` is required even when the config has
`enabled = true` (the CLI flag is the second confirmation). Failures from
policy or transport map to `McpFailed` (exit code 26).

## Transports

| Transport   | Status (M7)                                              |
|-------------|----------------------------------------------------------|
| `--stdio`   | implemented (line-delimited JSON-RPC 2.0)                |
| `--listen`  | tracked in M8 (loopback TCP only, CIDR ACL)              |

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

33 tools dispatched through the policy gate. Mutating tools are denied unless
their name appears in `allow_write_tools`. Source:
[`crates/spt-mcp/src/tools.rs`](../crates/spt-mcp/src/tools.rs)
(`ALL_TOOL_NAMES`).

### Read-only

`config_validate`, `config_doctor`, `config_render`, `profile_list`,
`profile_show`, `forward_list`, `forward_explain`, `tunnel_status`,
`stats_summary`, `stats_export`, `session_list`, `session_show`,
`diagnose_run`, `diagnose_bundle`, `benchmark_report_export`, `dns_query`,
`log_tail`, `observe_metrics`, `event_test`, `service_render`, `secret_list`,
`key_inspect`.

### Mutating (allow-list required)

| Tool                  | Effect                                              |
|-----------------------|-----------------------------------------------------|
| `profile_set`         | Patch a profile (writes back through `spt-config`). |
| `forward_add`         | Add a forward to a profile.                         |
| `forward_remove`      | Remove a forward.                                   |
| `tunnel_reload`       | Trigger a hot reload (same as SIGHUP).              |
| `tunnel_failover`     | Force a manual failover.                            |
| `dns_record_add`      | Add a managed DNS record.                           |
| `dns_record_remove`   | Remove a managed DNS record.                        |
| `secret_set_ref`      | Store a `secret://` reference (never plaintext).    |
| `benchmark_run`       | Start a benchmark (refused without `--target`).     |
| `session_close`       | Close a single session (live-bridge).               |
| `session_drain`       | Drain a session gracefully (live-bridge).           |
| `stats_subscribe`     | Subscribe to streaming stats (live-bridge).         |

`secret_set_ref` accepts only references; secret material is never sent over
the wire. `allow_secret_reveal = true` in `[mcp]` is rejected by the
validator.

## Audit

Every tool invocation produces exactly one `AuditEvent`, regardless of
outcome (success, denied, errored). The audit sink defaults to no-op;
production wires the events bus via `McpAuditSink`. With `audit_events = true`
each call also fans out to the configured `[[events.bindings]]`.

## Policy redaction

Responses pass through the same redaction layer as logs. The default profile
masks `secret://…` references and inline plaintext password / token / cookie
fields with `[REDACTED]`; strict mode (used by `spt diagnose bundle`)
additionally masks IP-address-like host/endpoint values.

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
