# MCP

`spt` embeds a Model Context Protocol (MCP) server: 16 read-only resources +
31 tools, JSON-RPC 2.0 over stdio. The server is **disabled by default**,
**read-only by default**, and **never returns plaintext secrets**.

## Enabling

The `[mcp]` config table opts in:

    [mcp]
    enabled = true
    read_only = true
    allow_write_tools = []        # explicit allow-list
    audit_to = "events"           # route audit events through `spt-events`

`spt mcp serve --enable --stdio` is required even when the config has
`enabled = true` (the CLI flag is the second confirmation).

## Transports

| Transport   | Status (M7)                                              |
|-------------|----------------------------------------------------------|
| `--stdio`   | implemented (line-delimited JSON-RPC)                    |
| `--listen`  | tracked in M8 (loopback TCP only, CIDR ACL)              |

## Resources

16 resources, identified by `spt://` URIs. Examples:

- `spt://status`              — current `StatusSnapshot`.
- `spt://config/effective`    — strict-redacted config.
- `spt://profiles`            — profile list.
- `spt://forwards`            — forward list.
- `spt://dns/records`         — managed DNS records.
- `spt://service/definition`  — rendered service definition.

Reads never call mutating code paths. The redaction layer rewrites every
response before it leaves the server.

## Tools

31 tools — both read-only (`tunnel_status`, `forward_list`, ...) and mutating
(`forward_add`, `profile_set`, `tunnel_failover`, ...). Mutating tools are
denied unless their name appears in `allow_write_tools`.

## Audit

Every tool invocation produces exactly one `AuditEvent`, regardless of
outcome. The default sink is no-op; production wires the events bus via
`McpAuditSink`.

## Reference

- `crates/spt-mcp/src/server.rs` — entry point.
- `crates/spt-mcp/src/resources/` — resource handlers.
- `crates/spt-mcp/src/tools/` — tool handlers.
- `crates/spt-mcp/src/policy.rs` — policy + redaction gate.
