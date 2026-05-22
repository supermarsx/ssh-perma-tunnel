# Observability

`spt` emits structured logs, metrics, and an SNMPv3 trap surface. All output
passes through the redaction layer before reaching disk or network.

## Logging

Defaults: stderr, level `info`, compact text. Configure under `[logging]`:

    [logging]
    level = "info"               # error|warn|info|debug|trace
    format = "compact"           # compact|pretty|json
    destinations = ["stderr", "file"]
    file = "/var/log/spt/spt.log"
    rotate = "daily"             # size|daily|hourly|none
    max_files = 14
    redact = ["secrets", "auth"]

Linux destinations also include `journald`. Remote sinks (`syslog_udp`,
`syslog_tcp`, `syslog_tls`, `https_jsonl`, `otlp`) are declared as
`[[logging.remote]]` blocks. Syslog UDP sends best-effort RFC 5424 datagrams;
syslog TCP uses RFC 6587 octet-counted framing with reconnect and disk spool;
syslog TLS uses RFC 5425 framing over rustls with verification enabled by
default.

The redaction wrapper sits between the formatter and every sink — bytes
matching the configured redaction patterns are replaced before they leave
the process.

## Metrics

A Prometheus text-format exporter writes `metrics.prom` under the state
directory on a configurable interval. Read with `spt observe metrics` or
scrape the file directly.

## SNMP

`[observability.snmp]` enables an in-process SNMPv3 (USM, AES-128-CFB,
HMAC-SHA-256) agent. The project MIB ships at
[`/mibs/SPT-MIB.txt`](../mibs/SPT-MIB.txt). Enabled SNMP configs must set
`enterprise_id` to the operator's registered IANA Private Enterprise Number;
the checked-in `32473` MIB subtree is a documentation template, not a
production default. The agent startup path rejects `32473` and the old
`99999` placeholder unless a test fixture explicitly opts into the
documentation PEN. Traps are sent to configured sinks via UDP.

## Status snapshot

`<state_dir>/status.json` is the source-of-truth document for `spt tunnel
status` and external monitors. Schema in
`crates/spt-state/src/status.rs::StatusSnapshot`.

## OTLP

OTLP export is feature-gated on the `otlp` cargo feature in
`spt-observability`. Enable with `--features spt-observability/otlp` and
configure under `[[logging.remote]]` with `type = "otlp"`.

## Runtime log filter control (t8-A3)

The tracing subscriber installed by `spt-bin` wraps its `EnvFilter` in a
`tracing_subscriber::reload::Layer`, so the global filter directive can be
swapped at runtime without rebuilding the subscriber. Three control paths
share the same reload handle:

1. **Boot-time selection** — `tracing_init::resolve_filter_directive` reads
   `SPT_LOG` first (validated against `EnvFilter::try_new`), then falls back
   to the verbosity flags on the CLI.
2. **SIGHUP** — on Unix, `install_sighup_log_reload` re-reads
   `<state_dir>/log-filter` and applies its contents on every `SIGHUP`. A
   parse failure is logged and the previous filter is retained.
3. **MCP `log_set_level` tool** — see below.

### MCP `log_set_level` tool

| Field   | Type   | Required | Notes |
|---------|--------|----------|-------|
| `target` | string | yes | Tracing target. Typically a Rust module path (e.g. `spt_supervisor` or `spt_mcp::server`). Pre-validated against `^[A-Za-z_][A-Za-z0-9_:.-]*$`. |
| `level`  | string | yes | One of `trace`, `debug`, `info`, `warn`, `error`, `off`. Case-insensitive. |

Example call (JSON-RPC body of `tools/call`):

    {
      "name": "log_set_level",
      "arguments": { "target": "spt_supervisor", "level": "debug" }
    }

On success the tool returns `{ "applied": true, "target": ..., "level": ...,
"directive": "target=level" }`. The applied directive replaces the global
`EnvFilter`, so callers wanting per-module overrides must include every
target in a single call (e.g. `target = "info,spt_supervisor=debug"` is
*not* supported via this tool — use `SPT_LOG` / SIGHUP for compound
directives).

**Security note.** `log_set_level` mutates global process state and so
appears in [`spt_mcp::policy::WRITE_TOOLS`]. It is denied unless its name
is added explicitly to the operator's `[mcp].allow_write_tools` list. The
tool also requires `spt-bin` to have wired a [`LogReloadBridge`] adapter
into the MCP server; ad-hoc / smoke instances built via
`build_noop_server` return `Error::Internal("log reload bridge not wired")`.

## Pinned TLS (t5-e2)

Every HTTPS-bearing remote-log sink (`syslog_tls`, `https_jsonl`) carries
three optional fields that route through `spt_trust::PinnedTlsConnector`:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `pin_spki_sha256` | array of strings | `[]` | SPKI SHA-256 pins (`SHA256:<base64>` or hex). Non-empty enables leaf-cert pinning. |
| `allow_self_signed` | bool | `false` | When `true`, the WebPKI verifier is skipped and the pin set becomes the sole trust anchor. **Requires** a non-empty `pin_spki_sha256` — the builder refuses to disable verification entirely. |
| `max_cert_chain_depth` | integer | `5` (`Some(5)`) when omitted | Maximum intermediates between leaf and trust anchor. Set explicitly to `0` to disallow intermediates entirely. |

The legacy `allow_invalid_certs` flag on `syslog_tls` remains accepted for
back-compat but emits a `remote_log_allow_invalid_certs_deprecated`
warning from `spt config validate`. Operators should migrate to
`allow_self_signed` + `pin_spki_sha256`. The OTLP exporter currently
exposes the same schema-level fields but does not yet route through the
pinned connector (tonic-rustls wiring is deferred to a follow-up).
