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

Linux destinations also include `journald`. Remote sinks (`syslog_tls`,
`https_jsonl`, `otlp`) are declared as `[[logging.remote]]` blocks.

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
[`/mibs/SPT-MIB.txt`](../mibs/SPT-MIB.txt). Traps are sent to configured
sinks via UDP.

## Status snapshot

`<state_dir>/status.json` is the source-of-truth document for `spt tunnel
status` and external monitors. Schema in
`crates/spt-state/src/status.rs::StatusSnapshot`.

## OTLP

OTLP export is feature-gated on the `otlp` cargo feature in
`spt-observability`. Enable with `--features spt-observability/otlp` and
configure under `[[logging.remote]]` with `kind = "otlp"`.
