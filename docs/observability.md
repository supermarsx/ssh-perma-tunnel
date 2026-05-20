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
