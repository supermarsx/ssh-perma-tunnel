# Diagnostics

`spt diagnose` runs structured checks against the local environment and a
loaded config. Each check has an id, severity, status, evidence list, and an
optional remediation hint.

## Running

    spt diagnose run                    # batch
    spt diagnose run --report report.json
    spt diagnose port --host db --port 5432 --tcp --autodetect-service
    spt diagnose bundle --out support.tgz --redacted --since 24h

Available subcommands map 1:1 to sub-systems: `network`, `auth`, `trust`,
`dns`, `bind`, `port`, `service`, `secrets`, `observability`, `mcp`.

`diagnose run` registers and executes the **real** check set (it is no
longer a no-op that prints "0 checks") — `run` reuses the same runner and
context as the individual subcommands, honours `--report <path>` to write
the structured JSON report, and **exits non-zero when any check fails**
(`has_failures()`). The `mcp` check spawns `mcp serve --stdio --enable` and
asserts the live tool/resource counts (35 tools / 16 resources); the `ssh2`
check queries the real russh algorithm set; `network`, `dns`/`bind`,
`service`, and `time` (NTP drift) checks run real probes.

## Port autodetect

`diagnose port --autodetect-service` performs a banner-then-probe sweep:
reads the server's first bytes for known patterns (SSH/SMTP/IMAP/POP3/FTP),
or sends a TLS ClientHello / HTTP probe when the peer is silent.

## Bundle contents

`spt diagnose bundle` writes a `tar.gz` containing:

- `manifest.txt`             — generation metadata.
- `version.txt`              — `spt --version` output.
- `effective-config.toml`    — strict-redacted config.
- `status.json`              — last status snapshot.
- `events.jsonl`             — recent events (redacted).
- `logs.txt`                 — log tail.
- `stats.txt`                — Prometheus exposition (the metrics exporter
                               is spawned at `tunnel run` and writes
                               `metrics.prom` in the state dir).
- `report.json`              — structured diagnostic report.

Every text entry is passed through `spt_core::redact(..,
RedactionMode::Strict)` defensively, even after the producer has already
redacted.

## Sharing bundles

Bundles never contain plaintext secret material. They may still contain
hostnames, paths, and process IDs — review before sharing externally.

## Programmatic use

The `DiagnosticRunner` is in `crates/spt-diagnostics`. Register custom
`Diagnostic` impls and call `runner.run(&ctx).await`.
