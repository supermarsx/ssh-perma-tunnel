# Benchmarking

`spt` ships a structured benchmark driver framework (`crates/spt-benchmark`) and a CLI group (`spt benchmark`) for running performance probes against both live tunnel forwards and synthetic in-process connectors. Separate Criterion micro-benchmarks cover hot-path crates in the workspace.

## The `spt benchmark` command

`spt benchmark` dispatches one of seven driver subcommands. For details on all flags see [CLI Reference](cli-reference.md). For observability of running benchmarks see [Observability](observability.md).

### Subcommands

| Subcommand | Driver | Live tunnel |
|---|---|---|
| `run` | General-purpose dispatcher: select a driver with `--driver <NAME>`. | Yes (latency, throughput, limits, reconnect) |
| `latency` | Round-trip latency: samples, percentiles, jitter. | Yes |
| `throughput` | Sustained byte rate in both directions. | Yes |
| `reconnect` | Supervisor close/reconnect cycle time. | Yes |
| `limits` | Concurrent-connection ceiling and throttle probe. | Yes |
| `udp` | UDP loss and jitter (SSH3 only). | No — synthetic only |
| `dns` | DNS query rate against the internal resolver. | No — synthetic only |

#### `spt benchmark run`

```
spt benchmark run --driver latency --profile edge --forward db --duration 30s --connections 16
spt benchmark run --driver throughput --profile edge --forward db --duration 60s
```

Flags: `--driver NAME`, `--profile`, `--forward`, `--duration`, `--connections`, `--count`, `--unsafe-allow-production-impact`, `--json`.

#### `spt benchmark latency`

```
spt benchmark latency --profile edge --forward db --samples 1000
```

Flags: `--profile`, `--forward`, `--samples`, `--unsafe-allow-production-impact`, `--json`.

#### `spt benchmark throughput`

```
spt benchmark throughput --profile edge --forward db --duration 60s --payload-size 64KiB
```

Flags: `--profile`, `--forward`, `--duration`, `--payload-size`, `--unsafe-allow-production-impact`, `--json`.

#### `spt benchmark reconnect`

```
spt benchmark reconnect --profile edge --iterations 20
```

Flags: `--profile`, `--iterations`, `--unsafe-allow-production-impact`, `--json`.

#### `spt benchmark limits`

```
spt benchmark limits --profile edge --forward db
```

Flags: `--profile`, `--forward`, `--unsafe-allow-production-impact`, `--json`.

#### `spt benchmark udp`

```
spt benchmark udp --profile edge --forward media --duration 30s --packet-size 1400 --pps 500
```

UDP has **no live path**. Running it against a profile returns a structured `UnsupportedPlatform` error. The `TunnelSession` API exposes no raw-datagram seam: even SSH3's advertised UDP capability has no in-process channel to benchmark over. The error message distinguishes SSH2 (no UDP capability) from SSH3 (capability present, no seam). Use this subcommand only against the synthetic loopback connector (no `--profile`).

#### `spt benchmark dns`

```
spt benchmark dns --name registry.internal --samples 500
```

DNS operates against the synthetic loopback resolver only. Flags: `--name`, `--samples`, `--json`.

#### `spt benchmark report compare`

```
spt benchmark report compare --baseline base.json --candidate cand.json
```

Loads two `BenchResult` JSON files and outputs a side-by-side diff with per-metric deltas. This path needs no live tunnel.

#### `spt benchmark report export`

```
spt benchmark report export <RUN-ID> --format markdown --out report.md
```

Exports a stored run from `<state_dir>/benchmarks/<run-id>.json`. Supported formats: `json`, `jsonl`, `csv`, `markdown`.

### Live tunnel mode

When `--profile` is supplied, the CLI sends the benchmark request to the running supervisor through the MCP loopback. The supervisor wires a session-aware live connector (and a live reconnect trigger for the reconnect driver) into the driver. The `latency`, `throughput`, `limits`, and `reconnect` drivers execute against the real tunnel forward.

Without `--profile`, or when the named profile is stopped, the CLI uses synthetic in-process connectors so reports and formats can be exercised offline.

Live-tunnel TCP caveat: the driver targets loopback on the remote side. A full echo round-trip requires the remote host to run an echoer on the target port. Without a remote echoer the write path still genuinely exercises the live session; the driver records read timeouts as errors rather than fabricating throughput.

## Safety gating

Production-impacting drivers (`latency`, `throughput`, `limits`, `reconnect`) require a **two-key opt-in** before they run against a live tunnel:

1. The CLI flag `--unsafe-allow-production-impact` on the command.
2. The config field `[benchmark].allow_production_impact = true`.

Both must be set; setting only one has no effect and returns `SafetyError` (exit 35, `BenchmarkRefused`). The loopback / synthetic path (no `--profile`) is never gated: it cannot impact production by construction.

## The `[benchmark]` configuration table

```toml
[benchmark]
enabled                  = true
default_duration         = "30s"
max_duration             = "300s"
max_connections          = 64
max_bytes_per_second     = "100MiB"
max_packets_per_second   = 10000
require_explicit_target  = false
allow_production_impact  = false
results_dir              = "/var/lib/spt/benchmarks"
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Master switch. When false the `spt benchmark` group returns an error. |
| `default_duration` | duration string | `"30s"` | Duration used when the driver does not specify one. |
| `max_duration` | duration string | `"300s"` | Maximum allowed benchmark duration. Longer requests are rejected. |
| `max_connections` | integer | `64` | Maximum concurrent connections a driver may open. |
| `max_bytes_per_second` | bytesize string | — | Per-direction byte rate cap for throughput drivers. |
| `max_packets_per_second` | integer | — | Packet rate cap for UDP drivers. |
| `require_explicit_target` | bool | `false` | Reject benchmarks that do not supply `--profile` and `--forward`. |
| `allow_production_impact` | bool | `false` | Second key of the production-impact two-key gate. |
| `results_dir` | path string | `<state_dir>/benchmarks` | Directory where result files are written. |

## Result schema

`BenchResult` is the stable, serialisable output of every driver run. Its top-level fields are:

- `env` (`BenchEnv`) — host, OS, `spt` version, driver name, profile and forward names, timestamp, and a notes field.
- `metrics` (`MetricSet`) — sample count, `Percentiles` (p50, p90, p95, p99, p999, min, max), and throughput (bytes/sec).
- `error` — populated when the driver returns a non-fatal partial result.

Results are written as a pair of files:

```
<state_dir>/benchmarks/<run-id>.json
<state_dir>/benchmarks/<run-id>.md
```

The JSON form is the canonical format; the Markdown form is a human-readable summary. Use `spt benchmark report export --format json` to round-trip the JSON through the export pipeline if you need to convert between formats.

## Criterion micro-benchmarks

The following crates carry Criterion benchmark suites that measure hot-path performance at the micro level. Run them with `cargo bench -p <crate>`:

| Crate | Bench file | What is measured |
|---|---|---|
| `spt-config` | `benches/parse.rs` | TOML config parse and validate round-trip |
| `spt-core` | `benches/redaction.rs` | Redaction throughput across the three modes |
| `spt-events` | `benches/hot_paths.rs` | Event bus publish and fan-out |
| `spt-forward` | `benches/token_bucket.rs` | Token-bucket rate-limiter throughput |
| `spt-observability` | `benches/hot_paths.rs` | Metrics write and Prometheus serialisation |
| `spt-protocol` | `benches/forward_state.rs` | Forward state-machine transitions |
| `spt-snmp` | `benches/agent.rs`, `benches/ber.rs`, `benches/usm.rs` | SNMP agent dispatch, BER encode/decode, USM key derivation |
| `spt-ssh3` | `benches/wire.rs` | SSH3 frame encode/decode |
| `spt-state` | `benches/snapshot.rs` | State snapshot serialise/deserialise |
| `spt-stats` | `benches/aggregation.rs` | Counter aggregation and histogram update |
| `spt-trust` | `benches/match_verify.rs` | `known_hosts` pattern match and key verify |

## Comparative performance matrix

The release-grade performance surface is a 3 x 3 x 2 x 3 = 54-cell matrix comparing `spt` against vanilla OpenSSH (`ssh -N`) and `autossh` across network condition axes:

| Axis | Values |
|---|---|
| Latency | 10 ms, 100 ms, 500 ms (injected by the chaos proxy) |
| Loss | 0%, 1%, 5% |
| Load | `idle` (64 KiB throughput), `saturated` (4 MiB) |
| Tool | `spt`, `openssh`, `autossh` |

Each cell captures p50/p99 latency (microseconds), throughput (bytes/sec), reconnect cost (ms), and peak RSS (MB via `extras.peak_rss_mb`).

### Running the matrix

```sh
# full 54-cell matrix (requires openssh + autossh installed)
bash scripts/perf/run_matrix.sh

# spt-only, faster for PR-grade checks
OUT_DIR=docs/perf/runs/local bash scripts/perf/run_matrix.sh --tools spt

# custom remote upstream
bash scripts/perf/run_matrix.sh --upstream 192.0.2.10:22
```

Output goes to the directory named by `OUT_DIR` (defaults to `docs/perf/runs/<timestamp>/`): one JSON file per cell plus an aggregate `matrix.json`. Per-cell failures are non-fatal; the script exits non-zero only when every cell fails. Cells whose comparator binary is absent report `skipped: true`.

Comparator prerequisites:

- OpenSSH 9.x client: `apt-get install openssh-client` / `brew install openssh`
- autossh 1.4g: `apt-get install autossh` / `brew install autossh`
- Windows: comparators are not available by default; those cells are skipped.

### Rendering the dashboard

```sh
python3 scripts/perf/render_html.py \
  --input    docs/perf/runs/local/matrix.json \
  --baseline docs/perf/baseline-v1.0.json \
  --output   docs/perf/dashboard.html
```

Produces a single self-contained HTML page with one tab per `(load x tool)` pair and a 3 x 3 grid of latency-by-loss cells inside each tab. Cells are shaded green/yellow/red based on delta from the baseline.

### Regression detection

```sh
python3 scripts/perf/regression_check.py \
  --baseline docs/perf/baseline-v1.0.json \
  --current  docs/perf/runs/local/matrix.json \
  --threshold 10
```

Compares every cell metric against the baseline with a default 10% threshold. Exit codes:

- `0` — all measured metrics within threshold.
- `1` — at least one regression exceeded threshold; details on stdout.
- `2` — invalid input (missing or malformed JSON).

Cells where the baseline value is `null` are skipped. The automated `bench-regression` workflow and the gh-pages dashboard have been removed; run these scripts locally.

### Baseline maintenance

The checked-in baseline (`docs/perf/baseline-v1.0.json`) is updated manually after each tagged release:

1. Run the full matrix on the release runner or download the `matrix.json` artifact from the release CI run.
2. Translate throughput: `throughput_mbps = throughput_bps / 1_000_000`. Update the top-level `version`, `captured_at` (ISO-8601 UTC), and `host` fields.
3. Commit the new baseline as `docs/perf/baseline-v<NEXT>.json`.

Cells skipped during capture should keep `null` metrics with a `note` explaining why.

## Programmatic use

The `BenchmarkDriver` trait in `crates/spt-benchmark/src/driver.rs` defines the interface all concrete drivers implement. Tests inject a `Connector` closure that returns a `tokio::io::duplex` pair so drivers run without any network. See `crates/spt-benchmark/src/lib.rs` for the public API surface.
