# Benchmarking

`spt benchmark` runs structured performance probes against a forward.

## Drivers

| Driver       | Status                                                     |
|--------------|------------------------------------------------------------|
| `latency`    | implemented; synthetic connector or live tunnel TCP stream |
| `throughput` | implemented; synthetic connector or live tunnel TCP stream |
| `udp`        | implemented; synthetic loopback or `LiveConnector::open_udp` |
| `reconnect`  | implemented; synthetic no-op or supervisor close/reconnect trigger |
| `dns`        | implemented through the async `DnsClient` seam             |
| `limits`     | implemented; probes the supplied connector for cap/throttle behavior |

When a CLI benchmark includes `--profile`, the request is sent to the
running supervisor through the MCP loopback and the server-side bridge wires
the live connector and reconnect trigger into the driver suite. Without a
profile, the CLI uses synthetic in-process connectors so reports and formats
can still be exercised offline.

## Safety

Production-impacting drivers require `--unsafe-allow-production-impact` (a
`SafetyError` is returned otherwise). Loopback / dry-run paths are never
gated.

## Result schema

`BenchResult` carries an environment block (host, OS, version, driver), a
metric set (samples, percentiles, throughput), and a free-form notes field.
Reports are written under `<state_dir>/benchmarks/<id>.{json,md}`.

## Compare

    spt benchmark report compare --baseline base.json --candidate cand.json

Outputs a side-by-side diff with per-metric deltas. The compare path is
implemented end-to-end in M0 (it doesn't need a live tunnel).

## Programmatic

See `crates/spt-benchmark/src/lib.rs` for the `BenchmarkDriver` trait.
Tests inject a `Connector` closure that returns `tokio::io::duplex` so the
drivers run without any network.

## Comparative matrix

The release-grade perf surface is a 3 × 3 × 2 × 3 = 54-cell matrix
exercising `spt` against vanilla OpenSSH (`ssh -N`) and `autossh`
across three latency settings, three loss settings, two load profiles,
and three tools:

| Axis      | Values                                        |
|-----------|-----------------------------------------------|
| Latency   | 10 ms, 100 ms, 500 ms (injected by chaos proxy) |
| Loss      | 0%, 1%, 5%                                    |
| Load      | `idle` (64 KiB throughput), `saturated` (4 MiB) |
| Tool      | `spt`, `openssh`, `autossh`                   |

Each cell captures p50 / p99 latency (µs), throughput (bytes / sec, the
dashboard renders as MB/s), reconnect cost (ms), and peak RSS (MB —
populated via the `extras.peak_rss_mb` field on `CellOutcome`).

### Running locally

The matrix runner lives at `scripts/perf/run_matrix.sh`. It writes one
JSON file per cell plus an aggregate `matrix.json` into the directory
named by the `OUT_DIR` environment variable (auto-generated under
`docs/perf/runs/<timestamp>/` when unset).

    # full 54-cell matrix (requires openssh + autossh installed)
    bash scripts/perf/run_matrix.sh

    # spt-only (PR-grade)
    OUT_DIR=docs/perf/runs/local bash scripts/perf/run_matrix.sh --tools spt

    # custom upstream
    bash scripts/perf/run_matrix.sh --upstream 192.0.2.10:22

Per-cell failures are logged but non-fatal — the script exits non-zero
only when **every** cell fails. Cells whose comparator binary isn't
installed report `skipped: true`.

### Installing comparators

The shell-out comparators expect:

- **OpenSSH 9.x** client: `apt-get install openssh-client` /
  `brew install openssh`.
- **autossh 1.4g**: `apt-get install autossh` /
  `brew install autossh`.

On Windows the comparators are not installed by default and the
matrix will report `openssh` / `autossh` cells as skipped.

### Rendering the dashboard

`scripts/perf/render_html.py` consumes the aggregate `matrix.json` and
emits a single self-contained HTML page (no external assets, no
JavaScript dependencies). Each cell is shaded green / yellow / red
based on delta vs the baseline.

    python3 scripts/perf/render_html.py \
      --input    docs/perf/runs/local/matrix.json \
      --baseline docs/perf/baseline-v1.0.json \
      --output   docs/perf/dashboard.html

The dashboard has one tab per `(load × tool)` pair (so six tabs for
the full matrix) and a 3 × 3 grid of (latency rows × loss columns)
inside each tab.

### Regression detection

`scripts/perf/regression_check.py` compares a current `matrix.json`
against `docs/perf/baseline-v1.0.json` cell-by-cell. The default
threshold is 10 % per metric; cells where the baseline value is `null`
(not yet measured) are skipped.

Exit codes:

- `0` — every measured metric is within threshold.
- `1` — at least one regression exceeded threshold; details on stdout.
- `2` — invalid input (missing/unparseable JSON, malformed shape).

    python3 scripts/perf/regression_check.py \
      --baseline docs/perf/baseline-v1.0.json \
      --current  docs/perf/runs/local/matrix.json \
      --threshold 10

> **Note:** perf benchmarking is a local/manual tool. The automated
> `bench-regression` workflow and the published gh-pages perf dashboard have
> been removed; run `render_html.py` and `regression_check.py` locally as
> shown above.

### Baseline maintenance

The checked-in baseline (`docs/perf/baseline-v1.0.json`) is updated
manually after each tagged release. Procedure:

1. Run the full matrix on the release runner (or download the
   `perf-dashboard`-adjacent `matrix.json` artifact from the release
   CI run).
2. Translate each cell with the helper:
   `throughput_mbps = throughput_bps / 1_000_000`,
   `peak_rss_mb = extras.peak_rss_mb` (if recorded). The renderer and
   regression checker accept both shapes — the manual translation is
   only required so the on-disk baseline stays self-describing.
3. Update the top-level `version`, `captured_at` (ISO-8601 UTC) and
   `host` fields.
4. Commit the new baseline file under
   `docs/perf/baseline-v<NEXT>.json` and update the workflow
   reference if rotating.

Cells where the comparator wasn't installed during the capture should
keep `null` metrics with a `note` explaining the skip; this prevents
spurious "regression" alerts on future runs that *do* have the
comparator.
