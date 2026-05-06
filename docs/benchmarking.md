# Benchmarking

`spt benchmark` runs structured performance probes against a forward.

## Drivers

| Driver       | Status (M0)                                                |
|--------------|------------------------------------------------------------|
| `latency`    | implemented (loopback duplex; Connector-injectable)        |
| `throughput` | implemented (loopback duplex; Connector-injectable)        |
| `udp`        | stub — wired to live tunnels in M6                         |
| `reconnect`  | stub — needs supervisor handle                             |
| `dns`        | stub — needs DNS handle                                    |
| `limits`     | stub — needs forward-handle                                |

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
