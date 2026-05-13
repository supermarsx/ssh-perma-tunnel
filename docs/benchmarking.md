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
