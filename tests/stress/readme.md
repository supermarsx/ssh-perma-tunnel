# `stress` — soak, burst, and fd-leak hunt tests

Standalone (single-package) workspace under `tests/stress/`. Every test in
this crate is `#[ignore]`'d by default and only runs when you ask for it.

## Run

```sh
cargo test -p stress -- --ignored --test-threads 1
```

`--test-threads 1` matters: the tests open ephemeral loopback sockets and
sample process-wide resource counters. Running them concurrently would make
the assertions flap.

To run an individual test:

```sh
cargo test -p stress --test burst_10k -- --ignored --test-threads 1
cargo test -p stress --test fd_leak  -- --ignored --test-threads 1
cargo test -p stress --test soak_24h -- --ignored --test-threads 1
```

## Tests

| File                  | What it does                                                                 | Default threshold(s)                                                                                                |
|-----------------------|------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| `tests/burst_10k.rs`  | 10 000 sequential echo round trips with an embedded russh server held open.  | `PEAK_RSS_GROWTH_BYTES = 64 MiB`                                                                                    |
| `tests/soak_24h.rs`   | Steady-state at 100 conn/s for `SOAK_DURATION` (default 24h).                | `RSS_GROWTH_LIMIT_BYTES = 32 MiB` above rolling-min; `HANDLE_DELTA_LIMIT = 32`                                      |
| `tests/fd_leak.rs`    | 1000 connect/close cycles, then assert open-handle delta vs. baseline.       | `HANDLE_DELTA_LIMIT = 16`                                                                                           |

All thresholds are named `const`s at the top of each test file — adjust
there if a CI host has a tighter or looser budget.

## Determinism

All randomness flows through `stress::seed::rng()`:

- Default seed: `stress::seed::DEFAULT_SEED` (a fixed `u64` constant).
- Override at run time: `SPT_STRESS_SEED=<u64>` env var.

A re-run with the same seed produces the same payload sizes and connection
ordering.

## Shorter soak runs

The 24h default is impractical for CI. Override via:

```sh
SPT_SOAK_DURATION_SECS=60 \
  cargo test -p stress --test soak_24h -- --ignored --test-threads 1
```

For runs under `MIN_SOAK_FOR_ASSERTIONS` (1h by default) the test still
exercises the steady-state path but skips the hourly RSS-trend assertions
and only verifies end-of-run liveness.

## Honesty note: forwarding vs. echo

The `RusshTestServer` shipped from `spt-ssh2/testing` does not implement a
`direct-tcpip` channel handler today — only session-channel data echo. The
stress tests therefore drive their connection loops against an in-process
TCP echo server (`stress::echo::EchoServer`) while keeping a libssh2
session open against the russh server in the background. This still hunts:

- task-handle leaks (any leaked tokio task surfaces as a hang on shutdown),
- file-descriptor / handle leaks (delta vs. baseline),
- monotonic RSS growth (rolling-min vs. hourly samples).

When `t2-e3` (or a follow-on) extends `RusshTestServer` with a `direct-tcpip`
echo handler, the burst test should switch its inner loop to `-L`-style
forwarding through libssh2; the assertion structure does not need to change.

## MSRV / lockfile

- Edition 2021, `rust-version = "1.83"`.
- No new transitive crates: every dev-dep version above already resolves in
  the parent `Cargo.lock`. Building this crate must NOT trigger a
  `cargo update`.
