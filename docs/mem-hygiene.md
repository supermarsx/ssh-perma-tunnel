# Memory Hygiene

`spt` ships an **opt-in** runtime memory-growth monitor. When enabled it
samples the process's resident set size (RSS) on an interval, runs a
sliding-window heuristic over recent samples, and emits a
`memory.leak_suspected` event when it observes sustained growth. It is a
diagnostic aid — a *suspicion* signal you can route to an alert sink — **not**
a definitive leak detector.

The monitor is **off by default.** With no `[mem_hygiene]` block (or
`enabled = false`) the supervisor never spawns the sampler and there is zero
runtime cost.

## `[mem_hygiene]`

    [mem_hygiene]
    enabled             = true       # default: false (off — supervisor only spawns when true)
    interval            = "60s"      # sampling cadence (duration string)
    window_samples      = 30         # sliding-window length (samples)
    growth_threshold    = "64MiB"    # absolute net-growth floor (bytesize string)
    growth_rate_per_min = "2MiB"     # minimum average growth rate (bytesize per minute)
    min_rising_fraction = 0.8        # fraction of adjacent pairs that must rise, in (0, 1]

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Master switch. The monitor only spawns when `true`. |
| `interval` | duration string | `60s` | How often RSS is sampled. |
| `window_samples` | integer (> 0) | `30` | Length of the sliding window. At defaults the window spans `(30-1) * 60s` ≈ 29 minutes. |
| `growth_threshold` | bytesize string | `64MiB` | Net RSS growth across the window must reach this absolute floor before a flag fires. |
| `growth_rate_per_min` | bytesize string | `2MiB` | Average per-minute growth across the window must reach this rate. |
| `min_rising_fraction` | float in `(0, 1]` | `0.8` | Fraction of adjacent sample pairs that must be *strictly* increasing. |

All fields are optional; omitted keys fall back to the defaults above and
round-trip byte-identically through `spt config render`. `spt config validate`
checks `interval` / `growth_threshold` / `growth_rate_per_min` parse, that
`window_samples > 0` (code `mem_hygiene_window_samples_zero`), and that
`min_rising_fraction` is within `(0, 1]` (code
`mem_hygiene_min_rising_fraction_range`) — even when `enabled = false`.

## The growth heuristic

A flag fires only when **all** of the following hold for the most recent
window:

1. **Window full** — at least `window_samples` samples collected (and ≥ 2).
2. **Monotonic enough** — at least `min_rising_fraction` of adjacent sample
   pairs are *strictly* increasing. (A flat line or a single spike on an
   otherwise flat window does not qualify, which rejects one-off jumps.)
3. **Absolute floor** — net growth (newest − oldest sample) is at least
   `growth_threshold`.
4. **Rate floor** — the average growth rate across the window is at least
   `growth_rate_per_min`.

After a flag, the monitor enters a **cooldown**: it re-arms only once RSS drops
back below the flagged baseline, so a single sustained-growth episode produces
**one** event rather than a flood. A transient sampling miss reuses the last
known RSS rather than injecting a phantom zero.

Because this is a heuristic over a coarse RSS signal, treat hits as a prompt to
investigate, and tune the thresholds to your workload — a process with a large
warm cache or bursty buffers can legitimately grow. Raise `growth_threshold` /
`growth_rate_per_min` or `min_rising_fraction` to reduce false positives;
lower them (and/or shorten `interval`) to catch slower leaks sooner.

## The `memory.leak_suspected` event

When the heuristic fires the monitor emits an `Event`:

- `kind` — `memory.leak_suspected`
- `severity` — `warn`
- `fields`:

| Field | Meaning |
|---|---|
| `rss_bytes` | Newest RSS sample. |
| `baseline_rss_bytes` | Oldest sample in the window (the baseline growth is measured from). |
| `growth_bytes` | `rss_bytes - baseline_rss_bytes`. |
| `growth_rate_bytes_per_min` | Average growth rate across the window. |
| `window_secs` | Window span, `(samples - 1) * interval`. |
| `samples` | Number of samples in the window at flag time. |
| `pid` | Monitored process id (`0` if unknown). |

This is a normal event — no event-schema change was needed — so it routes
through the existing pipeline like any other kind.

## Routing the event to a sink

Bind `memory.leak_suspected` to any configured sink the same way you bind other
event kinds. `memory.leak_suspected` is included in the TUI Events page
`KNOWN_KINDS` hint, but `on` stays free-text so globs and arbitrary kinds keep
working:

    [[events.bindings]]
    name = "leak-alert"
    on   = ["memory.leak_suspected"]
    sinks = ["ops-pager"]

See [Events](events.md) for the full binding / sink / dedupe reference.

## `spt status`

When the monitor is enabled, `spt status` renders a **Memory monitor** block
under the subsystems section showing the interval, the last observed RSS, the
number of samples taken, and whether a growth episode has been flagged. The
same fields serialize into the JSON status snapshot.

## Leak / bounded-growth tests

The project carries a memory-leak and bounded-growth test suite built on a
dep-free `CountingAllocator` (a `#[global_allocator]` wrapper over the system
allocator that tracks live and peak bytes via atomics). The leak tests run a
hot path at two iteration counts and assert that the net live-bytes delta is
bounded rather than linear; companion tests assert that long-lived structures
(event ring, disk spool, flow/connection tables, broadcast channels, DNS
caches, and the monitor's own window) stay bounded. These live in dedicated
test binaries so the process-global allocator is never mixed with unit tests.
