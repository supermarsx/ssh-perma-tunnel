# Resilience

`spt` is designed to stay connected. The supervisor combines a formal state machine, full-jitter exponential backoff, a sliding-window instability detector, endpoint failover, and SSH-level keepalives into a layered defence that keeps tunnels alive through transient outages, degraded links, and data-centre events. This chapter explains each layer individually and then traces how they interact end-to-end.

## The supervisor state machine

Every profile runs a 13-state machine defined in `crates/spt-supervisor/src/state_machine.rs`. States are the source of truth for which lifecycle transitions are legal; the `ProfileSupervisor` drives the machine by feeding it the events that arrive from the real world.

| State | Meaning |
|---|---|
| `Disabled` | Profile is administratively disabled. Terminal. |
| `Idle` | Created but not yet started (lazy startup). |
| `Resolving` | DNS resolution in flight for the target host. |
| `Connecting` | TCP or QUIC connect attempt in flight. |
| `Authenticating` | SSH or OIDC authentication exchange in flight. |
| `EstablishingForwards` | Session up; opening the configured forwards. |
| `Active` | Session healthy and all required forwards active. |
| `Degraded` | Session up but at least one non-required forward has failed or is sleeping. |
| `Reconnecting` | Session lost; waiting out the backoff delay before retrying. |
| `FailingOver` | Active endpoint failed; the selector is picking the next endpoint. |
| `Unstable` | Instability detector tripped. |
| `Stopping` | Shutdown in progress. |
| `Stopped` | Terminal — clean shutdown complete. |

Each forward also carries its own 8-state machine (bound, listening, active, failed, sleeping, stopping, stopped, disabled). A required forward going down drives the profile from `Active` to `Reconnecting`; a non-required forward going down drives it to `Degraded`. Forwards in `Degraded` profiles continue operating; the profile reconnects without tearing down running forwards that are still healthy.

The orchestrator runs all profiles under a single `tokio` runtime. Profiles are started up to `profile_start_parallelism` at a time (default: unlimited). See [architecture.md](architecture.md) for the task tree.

## Backoff and jitter

Reconnect policy is configured under `[profiles.reconnect]`. The algorithm is full-jitter exponential backoff:

```
delay_n = uniform(0, min(max_delay, initial_delay * 2^n))
```

With the default `jitter = "100%"` (full jitter), the delay for attempt `n` is drawn uniformly from zero to the exponential ceiling. A fractional `jitter` value introduces a deterministic floor:

```
delay = ceiling * (1 - jitter_fraction) + uniform(0, ceiling * jitter_fraction)
```

Setting `jitter = "0%"` produces a deterministic (no-random) backoff equal to the ceiling at each step, which is useful in labs and integration tests but should not be used in production because it causes reconnect storms when many tunnels share the same bastion.

After the connection has been stable for at least `reset_after`, the attempt counter resets to zero on the next failure, so a long-running session that drops once returns to the short initial delay rather than jumping straight to the maximum.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `initial_delay` | duration | `1s` | First retry delay ceiling. |
| `max_delay` | duration | `60s` | Cap on the exponentially increasing delay. |
| `jitter` | percentage | `100%` | Fraction of the ceiling that is randomized. |
| `reset_after` | duration | `2m` | Reset attempt counter after this much continuous stable uptime. |
| `max_attempts` | integer | `0` | Maximum retries before giving up. `0` means unlimited. |
| `retry_auth_failures` | bool | `false` | Accept authentication failures as retryable. The terminal-vs-retryable error classifier is not yet wired; today auth failures follow the same reconnect path as any other connect error regardless of this field. Full consumer wiring is deferred to Wave C. |

## Instability detection

Transient packet loss produces single drops that backoff handles naturally. A link that fails repeatedly within a short window is qualitatively different: its instability is an operational signal in its own right.

`[profiles.instability]` enables a sliding-window disconnect detector:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Activate the detector. |
| `window` | duration | `60s` | Sliding window over which disconnects are counted. |
| `max_disconnects` | integer | `3` | Maximum disconnects allowed within the window before tripping. |
| `max_keepalive_misses` | integer | `null` | Trip on this many consecutive keepalive probe misses. Disabled when absent. |
| `max_latency_p95` | duration | `null` | Trip when the rolling p95 RTT (64-sample window) exceeds this threshold. Disabled when absent. |
| `min_successful_uptime` | duration | `2m` | Continuous healthy uptime required to clear the instability flag. |
| `action` | string | `mark_degraded` | Response taken when the detector trips. |

When the detector trips the supervisor emits an `InstabilityHit` event and moves the profile to the `Unstable` state. The flag clears once the connection has been stable for `min_successful_uptime`, at which point the profile returns to `Active`.

Available `action` values:

| Value | Effect |
|---|---|
| `mark_degraded` | Move the profile to `Unstable` and escalate backoff. This is the default and the currently fully-wired path. |
| `failover` | Trigger a failover to another endpoint. |
| `increase_keepalive` | Increase the keepalive probe cadence. |
| `increase_backoff` | Increase the reconnect backoff ceiling. |
| `emit_event` | Emit an instability event without changing behaviour. |
| `restart_session` | Tear down and restart the current session immediately. |

The `mark_degraded` action corresponds to the historical fixed behaviour and is the most thoroughly tested path. The other actions are defined and recognised by the config validator; their full consumer wiring in `ProfileSupervisor` is pending (Wave C).

## Endpoint failover

A profile can declare multiple endpoints under `[[profiles.endpoints]]`. The failover selector chooses which endpoint is attempted, supports three modes, and implements per-endpoint cooldowns.

`[profiles.failover]` controls the selector:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `mode` | string | `priority` | Selection strategy: `priority`, `weighted`, or `manual`. |
| `health_check` | string | `tcp_connect` | Probing style: `tcp_connect`, `ssh_handshake`, `ssh_auth_preflight`, or `ssh3_endpoint`. |
| `fail_after` | integer | `3` | Consecutive failures before an endpoint enters cooldown. |
| `restore_after` | duration | `2m` | Time an endpoint must be reachable before it leaves cooldown. |

Selection modes:

- **`priority`** — The selector always picks the endpoint with the numerically lowest `priority` field that is not in cooldown. When the primary enters cooldown the next lowest-priority endpoint is used. When the primary recovers and `restore_after` expires, traffic returns to it.
- **`weighted`** — Among endpoints sharing the lowest priority value, selection is weighted-random by the `weight` field.
- **`manual`** — Only the endpoint named by `spt tunnel failover <profile> --to <endpoint>` is used. All other endpoints are ignored until the override is cleared.

Each endpoint entry supports per-endpoint authentication that fully overrides the profile-level `[profiles.auth]` block for that endpoint:

```toml
[[profiles.endpoints]]
name = "primary"
host = "edge-primary.example.com"
port = 22
priority = 0
weight = 100

[[profiles.endpoints]]
name = "dr"
host = "edge-dr.example.com"
port = 22
priority = 10
weight = 50
user = "tunnel-dr"     # optional per-endpoint user
```

When no endpoints are configured the profile connects to the top-level `host` and `port` fields directly. When endpoints are present, `host` and `port` act as a fallback of last resort if all endpoints are in cooldown.

For more detail on per-endpoint auth and forwarding interactions see [forwarding.md](forwarding.md) and [configuration-reference.md](configuration-reference.md).

## Keepalive liveness

SSH-level keepalive probes detect dead connections faster than TCP socket timeouts. Without them a silent firewall or NAT box can hold the socket open while the tunnel is effectively dead.

`[profiles.keepalive]` controls the probe cadence:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `interval` | duration | none | Time between keepalive probes. A probe is sent every `interval` while the session is `Active`. |
| `timeout` | duration | none | Maximum time to wait for a probe response. |
| `max_missed` | integer | none | Consecutive missed probes before the session is treated as dead and `SessionLost` is signalled. |

Keepalive events feed the instability detector. A missed probe increments the consecutive-miss counter; `max_keepalive_misses` in `[profiles.instability]` sets the threshold before the instability flag trips, independently of the disconnect count.

If `[profiles.keepalive]` is absent, no SSH-level probes are sent. TCP socket-level keepalive is controlled separately in `[profiles.connection]` (`socket_keepalive`, `keepalive_idle`, `keepalive_interval`, `keepalive_retries`).

## Connection limits

`[profiles.limits]` caps resource consumption per profile:

| Field | Type | Meaning |
|---|---|---|
| `max_active_connections` | integer | Maximum concurrent forwarded connections. |
| `max_new_connections_per_second` | integer | Admission rate limit. |
| `max_bytes_per_second_in` | bytesize | Inbound byte-rate cap. |
| `max_bytes_per_second_out` | bytesize | Outbound byte-rate cap. |
| `max_bits_per_second_in` | bitrate | Inbound bit-rate (display only; not independently enforced). |
| `max_bits_per_second_out` | bitrate | Outbound bit-rate (display only). |
| `throttle_algorithm` | string | Throttle algorithm used when byte-rate limits are active. |
| `max_connection_lifetime` | duration | Forcibly close connections older than this. |

Per-forward limits (`max_connections`, `max_bytes_per_second_in`, `max_bytes_per_second_out`, `max_new_connections_per_second`, `idle_timeout`) are set directly on each `[[profiles.forwards]]` entry and take precedence over the profile-level limits for traffic on that forward. See [forwarding.md](forwarding.md).

## Health checks

When a profile is in `Reconnecting` or `FailingOver`, the supervisor can actively probe endpoints before committing to a reconnect attempt. The `health_check` field in `[profiles.failover]` selects the probe depth:

| Value | What it does |
|---|---|
| `tcp_connect` | TCP three-way handshake only. Fast; does not establish an SSH session. |
| `ssh_handshake` | TCP connect plus the SSH protocol negotiation (version exchange). |
| `ssh_auth_preflight` | SSH handshake plus a lightweight auth attempt to verify credentials are still accepted. |
| `ssh3_endpoint` | HTTP/3 CONNECT probe for SSH3 profiles. |

Deeper health checks catch more failure modes (expired certificates, rotated host keys) at the cost of slightly higher probe latency.

## systemd watchdog and service restart policy

`spt` integrates with the systemd supervisor through `[service]`:

| Field | Type | Meaning |
|---|---|---|
| `restart_policy` | string | `always`, `on-failure`, or `never`. Shapes `Restart=` in the generated unit. |
| `sd_notify` | bool | Enable `Type=notify` and call `sd_notify(READY=1)` after the orchestrator is running. Linux only. |
| `watchdog_sec` | integer | Sets `WatchdogSec=` in seconds. The process must post `WATCHDOG=1` within this interval or systemd will restart it. Required to arm the watchdog pinger; omitting this field disables watchdog supervision. |
| `user` | string | Drop to this user after service start. |
| `group` | string | Run as this group. |
| `env` | map | Extra environment variables baked into the generated unit. |
| `stdout` / `stderr` | path | Standard output and error log paths (launchd and SysV only). |

When `watchdog_sec` is set and `sd_notify = true`, the supervisor posts `WATCHDOG=1` on a timer driven by the watchdog interval. If the supervisor deadlocks or blocks, systemd will kill and restart the process within `watchdog_sec` * 2 seconds.

`spt service install` reads `[service]` from the config file and merges its fields over any CLI flags. Fields absent from the config preserve the CLI-driven defaults. See [service.md](service.md) for the full install and uninstall reference.

## OOM pressure and cgroup monitoring

The `[mem_hygiene]` table configures an optional runtime memory-growth monitor. It is disabled by default and has zero cost when absent. When enabled (`enabled = true`) the supervisor spawns a sampling task that watches RSS and emits structured events when growth exceeds the configured thresholds.

Beyond the sliding-window RSS heuristic (detailed in the event docs), two additional checks are available:

| Field | Type | Meaning |
|---|---|---|
| `rss_high` | bytesize | Absolute RSS high-water mark. Crossing it emits a `memory.high_water` event (OOM P3 severity). Disabled when absent. Wave 8. |
| `cgroup_watch` | bool | Enable cgroup `memory.max` / `memory.current` / `oom_kill` watching on Linux. Default `false`. Ignored on non-Linux targets. Wave 8. |
| `cgroup_pressure_pct` | float | When cgroup memory usage crosses this percentage of `memory.max`, a `memory.cgroup_pressure` event is emitted (OOM P2). Requires `cgroup_watch = true`. Disabled when absent. Wave 8. |

All three fields are validated by `spt config validate` even when `enabled = false`. The monitor emits events into the same event bus that feeds `[[events.bindings]]`, so you can route `memory.leak_suspected`, `memory.high_water`, and `memory.cgroup_pressure` to any configured sink without writing any extra code.

For secrets in memory and zeroing-on-drop behaviour see [secrets.md](secrets.md) and [security.md](security.md).

## Graceful shutdown

When `spt tunnel stop` is received (or the process receives SIGTERM on Unix), the orchestrator:

1. Signals all profiles to enter the `Stopping` state.
2. Waits up to `runtime.shutdown_grace` for in-flight connections to drain. The default is enough for a clean close of most SSH channels; reduce it for aggressive restarts.
3. Forces-closes any connections that have not drained before the grace period expires.
4. Releases all port binds and file locks.

A `required_profiles` list in `[runtime]` marks profiles whose failure makes the process as a whole unhealthy. If a required profile cannot reconnect within its retry budget, the supervisor can escalate to process-level failure, which allows the service manager to handle the restart.

## End-to-end failure flow

This section traces a single link drop through the full stack using the `edge-ha` profile from the example below.

1. **Drop detected.** The TCP connection to `edge-primary.example.com` silently dies. The SSH keepalive (20 s interval, 5 s timeout, 3 miss max) fires three missed probes and signals `SessionLost` to the state machine. The profile moves from `Active` to `Reconnecting`.

2. **Backoff computed.** The reconnect module draws a delay from `uniform(0, min(2m, 1s * 2^n))` where `n` is the current attempt count. At attempt 0 the ceiling is 1 s, so the delay is a random value in `[0, 1s)`. Jitter is 30 %, meaning the floor is 70 % of the ceiling: `delay = 0.7 * 1s + uniform(0, 0.3 * 1s)`.

3. **Instability check.** Each `SessionLost` event also increments the instability detector's sliding-window counter. If the window already contains 3 disconnects within 10 minutes, the detector trips and sends `InstabilityHit`. The profile moves to `Unstable`. Because `action = "failover"` is set, the supervisor triggers a failover pick instead of simply escalating backoff.

4. **Failover pick.** The endpoint selector (mode `priority`) checks whether `primary` is still in cooldown. If it is (because `fail_after = 3` consecutive probe failures have been registered), it selects the `dr` endpoint (`priority = 10`). The profile transitions to `FailingOver`.

5. **Health check.** Before attempting to reconnect, the selector runs an `ssh_handshake` probe against `dr`. If the handshake succeeds, `EndpointReady` is fired and the profile moves to `Resolving` for the new target.

6. **Reconnect.** The profile resolves the `dr` hostname, opens a TCP connection, authenticates, establishes the `db` forward, and enters `Active`.

7. **Failback.** Once `restore_after = "2m"` expires with `primary` passing health checks, the selector removes it from cooldown. On the next drop (or manual `spt tunnel failover edge-ha --to primary`), it becomes eligible again.

8. **Instability clears.** After `min_successful_uptime = "3m"` of stable connection, `InstabilityClr` is emitted and the `Unstable` flag clears.

## Example: HA failover configuration

The following is the `examples/ha-failover.toml` file shipped with `spt`, edited for clarity:

```toml
version = 1

[runtime]
state_dir = "/var/lib/spt"
required_profiles = ["edge-ha"]
shutdown_grace = "20s"
profile_start_parallelism = 2

[logging]
level = "info"
format = "json"
destinations = ["file"]
file = "/var/log/spt/spt.jsonl"
rotate = "daily"
max_files = 30
redact = ["secrets", "auth"]

[[profiles]]
name = "edge-ha"
enabled = true
protocol = "ssh2"
host = "edge-primary.example.com"
port = 22
user = "tunnel"
network_change_reconnect = true
failure_policy = "retry"

[profiles.auth]
method = "public_key"
identity_file = "/etc/spt/id_ed25519"
passphrase = "secret://ssh/edge-ha/passphrase"

[profiles.trust]
mode = "known_hosts"
known_hosts_file = "/etc/spt/known_hosts"
strict = true

[profiles.keepalive]
interval = "20s"
timeout = "5s"
max_missed = 3

[profiles.reconnect]
initial_delay = "1s"
max_delay = "2m"
jitter = "30%"
reset_after = "5m"

[profiles.instability]
enabled = true
window = "10m"
max_disconnects = 4
max_keepalive_misses = 2
action = "failover"
min_successful_uptime = "3m"

[profiles.failover]
mode = "priority"
health_check = "ssh_handshake"
fail_after = 3
restore_after = "2m"

[[profiles.endpoints]]
name = "primary"
host = "edge-primary.example.com"
port = 22
priority = 0
weight = 100

[[profiles.endpoints]]
name = "dr"
host = "edge-dr.example.com"
port = 22
priority = 10
weight = 50

[[profiles.forwards]]
name = "db"
type = "local"
transport = "tcp"
bind = "127.0.0.1:5432"
target = "db.internal:5432"
target_resolve = "remote"
required = true
idle_timeout = "10m"
max_connections = 128
```

`spt config validate --config examples/ha-failover.toml` checks this file without starting a tunnel.

## Related pages

- [forwarding.md](forwarding.md) — per-forward limits, bind modes, and UDP forwarding
- [configuration-reference.md](configuration-reference.md) — full field reference for every table in this chapter
- [service.md](service.md) — systemd/launchd/Windows service install and watchdog wiring
- [observability.md](observability.md) — events and metrics emitted by the supervisor state machine
- [secrets.md](secrets.md) — how credentials referenced by `secret://` URIs are resolved
- [security.md](security.md) — memory protection, zeroing-on-drop, and the security model
- [troubleshooting.md](troubleshooting.md) — diagnosing stuck reconnect loops and instability storms
