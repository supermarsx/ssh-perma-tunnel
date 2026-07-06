# Architecture

`spt` is a Cargo **workspace** of roughly three dozen focused crates. A thin
binary (`spt-bin`) wires a Clap CLI (`spt-cli`) on top of a supervisor that
drives protocol backends through a shared adapter trait. This chapter is the
map the rest of the book refers back to: it names the subsystems, explains how
bytes actually move, traces the lifecycle a profile walks through, and draws
the trust and observability boundaries the other chapters expand on.

If you only read one section, read [The data plane](#the-data-plane) and
[The control plane](#the-control-plane--the-supervisor): they are the
correctness-critical core of the tool and the parts that are most heavily
regression-tested.

## Design principles

Everything in `spt` follows from a small set of deliberate choices. When a
design decision is ambiguous elsewhere in the book, these principles are the
tie-breaker.

- **Client-only.** `spt` is an SSH/SSH3 *client*. It never runs a general
  server role. The only inbound listeners that exist are the local forward
  listeners the operator explicitly configures (and, for spt-to-spt testing,
  the opt-in `spt ssh3-serve` responder). This shrinks the attack surface to
  what the operator asked for. See [The spt ↔ spt model](#the-spt--spt-model).
- **Configuration is the single source of truth.** Desired behaviour lives in
  the config file, not in runtime state. The supervisor's job is to make the
  world match the config; runtime state exists for observability and recovery,
  never as the authority for *what should be true*. See
  [Configuration as the source of truth](#configuration-as-the-source-of-truth).
- **Fail-closed.** Trust is verified before any secret byte is transmitted; an
  unknown host in strict mode, a pin mismatch, or a missing `[profiles.trust]`
  table stops the connection rather than proceeding hopefully. An invalid
  config reload keeps the *old* config running rather than swapping in a broken
  one. A second supervisor against the same state directory refuses to start.
- **Pure-Rust, memory-safe stack.** The SSH2 backend is built on `russh`, not
  the libssh2 C library; the SSH3 backend on `rustls`/`quinn`/`h3`. Crates that
  parse untrusted wire bytes (`spt-protocol`, `spt-snmp`, `spt-obfs`,
  `spt-trust`) forbid `unsafe`, and the release profile builds with
  `overflow-checks = true` so length-field arithmetic panics deterministically
  instead of wrapping. See [Security](security.md).
- **Observable by default.** Every lifecycle transition emits a typed event;
  every text output is redacted before it leaves the process; counters, session
  tables, and a `status.json` snapshot are always available. You should never
  have to attach a debugger to find out what a tunnel is doing.
- **Self-healing.** A profile that drops reconnects with jittered backoff,
  detects instability, fails over to a standby endpoint, and returns to its
  primary automatically — all without operator intervention. See
  [Resilience](resilience.md).

## The spt ↔ spt model

`spt` is a **client**. It speaks to an existing SSH2 or SSH3 server. In the
SSH2 case that server is any RFC 4253/4254 implementation (OpenSSH, dropbear,
…). In the SSH3 case it is the `francoismichel/ssh3` reference server — or,
for spt-to-spt interop, another `spt` running `spt ssh3-serve`. There is no
general server role: forward *listeners* live on the client side (local and
dynamic forwards) or are requested from the server (remote/reverse forwards via
`tcpip-forward`).

```text
        ┌────────────── spt (client) ──────────────┐
        │  CLI (clap)   ──►  Supervisor state m/c   │
        │      │                    │               │
        │   Config             Protocol adapter     │        ┌── SSH server ──┐
 local  │      │              ┌─────┴──────┐        │        │   OpenSSH /    │
apps ──►│  Forwarders ───────►│ ssh2 / ssh3│───────►│══tunnel═►  dropbear /   │
        │  (local/dyn)        └─────┬──────┘        │        │   ssh3 ref /   │
        │      ▲               obfuscation          │        │   spt ssh3-serve│
        │      └── remote/reverse listeners ◄───────│◄═══════│                │
        └───────────────────────────────────────────┘        └────────────────┘
```

The consequence of the client-only model shows up everywhere: trust is always
*outbound* (we verify the server, the server does not verify us beyond
authentication), the only privileged operation is binding a low local port, and
the "server" half of a spt-to-spt tunnel is a deliberately-scoped testing
feature rather than a supported deployment target. See [Transports](transports.md).

## Layered overview

`spt` is layered. Each layer depends only on the ones beneath it and exposes a
narrow interface upward. Reading top to bottom is the path a byte of desired
configuration takes to become a byte on the wire; reading bottom to top is the
path a packet from a local application takes to reach the far side.

```text
  ┌───────────────────────────────────────────────────────────────────────┐
  │ Front-ends      CLI (spt-cli) · TUI (spt-tui) · service manager       │
  │                 all three drive the SAME core                         │
  ├───────────────────────────────────────────────────────────────────────┤
  │ Configuration   spt-config → ConfigCell (validate-before-swap)        │
  │                 TOML → validate → migrate → canonical Config          │
  ├───────────────────────────────────────────────────────────────────────┤
  │ Orchestrator    spt-supervisor::Orchestrator                          │
  │                 one task per profile · shutdown gate · reload apply   │
  ├───────────────────────────────────────────────────────────────────────┤
  │ Profile control ProfileSupervisor + 13-state machine                  │
  │                 connect → auth → forwards → healthy → reconnect …     │
  ├───────────────────────────────────────────────────────────────────────┤
  │ Session /       TunnelProtocol::connect → Box<dyn TunnelSession>      │
  │ transport       ssh2 (russh) · ssh3 (QUIC/H3) · obfs (under ssh2)     │
  ├───────────────────────────────────────────────────────────────────────┤
  │ Channels        multiplexed per-forward channels on the session       │
  │                 direct-tcpip · tcpip-forward · streamlocal · QUIC     │
  ├───────────────────────────────────────────────────────────────────────┤
  │ Forwarders      spt-forward: L / R / D / UDS / UDP runners            │
  │                 accept → open channel → hand to the data plane        │
  ├───────────────────────────────────────────────────────────────────────┤
  │ Data plane      copy_bidirectional_throttled_idle                     │
  │                 two independent directions · half-close · throttle    │
  └───────────────────────────────────────────────────────────────────────┘

        Cross-cutting planes — woven through every layer above, not a
        layer of their own:
          • Trust           spt-trust
          • Secrets         spt-secrets · spt-mem-hygiene
          • Events & obs.   spt-events · spt-observability · spt-stats · spt-snmp
          • Service mgmt    spt-service
```

The four **cross-cutting planes** below the stack are not a layer of their own —
they thread through all of them. Trust decisions happen at the transport layer
but are configured per-profile and per-hop; secret resolution happens wherever a
credential is needed; the event/observability plane taps every layer's state
transitions; and the service plane wraps the whole process for an init system.

## Subsystem map (crate by crate)

The workspace groups roughly by concern. The core, protocol, and transport
crates form the spine; the rest are cross-cutting planes and integrations.

**Core & protocol**

| Crate | Role |
|-------|------|
| `spt-bin` | The `spt` binary entry point; wires everything together (runtime, reload pipeline, side-channels, signals). |
| `spt-core` | Core types, the 38 stable exit codes, error taxonomy, byte-level redaction, parsers. |
| `spt-protocol` | The tunnel adapter traits every backend implements (`TunnelProtocol`, `TunnelSession`, forward specs). |
| `spt-cli` | The Clap-derived command tree — one module per command group. |
| `spt-config` | TOML schema, validation, rendering, diffing, migration, `mutate::Document`. |
| `spt-state` | Runtime state directory, single-supervisor lock, atomic writes, status snapshot, event ring. |

**Transports** — see [Transports](transports.md)

| Crate | Role |
|-------|------|
| `spt-ssh2` | SSH2 backend on the pure-Rust `russh` crate. |
| `spt-ssh3` | SSH3 backend on QUIC + rustls + HTTP/3 (RTH3), incl. the `spt ssh3-serve` responder. |
| `spt-obfs` | Pluggable obfuscation transports (obfs4, meek, WebSocket, Shadowsocks) layered beneath SSH2. |
| `spt-net` | Address parsing, interface enumeration, bind-policy, socket options. |

**Forwarding & file transfer** — see [Forwarding](forwarding.md)

| Crate | Role |
|-------|------|
| `spt-forward` | Forwarding building blocks (bidirectional copy, token buckets, ACLs, listeners) + the supervisor-facing `ForwardRunner`. |
| `spt-sftp` | SFTP client (one-shot ops + recursive transfer + mount). |
| `spt-ftp-translator` | Passive-only FTP→SFTP translator with AUTH TLS upgrade. |

**Resilience** — see [Resilience & Self-Healing](resilience.md)

| Crate | Role |
|-------|------|
| `spt-supervisor` | Orchestrator + per-profile state machine; reconnect / instability / failover / round-robin. |
| `spt-chaos-proxy` | Fault-injecting TCP proxy used by the reconnect test suite. |

**Auth, trust & secrets** — see [Authentication](authentication.md), [Trust](trust.md), [Secrets](secrets.md)

| Crate | Role |
|-------|------|
| `spt-auth` | Protocol-agnostic auth method types + validation. |
| `spt-auth-sspi` | GSSAPI / Kerberos / SSPI / NTLM provider backends. |
| `spt-key` | Key generation, fingerprinting, OpenSSH user-certificate handling. |
| `spt-trust` | `known_hosts`, SHA-256 host pinning, CRL, TOFU, the `PinnedTlsConnector`. |
| `spt-secrets` | Secret resolver, encrypted vault, OS keychain, non-swappable allocations. |
| `spt-config-crypt` | Sealed-config envelope (`SPTENC1`). |
| `spt-mem-hygiene` | Best-effort process memory hardening (mlock, zeroize, dumpability). |

**Observability & events** — see [Observability](observability.md)

| Crate | Role |
|-------|------|
| `spt-observability` | Tracing stack, redaction wrapper, file rotation, remote sinks, metrics. |
| `spt-events` | Event bus, binding evaluator, dispatcher, notification sinks. |
| `spt-stats` | Rolling counters, sliding windows, EWMA, session/connection tables. |
| `spt-snmp` | SNMPv3 agent + traps (SPT-MIB), no `spt-*` deps and no `unsafe`. |
| `spt-winevent` | Windows Event Log integration. |
| `spt-status-api` | Read-only HTTP/JSON status API. |
| `spt-diagnostics` | Structured diagnostic checks + redacted bundle builder. |
| `spt-benchmark` | Benchmark drivers and result schemas. |

**Integrations & platform** — see [Integrations](mcp.md) and [Service Management](service.md)

| Crate | Role |
|-------|------|
| `spt-mcp` | Model Context Protocol control server (read-only by default). |
| `spt-dns` | Transparent DNS resolver + hosts-file manager. |
| `spt-firewall` | Cross-platform firewall planners. |
| `spt-scripting` | Sandboxed Rhai scripting hooks. |
| `spt-remote-config` | Remote config fetch with HTTPS pinning and sealed-envelope auto-unseal. |
| `spt-updater` | Embedded, signature-verifying auto-updater. |
| `spt-service` | systemd / launchd / SCM / OpenRC / SysV / Task Scheduler. |
| `spt-tui` | Terminal-UI profile configurator. |

The dependency direction is strict: `spt-protocol` contains *only* types and
traits (no I/O), so the supervisor can drive `ssh2` and `ssh3` through the same
seam without depending on either concretely. `spt-core` sits below everything
and depends on nothing in the workspace. Circular dependencies are structurally
impossible because the transport crates never call back up into the supervisor.

## The data plane

Once a session is authenticated and a forward's listener has accepted a
connection, the actual work of `spt` is moving bytes. This is the hot path, it
is where correctness bugs cause silent data corruption or truncation, and it is
therefore the most carefully written and most heavily regression-tested part of
the tool. The core lives in `crates/spt-forward/src/bidir.rs`.

### Two independent directions

Each accepted connection is a pair of duplex streams: the *application* side
(the local socket the app connected to, or the channel the server handed us) and
the *tunnel* side (the SSH/QUIC channel to the far end). `spt` splits each
stream into its read and write half and runs **two independent copy loops**:

```text
   app ──read──►  copy a→b  ──throttle──►  write ──► tunnel
   app ◄──write── copy b→a  ◄──throttle──  read  ◄── tunnel
                        tokio::join!(a→b, b→a)
```

The two directions are joined with `tokio::join!`, so they make progress
concurrently on the same task. This concurrency is not an optimisation — it is
required for correctness. A protocol like SMTP or a database wire protocol
interleaves request and response bytes; if one direction blocked the other, a
peer waiting to read its response while we are blocked reading its next request
would deadlock. Copying both directions concurrently is the only way to
faithfully relay a full-duplex stream.

### Half-close and EOF propagation

The directions are otherwise fully independent: **a half-close on one side does
not tear down the other.** When a copy loop reads EOF (a zero-length read) it
calls `shutdown()` on its downstream write half — propagating the half-close so
the peer observes the same EOF — and then returns, leaving the *opposite*
direction still copying. Only when *both* directions have closed (or one errors)
does the connection finish and its stats get recorded. This preserves the
TCP half-close semantics that protocols such as HTTP/1.0-with-`Connection: close`
and some RPC frames depend on.

### Backpressure

There is no unbounded buffering anywhere in the path. Each copy loop reuses a
single heap-allocated 16 KiB scratch buffer (`Box<[MaybeUninit<u8>; 16 KiB]>`,
allocated once per direction rather than per read, and only ever exposing its
initialised prefix to the writer). The loop reads a chunk, then `write_all`s it
downstream *before reading again*. If the downstream (tunnel or app) is slow to
accept bytes, the `write_all` future does not complete, the loop does not read
more, and the read backpressure propagates all the way to the origin socket via
the OS receive window. Memory use per connection is therefore bounded to a
couple of buffers regardless of throughput mismatch between the two sides.

### Rate limiting: the token bucket

Per-direction throughput caps (`max_bytes_per_second_in` /
`_out`, with `max_burst_bytes_*`) are enforced by a `TokenBucket` that each copy
loop consults *before* issuing its downstream write. Crucially the bucket
throttles the **write**, not just the read: a slow bucket makes `write_all` wait,
which backpressures the read, which backpressures the origin. Throttling the read
alone would let bytes pile up in the write buffer and defeat the cap. Pass
`TokenBucket::unlimited()` to disable a direction with zero overhead — the bucket
is only consulted when `is_active()`.

### The idle watchdog vs. the throttle

An idle connection should be reclaimed after `idle_timeout`, but a
*legitimately slow* connection — one that is draining real data through a tight
rate limit — must **not** be mistaken for idle and truncated. Reconciling these
two is subtle, and getting it wrong silently corrupts throttled uploads. `spt`
solves it with a shared `ActivityBeacon` carrying two relaxed atomics:

- a **generation** counter, bumped once when a non-empty chunk is read and again
  when its write completes; and
- an **in-flight** counter, incremented for the entire duration a direction
  spends draining a chunk — that is, across *both* the token-bucket `acquire`
  and the downstream `write_all`.

A lightweight watchdog samples the beacon at `idle_timeout` cadence. It closes
the connection only when two consecutive samples show the generation has not
advanced **and** no direction is in-flight. The in-flight mark is the crux: a
16 KiB chunk metered at 1 KiB/s sits inside `acquire` for ~16 seconds — far
longer than a short idle window — during which the generation does not move. But
because the direction is marked in-flight the whole time, the watchdog reads the
connection as *busy, just slow* and never idle-closes it. This behaviour is
pinned by regression tests (`throttled_transfer_not_idle_closed`,
`throttled_but_quiescent_still_idle_closes`) that assert both the no-false-close
and the still-closes-when-genuinely-idle properties.

The same `copy_bidirectional_throttled_idle` core backs every forward flavour —
local TCP, remote/reverse TCP, dynamic SOCKS/HTTP, UNIX-domain sockets, and the
`tcp-framed` UDP mode — so all of them inherit identical half-close,
backpressure, throttle, and idle semantics. UDP additionally layers a NAT-style
flow table over the top; see [Forwarding](forwarding.md).

## The control plane — the supervisor

Where the data plane moves bytes, the control plane decides *whether a session
should exist at all* and drives it through its lifecycle. It lives in
`crates/spt-supervisor`.

### Orchestrator and per-profile tasks

The `Orchestrator` owns one `ProfileSupervisor` per enabled profile, each
running as its own `tokio` task under a single shared runtime. Profiles are
started up to `profile_start_parallelism` at a time. The orchestrator holds a
lock over its profile map and honours a **shutdown gate**: once graceful
shutdown has begun, the gate is raised *under the same lock* that spawns
profiles, so a config-reload or watcher event racing shutdown can never
resurrect a drained profile. Reloads re-drive the map (start new profiles, stop
removed ones, restart changed ones) through the same gated path.

### The 13-state profile machine

Each profile is governed by a small, pure state machine
(`state_machine.rs`) that is the *source of truth for which transitions are
legal*. The supervisor feeds it events drawn from the real world
(`ResolveOk`, `ConnectFail`, `AuthOk`, `SessionLost`, `InstabilityHit`,
`FailoverPick`, …) and the machine returns the next legal state or rejects the
transition.

```text
  Idle ─Start─► Resolving ─ResolveOk─► Connecting ─ConnectOk─► Authenticating
                                                                      │ AuthOk
                                                                      ▼
                     ┌──────────────── EstablishingForwards ◄─────────┘
                     │ ForwardsUp          │ ForwardDown
                     ▼                     ▼
                  Active ◄──ForwardUp──► Degraded
                   │  ▲                    │
      SessionLost  │  │ InstabilityClear   │ SessionLost
                   ▼  │                    ▼
              Reconnecting ◄───────────────┘
                   │  ▲
      FailoverPick │  │ EndpointReady / RetryNow
                   ▼  │
              FailingOver ──► (Resolving, new endpoint)

  InstabilityHit from {Active, Degraded, EstablishingForwards} ──► Unstable
  Stop from any non-terminal ──► Stopping ──Stopped──► (terminal)
  Disable from any non-terminal ──► Disabled (terminal)
```

The full transition table (every event × every state) is documented inline in
`state_machine.rs` and mirrored in [Resilience](resilience.md). Terminal states
are `Stopped` and `Disabled`; everything else can still move. A **required**
forward going down drives `Active → Reconnecting`; a **non-required** one drives
`Active → Degraded`, and a degraded profile keeps its healthy forwards running
while it recovers rather than tearing everything down.

### Terminal vs. retryable failures

Not every failure is worth retrying. The supervisor classifies connect errors:
`Error::TrustFailed` (host-key mismatch, pin failure, TLS-pin failure) and
`Error::KeyFailure` (a key or certificate that cannot be loaded) are
**terminal**. A host key that mismatched will never be accepted on retry, and a
malformed key file will never parse on retry — spinning the backoff loop against
them just produces noise and hides the real problem. On a terminal connect error
the supervisor emits `profile.connect_failed_terminal`, logs a fix-it message
("fix the host key / key file and restart"), and stops the profile rather than
reconnecting. Transient errors (DNS failure, network unreachable, keepalive
timeout, ordinary connect refusal) rejoin the backoff loop. Authentication
failures are classified separately and follow the `retry_auth_failures` policy.

### Keepalive, health, backoff

The resilience machinery layered on top of the state machine — SSH-level
keepalive probes, the full-jitter exponential backoff, the sliding-window
instability detector, endpoint failover with per-endpoint cooldowns, and active
health checks (`tcp_connect` … `ssh_auth_preflight`) — is documented in depth in
[Resilience](resilience.md), including a worked end-to-end failure trace. The
health-check preflight reuses the transport's `preflight_connect` primitive: a
throwaway connect+auth dial against a candidate endpoint that never disturbs the
established forwards.

### Graceful shutdown gate

On `spt tunnel stop` or SIGTERM, the orchestrator raises its shutdown gate and
stops every profile concurrently. Each profile drains in-flight connections up
to `runtime.shutdown_grace`, then force-closes what has not drained, releases its
port binds, and reports `Stopped`. On the signal path an aggregate deadline
bounds the whole drain so a wedged profile cannot hold the process open forever.
The state lock and PID file are released last, on drop. See
[Resilience](resilience.md#graceful-shutdown) and [Service](service.md) for the
watchdog and restart-policy interaction.

## Configuration & hot reload

Configuration is loaded, validated, and migrated by `spt-config` (see
[Configuration Overview](configuration-overview.md)) and then held live in a
`ConfigCell` — the one shared "last-applied config" cell used by **both** the
SIGHUP reload path and the MCP `reload` control tool.

The reload pipeline (`crates/spt-bin/src/controller.rs::run_reload_pipeline`) is
strictly **validate-before-swap**. The cell's inner mutex is held across the
*entire* reload so two concurrent reloads cannot diff against the same stale
baseline, and the sequence is:

1. **Re-apply enforced policy** (GPO / administrator overlay) so an enforced
   binding survives a reload rather than being silently stripped until the next
   restart.
2. **Surface unknown-key warnings** now that a subscriber (the running tracing
   stack) exists to log them.
3. **Validate** the freshly-loaded config, and **bail on any error** — before
   touching a single running profile.
4. **Diff** against the currently-applied config to compute the minimal set of
   profile starts, stops, and restarts.
5. **Apply** per profile: a profile flipped to `enabled = false` is *stopped*
   (not restarted); changed profiles are torn down and re-spawned; unchanged
   profiles are left running.
6. **Swap** the cached config into the cell — **only on success**.

The load-bearing property is step 3 combined with step 6: if the new config
fails to parse or validate, the pipeline returns an error and the cell is left
untouched, so **the old config stays live**. A typo in a reloaded file can never
take your tunnels down. Reloads are triggered by `SIGHUP` (Unix), a debounced
file-watch, or the service manager, per `[runtime.reload].mode`; MCP-driven
edits go through `spt_config::mutate::Document` and then the identical pipeline.
Remote configs fetched over pinned HTTPS — optionally sealed in an `SPTENC1`
envelope and Ed25519-signed — flow through the same validate-before-swap gate.
See [Secrets](secrets.md#sealed-config-envelopes-sptenc1) and
[Trust](trust.md#tls-verification).

## Trust & security boundaries

`spt` verifies trust **before** authenticating, so no credential is ever sent to
an unverified peer. The trust and secret boundaries are where the fail-closed
principle is most visible.

- **Host-key trust (SSH2).** Every connection is checked against
  `[profiles.trust]` — a `known_hosts` file (with optional non-interactive TOFU
  via `accept_new`), an explicit SHA-256 SPKI pin set, or both combined. A
  mismatch is never TOFU-accepted; a missing trust table is a load-time error.
  Comparisons use constant-time equality. A `TrustFailed` result is a
  [terminal](#terminal-vs-retryable-failures) failure, not a retry. See
  [Trust](trust.md).
- **TLS trust (SSH3 and every HTTPS surface).** SSH3, the remote-config fetcher,
  OTLP/syslog-TLS/webhook sinks, and the status API all route their TLS through
  the single `spt_trust::PinnedTlsConnector`: system roots or a private CA
  bundle, WebPKI verification by default, optional leaf SPKI pinning, a
  chain-depth cap, and optional CRL enforcement. A self-signed allowance is only
  honoured alongside a non-empty pin set — a fully unauthenticated TLS
  connection is never constructed.
- **The secret boundary.** Credentials never appear as plaintext in config.
  Fields carry `secret://`, `env:`, or `file:` references resolved at runtime by
  `spt-secrets` (keychain → vault → env → file). Resolved bytes are wrapped in a
  `SecretBox<Zeroizing<…>>` that is zeroed on drop and excluded from `Debug`, and
  hot key material can use non-swappable `memfd_secret`/`mlock` allocations. The
  config schema uses a `RedactedString` newtype throughout. See
  [Secrets](secrets.md).
- **Sandboxed side effects.** The command event sink runs an allow-listed
  subprocess only when `allow_exec = true`, with arguments passed as an
  **argv array** (never a shell string), so there is no shell-injection surface.
  Rhai scripting hooks run in a sandbox. The MCP surface is read-only unless
  mutating tools are explicitly allow-listed.
- **Process hardening.** At startup `spt-bin` calls
  `spt_mem_hygiene::harden()` — dropping core dumps and debuggability, blocking
  new-privilege escalation, and disabling code-injection vectors on Windows — on
  a best-effort basis recorded in a `HardeningReport`. This layers on top of the
  shipped systemd, AppArmor, SELinux, and seccomp profiles.

The overarching threat model, the redaction tiers, the MAC profiles, the fuzz
harnesses, and the 2026 audit baseline are documented in [Security](security.md).

## Eventing & observability plane

The observability plane taps every layer without being on any layer's critical
path. Its spine is the **event bus** in `spt-events`: a
`tokio::sync::broadcast::Sender<Arc<Event>>` that fans each typed lifecycle
event to an arbitrary number of subscribers with no cloning of the payload.
Emitting is non-blocking and always succeeds even with zero subscribers; a
consumer that falls more than `ring_capacity` events behind receives a `Lagged`
signal rather than stalling the producer. An optional `EventRing` persists every
event to a daily JSONL file for replay.

Around the bus:

- The **dispatcher** subscribes to the bus and evaluates `[[events.bindings]]` —
  matching event kinds, applying `min_level`, throttle, and dedupe windows — then
  routes matches to the **sink registry**: `http`/`webhook_post`, `email`, `sms`,
  `push`/`webpush`, `command`, and `mcp_notify`. Failed deliveries spool to disk
  and retry with backoff. HTTPS sinks share the pinned-TLS connector.
- **Structured logging** (`spt-observability`) passes every formatted line
  through byte-level redaction before it reaches any of its concurrent
  destinations (stderr, rotating file, journald) or remote sinks (syslog
  UDP/TCP/TLS, HTTPS-JSONL, OTLP), with a hot-reloadable filter.
- **Metrics** are exported in Prometheus text format via atomic-rename to a
  state file, fed by the `spt-stats` counters, sliding windows, and EWMAs.
- The **`spt-stats` session and connection tables** (concurrent `dashmap`s) track
  every live session and forwarded connection; they back both the metrics and
  the `status.json` snapshot written atomically on every state change.
- **SNMP** (`spt-snmp`) serves an in-process SNMPv3 agent and sends traps on
  lifecycle events, and **`spt-status-api`** exposes a read-only HTTP/JSON view.

Full configuration and the CLI surface (`spt observe`, `spt event`, `spt stats`,
`spt status`, `spt log`) are in [Observability](observability.md).

## Runtime & threading model

`spt` runs on a single multi-threaded `tokio` runtime shaped by
`[runtime.threads]` (`orchestrator_threads`, `service_threads`,
`blocking_worker_threads`). The concurrency model is **task-per-unit-of-work**:

- one task per **profile** (the `ProfileSupervisor` loop);
- one task per accepted **forward connection** (the two-direction copy);
- background tasks for the dispatcher, event ring, metrics writer, watchdog
  pinger, DNS resolver, remote-config poller, and each side-channel server.

Because every unit is its own task, a slow or stuck connection cannot block
another, and per-connection backpressure stays local to that connection's task.
Blocking work (keychain access, some filesystem operations) is pushed to the
blocking pool rather than stalling an async worker.

All three front-ends — the **CLI** (`spt-cli`), the **TUI** (`spt-tui`), and the
OS **service** wrappers (`spt-service`) — drive the *same* orchestrator core.
`spt tunnel run` from a shell, an interactive `spt tui` session, and a
systemd-managed daemon differ only in how they launch and observe the core, not
in what the core does. Memory hygiene (`spt_mem_hygiene::harden()` at startup,
zeroizing secret buffers, optional RSS/cgroup monitoring under `[mem_hygiene]`)
applies uniformly across all three.

## Extensibility seams

`spt` is extended by implementing a narrow trait or adding a schema-driven
entry, not by patching the core. The main seams:

- **Transports** implement `spt_protocol::TunnelProtocol` (a stateless factory:
  `connect(endpoint, auth) -> Box<dyn TunnelSession>`, plus `capabilities()` and
  `name()`). The returned `TunnelSession` opens the various forward flavours;
  unsupported ones default to `UnsupportedPlatform` so a backend can implement
  the subset it supports and still compile. This is the seam `ssh2`, `ssh3`, and
  the obfuscation-wrapped variants all sit behind.
- **Auth methods** are protocol-agnostic types in `spt-auth`, validated
  independently of any transport, with provider backends (e.g. `spt-auth-sspi`)
  plugged in behind them.
- **Event sinks** are entries in the `spt-events` sink registry driven by
  `[[events.sinks]]`; a new delivery channel is a new sink kind, and bindings
  route to it by name with no core change.
- **Configuration** is a versioned TOML schema in `spt-config` with a migration
  path (`spt config migrate`); new capabilities generally mean a new `[table]`
  plus a validator rule, which is why nearly every feature in this book has both
  a config table and a matching CLI command.

The mechanics of building against these seams — trait signatures, testing
harnesses, and workspace conventions — live in the
[Development Guide](development.md).

## Runtime shape

Putting the layers in motion, a `spt tunnel run` proceeds as follows:

1. **Load & validate.** `spt-config` parses the TOML (or unseals an `SPTENC1`
   envelope), applies defaults, migrates old `version`s, and runs `validate`
   (errors block; warnings inform). The result is cached in the `ConfigCell`.
   See [Configuration Overview](configuration-overview.md).
2. **Acquire the state lock.** `spt-state` takes an exclusive `fs4` lock on
   `<state_dir>/spt.lock` (plus a PID file) so two supervisors cannot fight over
   the same profiles; a second instance exits with `StateLockFailed` (16).
3. **Harden & wire up.** `spt_mem_hygiene::harden()` runs; the event bus, sink
   registry, dispatcher, tracing stack, and metrics writer come up.
4. **Supervise.** For each enabled profile the orchestrator spawns a
   `ProfileSupervisor`: open a transport, authenticate, verify host trust, start
   the profile's forwards, and enter the lifecycle machine. Failures feed the
   reconnect / instability / failover machinery.
5. **Serve side channels.** Depending on config: the status API, SNMP agent, MCP
   server, DNS resolver, remote-config poller, and event/metrics exporters run
   alongside the tunnels.
6. **Reload in place.** SIGHUP / file-watch / MCP reloads run the shared
   validate-before-swap pipeline; an invalid config leaves the running one live.
7. **Shut down gracefully.** Signals raise the shutdown gate, drain forwards
   within `shutdown_grace`, flush sinks, release binds and the lock, and (under a
   service manager) honour the watchdog and restart policy.

## Configuration as the source of truth

Desired behavior comes from the config file, not runtime state. Runtime state
(the state directory, counters, session tables, `status.json`) exists for
observability and recovery, but the config file defines *what should be true*.
The supervisor continuously reconciles reality toward that declaration —
reconnecting, failing over, restarting changed profiles on reload — which is why
almost every capability in this book has a corresponding `[table]` in the
[Configuration Reference](configuration-reference.md) and a matching command in
the [CLI Reference](cli-reference.md).
