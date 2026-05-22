# Migrating from autossh

## Audience

You currently keep an SSH tunnel alive with [autossh](https://www.harding.motd.ca/autossh/),
typically as a wrapper around `ssh -N -L …` or `ssh -N -R …`. You probably
have one of:

- A shell snippet in `/etc/rc.local`, a `cron @reboot` line, or a systemd
  unit that spawns `autossh` and relies on it to relaunch on failure.
- A small fleet of similar wrappers — one per tunnel — that you update by
  hand when an endpoint moves.

You want the same "tunnel that just stays up" promise but with structured
config, structured logs, and first-class service integration.

## What autossh gives you

autossh is, in its own words, "a program to start a copy of ssh and
monitor it, restarting it as necessary should it die or stop passing
traffic" (see upstream docs). Its surface area is intentionally small:

- A monitor loop that watches one or two ports for round-trip traffic
  (`-M`), or — when run with `-M 0` — relies entirely on SSH-level
  `ServerAliveInterval` / `ServerAliveCountMax`.
- A "gate time" before the first restart counts as success
  (`AUTOSSH_GATETIME`, default 30s).
- Optional logging of restart events to a file (`AUTOSSH_LOGFILE`).
- Pass-through of every `ssh` flag — port forwards, identity files,
  jump hosts, `ControlMaster`, etc. all live in `ssh` arguments or
  `~/.ssh/config`.

Anything beyond that — failover, multi-tunnel orchestration, metrics,
reload — is not autossh's job. You bolt it on with shell or systemd.

## What spt gives you that's similar

| autossh concept                     | spt equivalent                                            |
|-------------------------------------|------------------------------------------------------------|
| Restart-on-exit loop                 | Supervisor with full-jitter exponential backoff (`[profiles.reconnect]`) |
| `-M 0` + `ServerAliveInterval`       | `[profiles.keepalive]` — `interval`, `timeout`, `max_missed` |
| `AUTOSSH_GATETIME`                  | `[profiles.reconnect].reset_after`                         |
| `-N` (no remote command)             | Default; `spt` never opens a remote shell                  |
| `-L 8080:internal:8080`              | `[[profiles.forwards]]` with `type = "local"`              |
| `-R 8080:127.0.0.1:80`               | `[[profiles.forwards]]` with `type = "remote"`             |
| `-i ~/.ssh/id_ed25519`               | `[profiles.auth] method = "public_key" identity_file = …`  |
| `-J jump.example`                    | `[[profiles.hops]]` chain                                  |
| `-o StrictHostKeyChecking=yes`       | `[profiles.trust] mode = "known_hosts" strict = true`      |
| `AUTOSSH_LOGFILE=/var/log/auto.log`  | `[logging] file = …` plus structured events                |
| `AUTOSSH_PIDFILE`                    | `<state_dir>/spt.pid` (managed by the file lock)            |

### Environment variable mapping

The full set of autossh env vars and their `spt` equivalents:

| autossh env var         | Effect                                          | spt equivalent                                                |
|-------------------------|--------------------------------------------------|----------------------------------------------------------------|
| `AUTOSSH_GATETIME`      | Seconds before first run "counts" (default 30) | `[profiles.reconnect].reset_after`                             |
| `AUTOSSH_POLL`          | Seconds between port-monitor probes              | `[profiles.keepalive].interval`                                |
| `AUTOSSH_FIRST_POLL`    | Seconds before first probe                       | `[profiles.keepalive].interval` (single value, no separate first) |
| `AUTOSSH_PORT`          | Echo monitor port (paired with `-M`)            | Not needed — keepalive uses SSH global request `keepalive@openssh.com` |
| `AUTOSSH_MAXSTART`      | Max restarts before giving up (-1 = forever)    | `[profiles.instability].action` + `[profiles.reconnect].max_attempts` |
| `AUTOSSH_MAXLIFETIME`   | Seconds before forced exit                      | No direct equivalent; use service-manager timer or `spt` reload |
| `AUTOSSH_LOGFILE`       | Path for autossh's own log                      | `[logging] file = …`                                           |
| `AUTOSSH_LOGLEVEL`      | 1–7 syslog level                                | `[logging] level = "debug" \| "info" \| …`                     |
| `AUTOSSH_DEBUG`         | Verbose stderr                                  | `[logging] level = "debug"` plus `format = "json"`             |
| `AUTOSSH_PATH`          | Path to ssh binary                              | Not applicable — `spt` is the SSH client                       |
| `AUTOSSH_PIDFILE`       | Where to write pid                              | `<state_dir>/spt.pid` (always)                                 |
| `AUTOSSH_NTSERVICE`     | Cygwin service mode                             | `spt service install` on Windows                               |
| `AUTOSSH_MESSAGE`       | Banner string injected into log                 | `[logging] tags = …` (if defined for your build)               |

## Concrete config translation

### Single local forward

The classic autossh invocation:

```bash
# Old: keep a postgres tunnel alive
AUTOSSH_GATETIME=0 \
AUTOSSH_PORT=20000 \
AUTOSSH_LOGFILE=/var/log/autossh-db.log \
  autossh -M 0 -N \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    -i /etc/ssh/tunnel_ed25519 \
    -L 5432:db.internal:5432 \
    tunnel@bastion.example.com
```

becomes:

```toml
# spt: /etc/spt/spt.toml
version = 1

[runtime]
state_dir = "/var/lib/spt"

[logging]
level = "info"
format = "compact"
destinations = ["file"]
file = "/var/log/spt/spt.log"

[[profiles]]
name = "db-bastion"
enabled = true
protocol = "ssh2"
host = "bastion.example.com"
port = 22
user = "tunnel"

[profiles.auth]
method = "public_key"
identity_file = "/etc/ssh/tunnel_ed25519"

[profiles.trust]
mode = "known_hosts"
strict = true

[profiles.keepalive]
interval = "30s"
timeout = "10s"
max_missed = 3

[profiles.reconnect]
initial_delay = "1s"
max_delay = "60s"
jitter = "20%"
reset_after = "5m"

[[profiles.forwards]]
name = "db"
type = "local"
transport = "tcp"
bind = "127.0.0.1:5432"
target = "db.internal:5432"
target_resolve = "remote"
required = true
```

`required = true` corresponds to autossh's
`ExitOnForwardFailure=yes` — if the listener cannot bind, the profile
moves to `CooldownAfterFailure` rather than running degraded.

### Reverse forward

```bash
# Old: expose a local webhook receiver via the edge box.
autossh -M 0 -N -R 8080:127.0.0.1:8080 edge@edge.example.com
```

```toml
[[profiles]]
name = "edge-callback"
protocol = "ssh2"
host = "edge.example.com"
user = "edge"

[profiles.auth]
method = "agent"

[profiles.trust]
mode = "known_hosts"
strict = true

[[profiles.forwards]]
name = "webhook"
type = "remote"
transport = "tcp"
bind = "127.0.0.1:8080"      # remote listen address (interpreted on the server)
target = "127.0.0.1:8080"    # local target on this host
target_resolve = "local"
required = true
```

Note the inversion versus autossh's `-R local:remote:port` syntax — in
the spt schema, `bind` is always "where the listener lives" and `target`
is "what we forward to". `target_resolve` makes that explicit.

### Multi-hop chain

`autossh` users typically rely on `~/.ssh/config`'s `ProxyJump`:

```ssh-config
Host inner
    HostName inner.internal
    ProxyJump jump.example.com
```

```bash
autossh -M 0 -N -L 8443:inner:443 inner
```

The spt equivalent declares hops directly in the profile (compare
[`examples/jump-host.toml`](../../examples/jump-host.toml)):

```toml
[[profiles]]
name = "inner-via-jump"
protocol = "ssh2"
host = "jump.example.com"
user = "ops"

[profiles.auth]
method = "agent"

[profiles.trust]
mode = "known_hosts"
strict = true

[[profiles.hops]]
name = "inner"
protocol = "ssh2"
host = "inner.internal"
port = 22
user = "ops"
target_resolve = "previous-hop"

[[profiles.forwards]]
name = "https"
type = "local"
transport = "tcp"
bind = "127.0.0.1:8443"
target = "127.0.0.1:443"
target_resolve = "remote"
```

## What changes for the operator

### Service management

You probably have something like:

```ini
# /etc/systemd/system/autossh-db.service
[Service]
Environment=AUTOSSH_GATETIME=0
ExecStart=/usr/bin/autossh -M 0 -N -L 5432:db.internal:5432 tunnel@bastion
Restart=always
```

Replace it with:

```sh
spt service install --config /etc/spt/spt.toml --system
systemctl enable --now spt.service
```

`spt` writes the unit, sets `Restart=on-failure` with appropriate
backoff, wires `ExecReload` to `kill -HUP`, and uses
`StateDirectory=spt` so the file lock is owned by the service.

### Log format

autossh writes free-form text to `AUTOSSH_LOGFILE`. `spt` defaults to a
compact key=value line format on stderr (suitable for `journalctl`) and
JSON on disk. Set `[logging] format = "json"` to force structured logs
everywhere. Each reconnect attempt emits a `connection.attempt` event;
each successful handshake emits `profile.ready`. See
[Events](../events.md) for the full list.

### Signal handling

| Signal      | autossh                                   | spt                                                       |
|-------------|-------------------------------------------|------------------------------------------------------------|
| `SIGINT`    | Forwards to ssh, exits when ssh exits     | Graceful shutdown with `[runtime].shutdown_grace`           |
| `SIGTERM`   | Same                                      | Graceful shutdown                                           |
| `SIGHUP`    | Forwarded to ssh (typically ignored)      | Reload config (when `[runtime.reload].mode = "signal"`)     |
| `SIGUSR1`   | Force ssh restart                         | Reserved — see CLI Reference                                |

### State directory

autossh leaves a pid file in `/var/run` (or wherever you point
`AUTOSSH_PIDFILE`). `spt` keeps a structured state directory:

```
/var/lib/spt/
├── spt.pid           # supervisor pid + fs4 lock
├── status.json       # snapshot for `spt tunnel status`
├── events.log        # ring of recent events (when enabled)
└── vault.spt         # encrypted secret vault (optional)
```

## What spt does that autossh doesn't

- **Multiple tunnels in one supervisor.** Add `[[profiles]]` blocks
  rather than spawning N autossh processes.
- **Failover.** Declare `[[profiles.endpoints]]` with priority and
  weight; the supervisor health-checks them and switches automatically.
  See [Profiles](../profiles.md).
- **Built-in DNS resolver.** Name forwarded services from local
  clients without editing `/etc/hosts`. See [DNS](../dns.md).
- **Structured observability.** Prometheus metrics, OTLP traces,
  syslog-TLS, journald, and SNMPv3 traps with the project
  [SPT-MIB](../../mibs/SPT-MIB.txt).
- **Secret resolution.** Identity passphrases, bearer tokens, and
  passwords resolve through `secret://`, `env:`, or `file://`
  references — never inline plaintext. See [Secrets](../secrets.md).
- **Hot reload.** Edit the TOML and `systemctl reload spt`; profiles
  with unchanged settings keep their sessions.
- **MCP server (read-only by default).** Inspect status from an
  agent-aware UI without giving it shell access. See [MCP](../mcp.md).
- **Diagnostic bundles.** `spt diagnose` produces a redacted tarball
  of state for support tickets.

## What autossh does that spt doesn't

- **Email-on-failure.** autossh has no built-in mailer either, but a
  common pattern is to wrap it in a script that emails on exit. With
  `spt`, wire `profile.degraded` events into your existing alerting
  (PagerDuty, Slack, OpsGenie) via the events sink. There is no
  built-in SMTP sender.
- **Whole-of-`ssh` flag passthrough.** autossh inherits the entire
  OpenSSH option surface. `spt` re-implements the subset its schema
  knows about. If you depend on an obscure `Match` rule, an
  `IPQoS` value, or a custom KEX algorithm, check
  [Configuration](../configuration.md) first; see upstream docs for
  options not covered.
- **`-M` traffic monitor on a dedicated echo port.** autossh's port
  pair (e.g. 20000/20001) round-trips bytes through the tunnel itself.
  `spt` uses SSH `keepalive@openssh.com` global requests instead — a
  protocol-level liveness check rather than a payload echo.

## Side-by-side runtime comparison

| Dimension                       | autossh                                  | spt                                                |
|---------------------------------|------------------------------------------|----------------------------------------------------|
| Cold-start to first byte        | ~1× ssh handshake                        | ~1× ssh handshake (pure-Rust `russh` backend)      |
| Resident memory (single tunnel) | ~3–5 MiB (autossh + ssh)                 | ~6–10 MiB (one supervisor for N profiles)          |
| Reconnect latency after drop    | `ServerAliveInterval × ServerAliveCountMax` (often 30s × 3 = 90s) | `keepalive.interval × max_missed`, then `[reconnect].initial_delay` (typically <1s after detection) |
| Reconnect backoff               | None — immediate restart                 | Full-jitter exponential, capped at `max_delay`     |
| Concurrent tunnel cost          | One `autossh` + one `ssh` per tunnel     | Shared supervisor; multiplexed channels per session|

## Step-by-step migration recipe

1. **Install `spt`** alongside autossh — they don't conflict.

   ```sh
   sudo apt install ./spt_<version>_amd64.deb     # or rpm/pkg/msi
   spt --version
   ```

2. **Translate one tunnel.** Pick the least critical autossh wrapper.
   Write its config to `/etc/spt/spt.toml` using the table above as a
   guide. For now, point its bind to a *different* local port than
   the autossh one so they coexist (e.g. `127.0.0.1:5433` instead of
   `5432`).

3. **Validate.**

   ```sh
   spt config validate --config /etc/spt/spt.toml --strict
   ```

   Fix any reported errors. The validator reports the exact field path
   on failure.

4. **Run in the foreground.**

   ```sh
   spt tunnel run --foreground --config /etc/spt/spt.toml
   ```

   In another shell:

   ```sh
   curl http://127.0.0.1:5433/         # or psql -h 127.0.0.1 -p 5433
   spt tunnel status --config /etc/spt/spt.toml
   ```

5. **Force reconnects.** Bounce the upstream session (kill the SSH
   process on the bastion, drop the network for 30s, suspend the
   laptop for a minute). Watch `spt tunnel status` and confirm the
   profile returns to `Ready` without intervention.

6. **Install as a service.**

   ```sh
   sudo spt service install --config /etc/spt/spt.toml --system
   sudo systemctl enable --now spt.service
   sudo systemctl status spt.service
   ```

7. **Cut over.** Swap the bind back to the original port (`5432`),
   stop and disable the autossh unit, reload `spt`:

   ```sh
   sudo systemctl disable --now autossh-db.service
   sudo systemctl reload spt.service
   ```

8. **Monitor for a release window.** Track `connection.failed`
   events and `spt_profile_state` Prometheus gauge. After a week of
   stable operation, remove the autossh unit file.

9. **Repeat.** Add the next tunnel as another `[[profiles]]` block in
   the same `spt.toml` — there is no need for one supervisor per
   tunnel.

## See also

- [Configuration](../configuration.md)
- [Profiles](../profiles.md) — failover, instability detection
- [Forwards](../forwards.md) — local, remote, UDP
- [Service Integration](../service-integration.md)
- [Troubleshooting](../troubleshooting.md)
