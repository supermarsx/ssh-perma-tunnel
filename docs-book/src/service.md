# Service Management

`spt` integrates with every major platform service manager so tunnels start at
boot, restart on failure, and participate in the host's normal operational
tooling. This chapter covers installation, control, the `[service]` config
table, and per-backend notes.

**One service per config file.** The spec enforces this boundary: profile
filters are runtime-only (pass `--profile name` as an extra arg) and must not
be expressed as separate service units.

## Supported backends

| Backend | Platform | Scope |
|---------|----------|-------|
| **systemd** | Linux | system (`--system`) and per-user (`--user`) |
| **launchd** | macOS | LaunchDaemon (`--system`) and LaunchAgent (`--user`) |
| **Windows SCM** | Windows | system only |
| **OpenRC** | Linux (Alpine, Gentoo, …) | system |
| **SysV init** | Linux (older distros) | system |
| **Task Scheduler** | Windows | system and current-user (`--user`) |

OpenRC and SysV templates live under `packaging/openrc/` and `packaging/sysv/`
respectively. They are shipped as fallbacks for systems without systemd and are
not exercised in CI.

## Installing the service

```sh
# Linux / macOS — system scope (requires admin)
sudo spt service install --config /etc/spt/spt.toml --system

# Linux — per-user scope (no sudo needed)
spt service install --config ~/.config/spt/spt.toml --user

# Windows — elevated PowerShell
spt service install --config "C:\ProgramData\spt\spt.toml" --system
```

`spt service install` auto-detects the running service manager and writes
the appropriate unit/plist/registry entry. The installed service name is
derived from the `[service].name` config field (default: `spt`).

### Rendering without installing

To inspect what would be written without touching the OS:

```sh
# Print the rendered systemd unit
spt service render --config /etc/spt/spt.toml --system --format unit

# Print the rendered launchd plist
spt service render --config /etc/spt/spt.toml --system --format plist
```

## Controlling the service

```sh
spt service start    --config /etc/spt/spt.toml --system
spt service stop     --config /etc/spt/spt.toml --system
spt service status   --config /etc/spt/spt.toml --system
spt service status   --config /etc/spt/spt.toml --system --json
spt service uninstall --config /etc/spt/spt.toml --system
```

See [CLI Reference](cli-reference.md) for the full flag set and exit codes.

## The `[service]` config table

Adding a `[service]` section to your config shapes what `spt service install`
generates. Every field is optional; omitting the entire section preserves the
previous CLI-flag-driven defaults.

```toml
[service]
# Human-readable description embedded in the unit / plist / SCM entry.
description = "Production bastion tunnel"

# User and group the service runs as (system scope only).
# Omit for per-user installs; the manager runs under your own account.
user  = "spt"
group = "spt"

# Extra environment variables baked into the generated unit.
# [service.env]
# SPT_LOG_LEVEL = "warn"

# Restart behaviour: "always" | "on-failure" | "never".
# Default: "on-failure".
restart_policy = "on-failure"

# Enable systemd Type=notify + sd_notify (Linux only).
# The packaged static unit already sets this; the CLI installer uses
# "Type=simple" by default (sd_notify calls are a clean no-op there).
sd_notify = true

# systemd WatchdogSec= interval in seconds. When set, systemd exports
# WATCHDOG_USEC so spt's internal watchdog pinger sends WATCHDOG=1 at
# half the interval. Omit to disable watchdog supervision entirely.
# Minimum meaningful value is 10 (a value of 0 is a validation error).
watchdog_sec = 30

# Log paths for backends that do not have journaling (launchd, SysV).
# stdout = "/var/log/spt/spt.log"
# stderr = "/var/log/spt/spt-error.log"
```

Field semantics are mapped onto the native concept for each backend:

| Field | systemd | launchd | SCM | OpenRC / SysV |
|-------|---------|---------|-----|---------------|
| `restart_policy` | `Restart=` | `KeepAlive` | recovery action | `respawn` / nothing |
| `sd_notify` | `Type=notify` | n/a | n/a | n/a |
| `watchdog_sec` | `WatchdogSec=` | n/a (ignored) | n/a (ignored) | n/a (ignored) |
| `stdout` / `stderr` | n/a (journald) | `StandardOutPath` / `StandardErrorPath` | n/a | redirect in init script |
| `user` / `group` | `User=` / `Group=` | `UserName` | `LocalSystem` or named | script `su` |

## Per-backend notes

### systemd (Linux)

The packaged unit file at `packaging/systemd/spt.service` is `Type=notify`
with `NotifyAccess=main`. The daemon sends `READY=1` once the orchestrator
is fully up and `STOPPING=1` at the start of graceful shutdown, using a plain
`UnixDatagram` writer — **no `libsystemd` C dependency**. When
`$NOTIFY_SOCKET` is unset the calls are a clean no-op.

File locations:

| Scope | Unit path |
|-------|-----------|
| system | `/lib/systemd/system/spt.service` (from deb/rpm) |
| system (CLI install) | `/etc/systemd/system/spt-<config-stem>.service` |
| user | `~/.config/systemd/user/spt-<config-stem>.service` |

The packaged unit applies the following sandboxing directives:
`NoNewPrivileges=true`, `ProtectSystem=strict`, `PrivateTmp=true`. The CLI
installer generates a simpler unit without `Type=notify` (the `sd_notify`
flag defaults to off on that path, so the daemon's notify calls no-op).

Enable and start:

```sh
sudo systemctl enable --now spt.service
```

Reload config without restarting (SIGHUP):

```sh
sudo systemctl reload spt.service
```

### launchd (macOS)

The packaged plist is at `packaging/launchd/spt.plist.tmpl`. The CLI
installer renders it from the `[service]` table.

| Scope | Plist path |
|-------|-----------|
| system (LaunchDaemon) | `/Library/LaunchDaemons/com.mariana.spt.plist` |
| user (LaunchAgent) | `~/Library/LaunchAgents/com.mariana.spt-<stem>.plist` |

Load / unload manually:

```sh
sudo launchctl load   -w /Library/LaunchDaemons/com.mariana.spt.plist
sudo launchctl unload -w /Library/LaunchDaemons/com.mariana.spt.plist
```

Send a reload signal (SIGHUP):

```sh
sudo launchctl kill -HUP system/com.mariana.spt
```

### Windows SCM

`spt service install --system` registers the service with the Service Control
Manager via the `windows-service` crate. Start type is `Automatic`; recovery
is configured to restart on failure.

```powershell
Start-Service spt
Stop-Service  spt
Get-Service   spt
```

Reload is triggered by the `ParamChange` service control event (the "Pause"
action in the SCM UI). `spt` handles it as a SIGHUP-equivalent.

### Task Scheduler (Windows)

`spt service install --user` on Windows creates a Task Scheduler entry for
the current user. This is the per-user alternative to the SCM system service.

## Reload semantics

| Backend | How to trigger a reload |
|---------|------------------------|
| systemd | `systemctl reload spt.service` (sends SIGHUP) |
| launchd | `launchctl kill -HUP system/com.mariana.spt` |
| SCM | Service "Pause" control event (`ParamChange` flag) |
| OpenRC | `rc-service spt reload` |
| SysV | `service spt reload` |

On reload `spt` re-reads its config file, applies any changes to the live
profile set, and reconnects profiles whose config changed.

## The supervisor watchdog

When `[service].watchdog_sec` is set and the backend is systemd, `spt`
spawns an internal watchdog pinger that sends `WATCHDOG=1` to
`$NOTIFY_SOCKET` at half the configured interval. If `spt` deadlocks or
stops responding, systemd will kill and restart it after `watchdog_sec`
seconds of silence.

This is distinct from `spt`'s own tunnel-health supervisor (which monitors
individual forwards and triggers reconnects); it is an OS-level liveness
check that guards against the process itself hanging. See
[Resilience & Self-Healing](resilience.md) for the internal reconnect logic.

## Checking service status

```sh
# Human-readable
spt service status --config /etc/spt/spt.toml --system

# Machine-readable JSON
spt service status --config /etc/spt/spt.toml --system --json
```

The JSON output includes the coarse `state` field (`running`, `stopped`,
`failed`, `not_installed`, or `unknown`), PID when available, last exit code,
start timestamp, and restart count. Fields are best-effort: each backend fills
what its underlying CLI exposes.

## Default config file paths per OS

`spt service install` writes a unit that passes `--config <path>` to `spt`.
When no explicit path is given, the service installer defaults to:

| OS | Default config path |
|----|---------------------|
| Linux | `/etc/spt/spt.toml` |
| macOS | `/usr/local/etc/spt/spt.toml` |
| Windows | `%PROGRAMDATA%\spt\spt.toml` |

These paths are also where the deb/rpm/msi/pkg installers seed the config.
