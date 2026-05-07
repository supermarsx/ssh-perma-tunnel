# Migration Guides

These guides help operators move existing tunneling setups onto `spt`. Pick
the guide that matches the tool you have today; each one walks through
feature mapping, concrete config translation, and a step-by-step swap
recipe that lets you run `spt` alongside the old tool until you trust it.

## Pick your starting point

| Coming from                                     | When to use this guide                                                                                  |
|-------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| [autossh](from-autossh.md)                      | You wrap `ssh -N -L … -R …` in `autossh -M 0` (or a systemd unit) for "ssh + auto-restart".             |
| [sshuttle](from-sshuttle.md)                    | You use `sshuttle 0/0` or specific subnets for transparent VPN-style routing over SSH.                   |
| [OpenSSH `~/.ssh/config`](from-openssh-config.md) | You drive long-lived tunnels via `ServerAliveInterval`, `ControlMaster`, `LocalForward`/`RemoteForward`. |
| [systemd-resolved](from-systemd-resolved.md)    | You combine systemd-resolved split-DNS with an SSH tunnel to reach internal names.                       |
| [corkscrew](from-corkscrew.md)                  | You tunnel SSH through an HTTP `CONNECT` proxy via corkscrew/proxytunnel.                                |

## What "migration" means here

`spt` is client-only. It connects to the same SSH/SSH3 servers your
existing tools talk to (OpenSSH, dropbear, the
`francoismichel/ssh3` reference implementation), so migration never
requires changing the remote side. What changes is:

- **The local config format** — TOML instead of `~/.ssh/config`,
  shell environment variables, or iptables rules.
- **The supervisor** — `spt` owns reconnect, instability detection,
  failover, and signalling instead of a wrapper script.
- **Observability** — structured events, Prometheus, OTLP, SNMPv3
  replace a tail on `journalctl` or `/var/log/auth.log`.

## Common preparation

Before following any specific guide:

1. Install `spt` (see [Installation](../installation.md)).
2. Pick a state directory you control (`/var/lib/spt` for system
   installs, `~/.local/state/spt` for user installs).
3. Decide how secrets will be resolved
   ([Secrets](../secrets.md)) — keychain, vault, env, or file.
4. Create an empty config and run
   `spt config validate --config /path/to/spt.toml`. The validator
   should report `ok: <path> (0 profile(s))` before you start
   adding profiles.

## After migration

- [Service Integration](../service-integration.md) — install `spt` as a
  long-running service on systemd, launchd, SCM, OpenRC, SysV, or Task
  Scheduler.
- [Observability](../observability.md) — wire structured events into the
  monitoring you already have.
- [Troubleshooting](../troubleshooting.md) — exit-code map and common
  failure scenarios.
