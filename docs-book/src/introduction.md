# Introduction

**`spt`** (`ssh-perma-tunnel`) is a single Rust command-line tool that
establishes and maintains **permanent SSH tunnels** — local, remote (reverse),
and dynamic port forwards that survive network drops, host restarts, service
restarts, DNS changes, and normal operational drift.

It is built for operators and developers who need a forward to *stay up* for
weeks or months without babysitting: exposing a remote SMTP relay locally,
reaching a private database or admin panel through a bastion, holding a reverse
tunnel open for controlled inbound access, or bridging UDP services over SSH3.

```sh
# Validate, then run a tunnel in the foreground.
spt config validate --config examples/minimal.toml
spt tunnel run --foreground --config examples/minimal.toml
```

## `spt` is client-only

> `spt` connects to **existing** SSH / SSH3 servers (OpenSSH, dropbear, the
> `francoismichel/ssh3` reference implementation, etc.) and maintains forwards
> *through* them. There is **no built-in server role** — bring your own remote.

This is a deliberate scope boundary. `spt` is not a general SSH client
replacement (no interactive shell, no `scp`), not a VPN (no TUN/TAP, no routes),
and not a proxy for anything outside SSH2/SSH3. What it *is*: a hardened,
config-driven, self-healing forwarding supervisor with deep operational
tooling.

## What makes it different

- **Permanence first.** A supervisor state machine reconnects across drops,
  restarts, and DNS changes with backoff, jitter, instability detection, and
  endpoint failover. See [Resilience & Self-Healing](resilience.md).
- **Two transports.** A production SSH2 backend on the pure-Rust `russh` stack,
  plus an experimental **SSH3** backend (RTH3 — Remote-Terminal-over-HTTP/3, per
  the `francoismichel/ssh3` reference) running over QUIC/HTTP3. Pluggable
  **obfuscation** (obfs4, meek, WebSocket, Shadowsocks) layers underneath. See
  [Transports](transports.md).
- **Every forward kind.** Local / remote (reverse) TCP, UDP (`tcp-framed` /
  `uds-bridge`), UNIX-domain sockets, dynamic SOCKS4/4A/5 + HTTP CONNECT with
  target ACLs, and multi-hop jump chains (`-J user@host,...`) with per-hop auth
  and trust. See [Forwarding](forwarding.md).
- **Secrets never in plaintext.** References resolve through pluggable backends
  (`env` / `file` / `vault` / OS keychain) via `secret://ns/name`; an encrypted
  vault (AES-256-GCM + Argon2id) and sealed config (`SPTENC1`) protect data at
  rest. See [Secrets & Vault](secrets.md).
- **Deep observability.** Rotating file logs, journald, syslog-TLS,
  HTTPS-JSONL, OTLP, Prometheus, an SNMPv3 agent + traps, an event bus with
  templated sinks, and three-tier redaction on every output. See
  [Observability](observability.md).
- **Operable everywhere.** Service integration for systemd / launchd /
  Windows SCM / OpenRC / SysV / Task Scheduler, a hardened Docker image, an
  embedded MCP control server, a transparent DNS resolver, firewall
  application, Rhai scripting hooks, and a signature-verifying auto-updater.

## How to read this book

- New here? Start with the [Architecture Overview](architecture.md), then
  [Installation](installation.md) and [Quick Start](quick-start.md).
- Writing config? The [Configuration Overview](configuration-overview.md)
  explains structure and precedence; the
  [Configuration Reference](configuration-reference.md) documents every table
  and field.
- Driving the tool? The [CLI Overview](cli.md) and
  [CLI Reference](cli-reference.md) cover every command group.
- The remaining chapters are subsystem deep-dives cross-linked throughout.

## Versioning & status

`spt` ships on a **rolling `YY.N` release** (this book documents **26.46**); the
workspace `Cargo.toml` encodes it as `0.YY.N` for Cargo's SemVer parser.
Releases cut automatically on green pushes to `main`.

Throughout this book, features that are **validate-warned but not yet fully
wired** are called out explicitly — the documentation aims to be honest about
what is enforced versus what is accepted-and-parsed. When in doubt, the code in
`crates/spt-config/src/schema.rs` and `crates/spt-config/src/validate.rs` is the
source of truth.
