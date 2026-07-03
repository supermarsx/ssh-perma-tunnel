# Architecture Overview

`spt` is a Cargo **workspace** of focused crates. A thin binary (`spt-bin`)
wires a Clap CLI (`spt-cli`) on top of a supervisor that drives protocol
backends through a shared adapter trait. This chapter maps the subsystems so
the rest of the book can refer to them by name.

## The spt ↔ spt model

`spt` is a **client**. It speaks to an existing SSH2 or SSH3 server. In the
SSH2 case that server is any RFC 4253/4254 implementation (OpenSSH, dropbear,
…). In the SSH3 case it is the `francoismichel/ssh3` reference server — or,
for spt-to-spt interop, another `spt` running `spt ssh3-serve`. There is no
general server role: forward *listeners* live on the client side (local and
dynamic forwards) or are requested from the server (remote/reverse forwards via
`tcpip-forward`).

```
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

## Subsystem map (crate by crate)

**Core & protocol**

| Crate | Role |
|-------|------|
| `spt-bin` | The `spt` binary entry point; wires everything together. |
| `spt-core` | Core types, the 38 stable exit codes, error taxonomy, parsers. |
| `spt-protocol` | The tunnel adapter traits every backend implements (SSH2, SSH3, …). |
| `spt-cli` | The Clap-derived command tree — one module per command group. |
| `spt-config` | TOML schema, validation, rendering, diffing, migration. |
| `spt-state` | Runtime state directory, single-supervisor locks, atomic writes. |

**Transports** — see [Transports](transports.md)

| Crate | Role |
|-------|------|
| `spt-ssh2` | SSH2 backend on the pure-Rust `russh` crate. |
| `spt-ssh3` | SSH3 backend on QUIC + rustls + HTTP/3 (RTH3). |
| `spt-obfs` | Pluggable obfuscation transports (obfs4, meek, WebSocket, Shadowsocks). |
| `spt-net` | Address parsing, interface enumeration, bind-policy, socket options. |

**Forwarding & file transfer** — see [Forwarding](forwarding.md)

| Crate | Role |
|-------|------|
| `spt-forward` | Forwarding building blocks + the supervisor-facing `ForwardRunner`. |
| `spt-sftp` | SFTP client (one-shot ops + recursive transfer + mount). |
| `spt-ftp-translator` | Passive-only FTP→SFTP translator with AUTH TLS upgrade. |

**Resilience** — see [Resilience & Self-Healing](resilience.md)

| Crate | Role |
|-------|------|
| `spt-supervisor` | Profile state machine; reconnect / instability / failover. |
| `spt-chaos-proxy` | Fault-injecting TCP proxy used by the reconnect test suite. |

**Auth, trust & secrets** — see [Authentication](authentication.md), [Trust](trust.md), [Secrets](secrets.md)

| Crate | Role |
|-------|------|
| `spt-auth` | Protocol-agnostic auth method types + validation. |
| `spt-auth-sspi` | GSSAPI / Kerberos / SSPI / NTLM provider backends. |
| `spt-key` | Key generation, fingerprinting, OpenSSH user-certificate handling. |
| `spt-trust` | `known_hosts`, SHA-256 host pinning, CRL, TOFU. |
| `spt-secrets` | Secret resolver, encrypted vault, OS keychain. |
| `spt-config-crypt` | Sealed-config envelope (`SPTENC1`). |
| `spt-mem-hygiene` | Best-effort process memory hardening (mlock, zeroize). |

**Observability & events** — see [Observability](observability.md)

| Crate | Role |
|-------|------|
| `spt-observability` | Tracing stack, redaction, file rotation, metrics. |
| `spt-events` | Event bus, binding evaluator, notification sinks. |
| `spt-stats` | Rolling counters, sliding windows, session/connection tables. |
| `spt-snmp` | SNMPv3 agent + traps (SPT-MIB). |
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
| `spt-remote-config` | Remote config fetch with HTTPS pinning. |
| `spt-updater` | Embedded, signature-verifying auto-updater. |
| `spt-service` | systemd / launchd / SCM / OpenRC / SysV / Task Scheduler. |
| `spt-tui` | Terminal-UI profile configurator. |

## Runtime shape

1. **Load & validate.** `spt-config` parses the TOML, applies defaults,
   migrates old `version`s, and runs `validate` (errors block; warnings inform).
   See [Configuration Overview](configuration-overview.md).
2. **Acquire the state lock.** `spt-state` takes a single-supervisor lock on the
   state directory so two supervisors can't fight over the same profiles.
3. **Supervise.** For each enabled profile the supervisor opens a transport,
   authenticates, verifies host trust, then starts the profile's forwards.
   Failures feed the reconnect/instability/failover machine.
4. **Serve side channels.** Depending on config: the status API, SNMP agent,
   MCP server, DNS resolver, event sinks, and metrics exporters come up
   alongside the tunnels.
5. **Shut down gracefully.** Signals drain forwards, flush sinks, release the
   lock, and (under a service manager) honor the watchdog and restart policy.

## Configuration is the source of truth

Desired behavior comes from the config file, not runtime state. Runtime state
(the state directory, counters, session tables) exists for observability and
recovery, but the config file defines *what should be true*. This is why almost
every capability in this book has a corresponding `[table]` in the
[Configuration Reference](configuration-reference.md) and a matching command in
the [CLI Reference](cli-reference.md).
