# ssh-perma-tunnel (`spt`)

[![CI](https://github.com/supermarsx/ssh-perma-tunnel/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/supermarsx/ssh-perma-tunnel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](license.md)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-dea584?logo=rust&logoColor=white&style=flat-square)](rust-toolchain.toml)
[![Release](https://img.shields.io/github/v/release/supermarsx/ssh-perma-tunnel?sort=semver&style=flat-square)](https://github.com/supermarsx/ssh-perma-tunnel/releases)

A single Rust command-line tool, `spt`, that establishes and maintains
**permanent SSH tunnels** — local and reverse port forwards that survive
network drops, host restarts, service restarts, DNS changes, and normal
operational drift.

> **`spt` is client-only.** It connects to existing SSH/SSH3 servers (OpenSSH,
> dropbear, the francoismichel/ssh3 reference, etc.) and maintains forwards
> through them. There is no built-in server role; bring your own remote.

## Features

**Transport & forwarding**
- SSH2 over the pure-Rust `russh` backend; experimental SSH3 (QUIC + HTTP/3).
- Local, remote, and dynamic (SOCKS4/4A/5, HTTP CONNECT) forwards; UDP
  (`tcp-framed` / `uds-bridge`); server-side UNIX-socket forwarding; multi-hop
  jump chains (`-J user@host[,...]`) over native russh channels.

**File transfer**
- Full SFTP suite (`cat`, `tail`, `chmod`, `symlink`, `readlink`, `realpath`,
  recursive `put`/`get` with `--resume`, BPS cap, SHA-256 verification).
- SFTP-as-drive mount (Linux FUSE, Windows Dokany2, macOS sshfs + macFUSE).
- FTP→SFTP translator with RFC 4217 AUTH TLS in-place upgrade.

**Authentication**
- Public keys: Ed25519, ECDSA P-256/384/521, RSA-SHA2-256/512 (legacy
  SHA-1 `ssh-rsa` rejected by default).
- SSPI / GSSAPI / Kerberos / NTLM (Windows `sspi`, Unix vendored `libgssapi`).
- TOTP / 2FA keyboard-interactive (RFC 6238).

**Stealth & resilience**
- Auto-reconnect across drops, restarts, and DNS changes.
- Obfuscation transports: obfs4, meek-http (domain-fronting),
  ssh-over-websocket, ssh-over-shadowsocks.

**Platform integration**
- Service integration: systemd, launchd, Windows SCM, OpenRC, SysV,
  Task Scheduler.
- Encrypted secret vault (AES-256-GCM + Argon2id) + OS keychain;
  references resolve via `secret://ns/name`.
- Built-in transparent DNS resolver (split-horizon, SRV synthesis).
- Sandboxed `rhai` scripting hooks; `--portable` mode (no OS install or
  user-directory/keychain side-effects).

**Operations**
- Observability: rotating file logs, journald, syslog-TLS, HTTPS-JSONL, OTLP,
  Prometheus, and an SNMPv3 agent + traps ([SPT-MIB](mibs/SPT-MIB.txt)).
- Embedded Model Context Protocol (MCP) server — read-only by default, never
  returns plaintext secrets.
- TUI profile configurator (`spt profile configure --tui`); diagnostics with
  redacted bundles; benchmarking driver framework.

## Install

### From a release artifact

| Platform | Artifact                                |
|----------|-----------------------------------------|
| Linux    | `spt_<version>_amd64.deb`,  `*.rpm`     |
| macOS    | `spt-<version>.pkg`                     |
| Windows  | `spt-<version>.msi`                     |
| Docker   | `ghcr.io/supermarsx/spt:<version>` (linux/amd64, linux/arm64) — see [`packaging/docker/readme.md`](packaging/docker/readme.md) |

`<version>` is the rolling-release `YY.N` string (current: `26.1`). See
[`docs/installation.md`](docs/installation.md) for verification and per-OS
notes, and [Versioning](#versioning) below.

### From source

Requires Rust 1.85 (pinned by `rust-toolchain.toml`).

```sh
cargo build --release -p spt-bin
sudo install -m 0755 target/release/spt /usr/local/bin/spt
```

## 60-second example

```sh
# 1. Validate the bundled minimal config.
spt config validate --config examples/minimal.toml

# 2. Run in the foreground.
spt tunnel run --foreground --config examples/minimal.toml

# 3. From another shell, hit the local end of the forward.
curl http://127.0.0.1:8080/

# 4. Inspect the live status snapshot.
spt tunnel status --config examples/minimal.toml
```

The bundled [`examples/minimal.toml`](examples/minimal.toml) shows the
canonical shape — a single profile with a single local TCP forward. Other
examples cover jump-host chains, reverse forwards, SMTP relays, the SSH3
backend, and split-horizon DNS.

## Documentation

- [Getting Started](docs/getting-started.md)
- [Configuration](docs/configuration.md) — TOML reference.
- [CLI Reference](docs/cli-reference.md) — every command + status.
- [Profiles](docs/profiles.md), [Forwards](docs/forwards.md),
  [Authentication](docs/auth.md), [Trust](docs/trust.md),
  [Secrets](docs/secrets.md).
- [SFTP](docs/sftp.md), [Obfuscation](docs/obfuscation.md),
  [Scripting](docs/scripting.md).
- [Service Integration](docs/service-integration.md),
  [DNS](docs/dns.md), [Firewall](docs/firewall.md),
  [Observability](docs/observability.md), [Events](docs/events.md).
- [Diagnostics](docs/diagnostics.md), [Benchmarking](docs/benchmarking.md),
  [MCP](docs/mcp.md), [TUI](docs/tui.md), [SSH3](docs/ssh3.md),
  [Remote Config](docs/remote-config.md).
- [Security](docs/security.md), [Versioning](docs/versioning.md),
  [Troubleshooting](docs/troubleshooting.md).

The full specification lives at [`spec.md`](spec.md).

## Versioning

`spt` ships on a **rolling `YY.N` release** (current: `26.1`); the workspace
`Cargo.toml` encodes it as `0.YY.N` for Cargo's SemVer parser. Releases are cut
automatically on green pushes to `main`. Full scheme, automation, and per-
release notes: [`docs/versioning.md`](docs/versioning.md),
[`releasing.md`](releasing.md), [`docs/releases/`](docs/releases/).

## Security

Secrets resolve through pluggable backends (keychain / vault / env / file) and
never appear as plaintext in config; three-tier redaction (`None` / `Standard`
/ `Strict`) guards every log, event, MCP, and diagnostic sink; 38 stable exit
codes; a single-supervisor lock per state directory. Full threat model:
[`docs/security.md`](docs/security.md).

## License

MIT — see [`license.md`](license.md).
