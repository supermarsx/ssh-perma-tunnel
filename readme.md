# ssh-perma-tunnel (`spt`)

[![CI](https://github.com/Mariana/ssh-perma-tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/Mariana/ssh-perma-tunnel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](license.md)
[![Built with Rust 1.83+](https://img.shields.io/badge/built_with-Rust_1.83+-dea584?logo=rust&logoColor=white)](rust-toolchain.toml)

A single Rust command-line tool, `spt`, that establishes and maintains
**permanent SSH tunnels** — local and reverse port forwards that survive
network drops, host restarts, service restarts, DNS changes, and normal
operational drift.

`spt` ships:

- SSH2 transport via `libssh2` (per spec §17.4) and an experimental SSH3
  transport over QUIC + HTTP/3.
- Local and remote TCP forwards everywhere; UDP forwards over SSH3.
- A built-in transparent **DNS resolver** with split-horizon, SRV
  synthesis, and managed-block hosts-file integration.
- An encrypted **secret vault** (AES-256-GCM + Argon2id) and OS keychain
  integration; references resolve through `secret://ns/name`.
- **Service integration** for systemd, launchd, Windows SCM, OpenRC,
  SysV, and Task Scheduler.
- Structured **observability**: rotating file logs, journald, syslog-TLS,
  HTTPS-JSONL, OTLP, Prometheus metrics, and a project SNMPv3 agent +
  traps with the [SPT-MIB](mibs/SPT-MIB.txt).
- An embedded **Model Context Protocol** (MCP) server with 16 read-only
  resources and 31 tools — disabled by default, read-only by default,
  never returns plaintext secrets.
- A **TUI** profile configurator (`spt profile configure --tui`).
- Diagnostics with redacted bundles and a benchmarking driver framework.

> **`spt` is client-only.** It connects to existing SSH/SSH3 servers (OpenSSH,
> dropbear, the francoismichel/ssh3 reference, etc.) and maintains forwards
> through them. There is no built-in server role; bring your own remote.

## Install

### From a release artifact

| Platform | Artifact                                |
|----------|-----------------------------------------|
| Linux    | `spt_<version>_amd64.deb`,  `*.rpm`     |
| macOS    | `spt-<version>.pkg`                     |
| Windows  | `spt-<version>.msi`                     |

See [`docs/installation.md`](docs/installation.md) for verification and
per-OS notes.

### From source

Requires Rust 1.83 (pinned by `rust-toolchain.toml`).

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
- [Service Integration](docs/service-integration.md),
  [DNS](docs/dns.md), [Firewall](docs/firewall.md),
  [Observability](docs/observability.md), [Events](docs/events.md).
- [Diagnostics](docs/diagnostics.md), [Benchmarking](docs/benchmarking.md),
  [MCP](docs/mcp.md), [TUI](docs/tui.md), [SSH3](docs/ssh3.md),
  [Remote Config](docs/remote-config.md).
- [Security](docs/security.md), [Troubleshooting](docs/troubleshooting.md).

The full specification lives at [`spec.md`](spec.md).

## Security model in brief

- All secrets resolved through pluggable backends — keychain, vault, env,
  file. References never appear in plaintext in config; the resolver
  returns `secrecy::SecretBox<Zeroizing<Vec<u8>>>`.
- Three-tier redaction (`None`, `Standard`, `Strict`) sits between every
  log/event/MCP/diagnostic sink and disk/network.
- 38 stable exit codes; full mapping in
  [`crates/spt-core/src/exit_code.rs`](crates/spt-core/src/exit_code.rs).
- Single-supervisor `fs4` lock per state directory.

For the full threat model, see [`docs/security.md`](docs/security.md).

## License

MIT — see [`license.md`](license.md).
