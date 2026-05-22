# ssh-perma-tunnel (`spt`)

[![CI](https://github.com/Mariana/ssh-perma-tunnel/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/Mariana/ssh-perma-tunnel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](license.md)
[![Built with Rust 1.85+](https://img.shields.io/badge/built_with-Rust_1.85+-dea584?logo=rust&logoColor=white&style=flat-square)](rust-toolchain.toml)

A single Rust command-line tool, `spt`, that establishes and maintains
**permanent SSH tunnels** — local and reverse port forwards that survive
network drops, host restarts, service restarts, DNS changes, and normal
operational drift.

`spt` ships:

- SSH2 transport via the pure-Rust `russh` backend — the only SSH2
  implementation (`libssh2` was removed in t7). Experimental SSH3 over
  QUIC + HTTP/3 also available.
- Local TCP, remote TCP, and dynamic (SOCKS4 / SOCKS4A / SOCKS5 / HTTP
  CONNECT) forwards.
- UDP forwarding with `tcp-framed` (default) and `uds-bridge` modes.
- Server-side UNIX-socket forwarding (`direct-streamlocal@openssh.com`).
- Multi-hop jump-proxy chains (`-J user@host[,...]`) over native russh
  channels — no socketpair indirection.
- Full **SFTP** suite: `cat`, `tail`, `chmod`, `symlink`, `readlink`,
  `realpath`, recursive `put` / `get` with `--resume`, BPS cap, and
  SHA-256 checksum verification.
- **SFTP-as-drive mount** — Linux via `fuser` (FUSE), Windows via Dokany2,
  macOS via the deprecation-warned `sshfs` + macFUSE shell-out.
- **FTP→SFTP translator** with real RFC 4217 AUTH TLS in-place upgrade.
- **Scripting hooks** via the sandboxed `rhai 1.19` engine — five
  entry-points (`pre_connect`, `post_connect`, `on_forward_state`,
  `on_disconnect`, `on_event`), `eval`/`import` disabled, fresh `Scope`
  per invocation.
- **Portable mode** (`--portable`): single-binary, no OS install, no
  user-directory or keychain side-effects.
- **SSPI / GSSAPI / Kerberos / NTLM** authentication — Windows via
  `sspi 0.15`, Unix via the vendored `libgssapi 0.9` fork (RFC 4462
  `gssapi-with-mic`).
- Full public-key matrix: Ed25519, ECDSA P-256/P-384/P-521,
  RSA-SHA2-256/512 (legacy `ssh-rsa` SHA-1 rejected by default).
- **TOTP / 2FA** keyboard-interactive auth (RFC 6238 SHA-1/256/512).
- **Obfuscation transports**: obfs4 (NTOR-style X25519 handshake),
  meek-http (HTTPS domain-fronting), ssh-over-websocket (RFC 6455),
  ssh-over-shadowsocks (AEAD-2022 + BLAKE3 KDF).
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
| Docker   | `ghcr.io/mariana/spt:<version>` (linux/amd64, linux/arm64) — see [`packaging/docker/readme.md`](packaging/docker/readme.md) |

`<version>` is the rolling-release `YY.N` string (e.g. `26.1`, `26.2`,
… `27.1`); the current release is `26.1`. See [Versioning](#versioning)
below and [`docs/installation.md`](docs/installation.md) for
verification and per-OS notes.

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
- [Diagnostics](docs/diagnostics.md), [Benchmarking](docs/benchmarking.md)
  (live [perf dashboard](https://Mariana.github.io/ssh-perma-tunnel/perf/dashboard.html)),
  [MCP](docs/mcp.md), [TUI](docs/tui.md), [SSH3](docs/ssh3.md),
  [Remote Config](docs/remote-config.md).
- [Security](docs/security.md), [Troubleshooting](docs/troubleshooting.md),
  [Production Readiness](docs/production_readiness.md).
- Migration: [t7 → t8](docs/migration/t7-to-t8.md).

The full specification lives at [`spec.md`](spec.md).

## Versioning

`spt` ships on a **rolling release** model. Versions take the shape
`YY.N` — two-digit UTC year plus a monotonic counter that resets each
January 1st (UTC). The current release is `26.1`; the next one will be
`26.2`, then `26.3`, … rolling into `27.1` when the year ticks over.
The workspace `Cargo.toml` carries the SemVer-compatible encoding
`0.YY.N` (e.g. `0.26.1`) because Cargo's TOML parser rejects the bare
`YY.N` shape; user-facing tags, release titles, docker tags, and
packaging recipes drop the leading `0.`.

A new release is cut automatically by `.github/workflows/ci.yml`
whenever the full CI matrix (fmt, clippy, test × 6 platforms, build ×
6 platforms) and the security audit (cargo-deny + RustSec) are green
on a push to `main`. See [`releasing.md`](releasing.md) and
[`docs/releases/`](docs/releases/) for the full automation and per-
release notes.

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
