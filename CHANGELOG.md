# Changelog

All notable changes to `spt` (`ssh-perma-tunnel`) are documented in
this file.

The format is based on [Keep a Changelog 1.1.0][kac] and this project
adheres to [Semantic Versioning 2.0.0][semver]. Dates are ISO 8601
(UTC).

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

- (entries land here as PRs merge; keep them user-visible and
  imperative — "Add SRV record synthesis to the resolver", not
  "Refactored the resolver internals").

## [0.1.0] - 2026-05-05

Initial public release. `spt` ships as a single, batteries-included
Rust CLI for permanent SSH tunnels.

### Added

- **SSH2 transport** via `libssh2` (spec §17.4) with full local and
  remote TCP forwarding, jump-host chains, agent + key auth, and a
  hardened trust store (`spt-trust`).
- **SSH3 transport** (experimental) over QUIC + HTTP/3, including
  per-forward channel framing, OIDC device-flow bearer auth
  (RFC 8628), and UDP forward support. Marked experimental and
  excluded from the security scope until standards-track.
- Built-in transparent **DNS resolver** with split-horizon resolution,
  SRV record synthesis, and a managed-block hosts-file integrator.
- Encrypted **secret vault** (AES-256-GCM + Argon2id) with OS-keychain
  integration; references resolve through `secret://ns/name`. Secrets
  are zeroized end-to-end via `secrecy::SecretBox<Zeroizing<Vec<u8>>>`.
- **Service integration** for systemd, launchd, Windows SCM, OpenRC,
  SysV, and Windows Task Scheduler — full lifecycle (install, start,
  stop, status, reload, uninstall) on every backend.
- **Observability** stack: rotating file logs, journald, syslog-TLS,
  HTTPS-JSONL, OTLP traces + metrics, Prometheus exporter, and a
  project SNMPv3 agent + traps using the bundled `SPT-MIB`.
- Embedded **Model Context Protocol** server: 16 read-only resources
  and 31 tools, disabled by default, read-only by default, never
  emits plaintext secrets through any transport.
- **TUI profile configurator** (`spt profile configure --tui`).
- **Diagnostics** with three-tier redaction (`None`, `Standard`,
  `Strict`) and a redacted bundle exporter.
- **Benchmark** driver framework for tunnel-throughput and
  reconnect-latency regression tracking.
- **27-crate workspace**, every library crate publishing a `testing`
  Cargo feature with fixtures, builders, and mocks for sibling-crate
  use.
- **Packaging** for 8 release targets: `.deb`, `.rpm`, `.pkg`, `.msi`,
  plus tarballs for the remaining triples; multi-arch GHCR images.
- 38 stable exit codes, complete CLI man-page set under
  `packaging/man/`, and a published spec (`spec.md`) covering the
  full surface area.
