# Changelog

This project follows a **rolling release** model with `YY.N` versions
(two-digit UTC year + monotonic counter that resets each year). The
workspace `Cargo.toml` carries the SemVer-compatible `0.YY.N` form
because Cargo's TOML parser rejects the bare `YY.N` shape; user-
facing tags drop the leading `0.`. See [`releasing.md`](releasing.md)
and [`docs/releases/readme.md`](docs/releases/readme.md) for the full
scheme.

Releases are cut automatically by `.github/workflows/ci.yml` when the
full CI matrix and the security audit are green on a push to `main`.
Per-release notes live under [`docs/releases/`](docs/releases/); this
file is the rolled-up index. Entries are prepended by the release
job using `## [VERSION] - YYYY-MM-DD`. Dates are ISO 8601 (UTC).

## [Unreleased]

### Added

- (entries land here as PRs merge; keep them user-visible and
  imperative — "Add SRV record synthesis to the resolver", not
  "Refactored the resolver internals").

## [26.1] - 2026-05-22

Initial rolling release. `spt` ships as a single, batteries-included
Rust CLI for permanent SSH tunnels. Closes out milestones t6 (feature
surface), t7 (libssh2 demolished, contract stubs become real), and
t8 (production hardening). See [`docs/releases/26.1.md`](docs/releases/26.1.md)
for the full release notes (highlights, migration notes from the
pre-release `0.x` series, known issues, and verification gates).

### Added

- **SSH2 transport** via the pure-Rust `russh` stack (libssh2 removed
  in t7-Phase0) with full local and remote TCP forwarding, jump-host
  chains, agent + key auth, and a hardened trust store (`spt-trust`).
- **SSH3 transport** (experimental) over QUIC + HTTP/3, including
  per-forward channel framing, OIDC device-flow bearer auth
  (RFC 8628), and UDP forward support. Marked experimental and
  excluded from the security scope until standards-track.
- **Post-quantum KEX**: `mlkem768x25519-sha256` (FIPS 203 ML-KEM-768
  hybrid with X25519) live in the vendored russh fork, wire-compatible
  with OpenSSH 9.9's `kexmlkem768x25519.c`.
- **Chaos engineering**: new `spt-chaos-proxy` crate + 12 reconnect
  scenarios under `tests/chaos/` validating supervisor backoff against
  partitions, latency spikes, RST storms, DNS flapping, host-key
  churn, slow-loris, half-close, and rapid-reconnect storms.
- **Comparative performance**: `spt-benchmark` `Comparator` trait
  with `OpenSshClient` and `AutosshClient` implementations; a
  3×3×2×3 (54-cell) baseline matrix checked in at
  `docs/perf/baseline-26.1.json` (file path retained as
  `baseline-v1.0.json` in this release for backward-compat).
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
  project SNMPv3 agent + traps using the bundled `SPT-MIB`. Per-
  module `SPT_LOG` filter directives with SIGHUP / MCP runtime reload.
- **Diagnostics with miette spans**: error surfacing rewritten across
  the top 50 error sites; FFI boundaries get explicit `catch_unwind`
  panic boundaries.
- Embedded **Model Context Protocol** server: 16 read-only resources
  and 31 tools, disabled by default, read-only by default, never
  emits plaintext secrets through any transport.
- **TUI profile configurator** (`spt profile configure --tui`).
- **27-crate workspace**, every library crate publishing a `testing`
  Cargo feature with fixtures, builders, and mocks for sibling-crate
  use.
- **Packaging** for 8 release targets: `.deb`, `.rpm`, `.pkg`, `.msi`,
  plus tarballs for the remaining triples; multi-arch GHCR images.
  Homebrew, Scoop, Chocolatey, Snap, Flatpak, AUR, Winget, and Nix
  manifests included.
- 38 stable exit codes, complete CLI man-page set under
  `packaging/man/`, and a published spec (`spec.md`) covering the
  full surface area.

### Security

- **Constant-time review**: every secret-comparison call site audited
  (`spt-secrets`, `spt-auth::totp`, `spt-key`, `spt-trust::known_hosts`)
  with `subtle 2` threaded through. TLS pinning + cert-validation
  edge cases (chain depth, expired-cert, missing-EKU) covered by 45
  new tests. Shadowsocks AEAD gained an explicit replay-window check.
- **Unsafe-block audit**: all 160 `unsafe` blocks (114 in `crates/` +
  46 in `vendor/`) carry per-block `// SAFETY:` comments; the
  `clippy::undocumented_unsafe_blocks` lint is `-D` workspace-wide.
- **8 new fuzz targets** (`socks5_negotiate`, `http_connect_request`,
  `ftp_verb_parse`, `ssh3_jwt_jose_header`, `openssh_config_parse`,
  `forward_spec_parse`, `obfs4_frame_decode`, `shadowsocks_aead_decrypt`).
  PR-gating runtime is 90 s per target.
