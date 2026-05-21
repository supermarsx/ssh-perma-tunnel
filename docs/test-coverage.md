# Test Coverage And Acceptance Inventory

This document is the current coverage report for production readiness. It
describes automated tests that exist in the repository and the acceptance
checks that still must run on real target platforms before a GA release.

## Current Status

The suite has broad unit and integration coverage for config parsing,
validation, CLI routing, secrets, SSH2/SSH3 forward wiring, diagnostics,
benchmark drivers, logging, service managers, MCP, SNMP feature builds, and
packaging metadata. The repository also has platform acceptance criteria in
[`platform-acceptance.md`](platform-acceptance.md).

This inventory is not a claim that the full OS matrix has passed. Release
approval still requires running the complete locked workspace test suite,
clippy, docs, audit/deny, package installation tests, and the Linux/macOS/
Windows acceptance matrix.

## CLI And Config Coverage

- `spt-cli` help snapshots verify the top-level command tree and help text for
  `auth`, `benchmark`, `completion`, `config`, `diagnose`, `dns`, `event`,
  `firewall`, `forward`, `key`, `log`, `mcp`, `observe`, `profile`,
  `secret`, `service`, `session`, `sftp`, `stats`, `status`, and `tunnel`.
- `spt-bin` dispatch tests exercise routing for config, profile, forward,
  tunnel, service, key, secret, auth, DNS, firewall, log, observe, event,
  stats, session, SFTP, diagnose, benchmark, MCP, completion, and status
  commands.
- Completion tests verify committed bash, zsh, fish, PowerShell, and Elvish
  artifacts match the live CLI tree.
- Man page generation is covered through the `spt-mangen` generator and
  package artifact checks.
- Config tests cover examples, strict validation, unknown-key diagnostics,
  migration, rendering, diffing, remote-config validation, policy overlay,
  network policy, capability gates, and sealed config loading.

## Feature Coverage By Area

| Area | Automated coverage |
|------|--------------------|
| SSH2 runtime | `spt-ssh2` russh backend tests cover password/public-key/cert/kbi auth paths, local TCP forwards, remote TCP forwards, dynamic SOCKS5 and HTTP CONNECT proxy forwarding, keepalive, and backend selection policy. |
| SSH auth policy | `spt-auth`, `spt-config`, `spt-diagnostics`, and `spt-bin` tests cover declared auth method translation, GSSAPI/Kerberos/SSPI config shape, delegation/NTLM capability gates, and explicit unsupported-runtime diagnostics for Kerberos/SSPI until backend negotiation exists. |
| SSH crypto policy | `spt-ssh2` classifies deprecated, post-quantum, and ML-KEM KEX names. `spt-config` validates PQ/ML-KEM capability gates and required-PQ policy. `spt-bin` tests assert requested PQ KEX returns an explicit runtime unsupported diagnostic until the transport KEX engines exist. |
| SFTP | `spt-ssh2` tests cover the russh SFTP client API and unsupported libssh2 diagnostics. `spt-config` validates `[[profiles.sftp_mounts]]` capability gates, drive-letter policy, and cache modes. `spt-bin` tests cover mount/drive config mutation and planning surfaces. |
| SSH3 runtime | `spt-ssh3` tests cover QUIC/TLS/HTTP3 CONNECT bootstrap, frame handling, local/remote TCP where peer capability exists, UDP capability gating, and experimental acknowledgement. |
| Forwards | `spt-forward` tests cover runner translation, bind modes, target parsing, dynamic proxy dispatch, UDP rejection where unsupported, state transitions, connection limits, and testing fixtures. |
| Runtime/supervisor | `spt-supervisor` tests cover reconnect state, failover, round-robin/weighted selection, reload diffing, live benchmark connectors, session/drain controls, and controller API paths. |
| Secrets/vault | `spt-secrets` tests cover vault lifecycle, encrypted-at-rest records, keychain mocks, refs, redaction, passphrase reading, and zeroizing buffers. `spt-bin` config tests cover sealed config passphrases stored in the vault and vault-master sealing. |
| Encrypted configs | `spt-config-crypt` tests cover SPTENC1 sealing, passphrase/X25519/vault-master key sources, metadata, tamper detection, wrong-key failures, and loader auto-detection. |
| Firewall/network policy | Firewall tests cover rule planning, bind preview, interface-specific binds, GPO write gates, policy list/show routes, and CLI mutation of `[network.interface]`, `[network.gateway]`, `[network.offload]`, and `[network.load_balance]`. |
| GPO policy | `spt-config` policy tests cover advisory/enforced precedence, type mismatches, unknown keys, allowlist intersection, denylist union, network/offload/load-balance bindings, capability gates, and Windows Event policy fields. |
| DNS | `spt-dns` and CLI tests cover record parsing, hosts-file render/apply/restore paths, resolver mode validation, upstream management, and query routing. |
| Observability/logging | `spt-observability` and CLI tests cover syslog TLS mock delivery, log export/tail, remote log list/test/status/drain routing, OTLP/syslog config validation, metrics state, and redaction. |
| Events | `spt-events` tests cover dispatcher recovery, sink formatting, HTTP/webhook-like transports, retry/backoff, redaction, and configured sink routing. |
| MCP | `spt-mcp` and `spt-bin` tests cover loopback transport, handshake, resource/tool listing, policy allowlists, disabled-by-default serving, and guarded write-tool routing. |
| SNMP | `spt-snmp` tests cover MIB constants, v3 auth/privacy shapes, agent GET behavior, trap structures, and rejection of documentation/placeholder enterprise PENs in runtime startup. |
| Windows Event Log | `spt-winevent` and CLI tests cover source install/uninstall/test command surfaces, policy fields, and non-Windows unsupported diagnostics. |
| Services | `spt-service` tests cover systemd, launchd, OpenRC, SysV, Windows SCM, and Task Scheduler rendering/status helpers with OS-specific execution separated behind mocks where needed. |
| Diagnostics | `spt-diagnostics` and CLI tests cover network/auth/trust/DNS/bind/port/service/secrets/observability/MCP/bundle checks, redaction, and protocol autodetection fixtures. |
| Benchmarking | `spt-benchmark` and CLI tests cover latency, throughput, UDP, reconnect, DNS, limits, safety gates, compare/export formats, and live-driver refusal when no sidecar is available. |
| Packaging | Packaging tests and scripts cover completions, man pages, package metadata, checksums/signing hooks, service templates, and platform acceptance criteria. |

## Encrypted Passwords In Configs

Do not put plaintext passwords in TOML. Use a secret reference:

```toml
[profiles.auth]
method = "password"
password = "secret://db/password"
```

For a local encrypted vault:

```text
spt secret store init --backend vault --vault-path ./secrets --passphrase-from env:VAULT_PP
spt secret set db/password --from-env DB_PASSWORD --vault-path ./secrets --passphrase-from env:VAULT_PP
```

For an entirely sealed config file, store the sealing passphrase in the vault:

```text
spt secret set cfg/seal-passphrase --from-env CONFIG_SEAL_PP --vault-path ./secrets --passphrase-from env:VAULT_PP
spt config encrypt spt.toml --passphrase-from secret://cfg/seal-passphrase --vault-path ./secrets --vault-passphrase-from env:VAULT_PP
```

Fleet configs can also use the vault master key:

```text
spt config encrypt spt.toml --use-vault-master --vault-path ./secrets --vault-passphrase-from env:VAULT_PP
```

## Required Full-Suite Commands

Run these before a release candidate:

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny check bans licenses sources
cargo audit
```

Run the feature matrix separately:

```text
cargo test --workspace --all-targets --locked
cargo test --workspace --all-targets --features snmp --locked
```

## Remaining Acceptance Gaps

- Run the complete platform matrix from
  [`platform-acceptance.md`](platform-acceptance.md) on Linux, macOS, and
  Windows with rootless and privileged installs.
- Run ignored stress tests for burst traffic, long soak, file descriptor/handle
  leaks, remote log outage/spool bounds, and low idle CPU.
- Exercise live OpenSSH/dropbear/libssh interoperability fixtures for SSH2
  local, remote, and dynamic proxy coverage.
- Add production-positive runtime tests for GSSAPI/Kerberos/SSPI, ML-KEM/PQ
  KEX negotiation, SFTP live server operations, filesystem mounts, and Windows
  drive-letter mounts once their runtime implementations are complete.
