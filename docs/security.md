# Security

## Threat model

`spt` is designed to mediate trusted local clients with a trusted remote SSH
endpoint. It defends against:

- Plaintext exposure of secrets in logs, status snapshots, MCP responses,
  diagnostic bundles, and Prometheus metrics.
- Unauthorised reconfiguration via the MCP tool surface (read-only by
  default; mutating tools require an explicit allow-list).
- Replay or tampering of remote-config documents (HTTPS + body-fingerprint
  pin, never trust the certificate alone).
- Concurrent supervisors stomping on the state directory (`fs4` exclusive
  lock + PID file).

It explicitly does **not** protect against a malicious local root or an
adversarial remote SSH server.

## Trust boundaries

| Boundary               | Control                                          |
|------------------------|--------------------------------------------------|
| local client → spt     | Loopback bind by default; CIDR ACLs per forward.|
| spt → remote endpoint  | Host-key (known_hosts) or SHA-256 pin; TLS pin for SSH3. |
| spt → secret backend   | OS keychain ACL, vault passphrase / Argon2id.    |
| spt → MCP client       | Stdio (or loopback TCP); read-only by default.   |
| operator → config disk | Mode 0640 root:spt; service runs as `spt:spt`.   |

## Secret handling end-to-end

1. Configs reference secrets symbolically: `secret://<ns>/<name>`,
   `env:<NAME>`, or `file:///abs/path`.
2. Resolver order: keychain → vault → env → file (matching backend type).
3. Secret bytes are wrapped in `secrecy::SecretBox<Zeroizing<Vec<u8>>>`,
   zeroed on drop, and never `Debug`-printed.
4. Renderers and event/log sinks pass output through
   `spt_core::redaction` before bytes hit disk or network.
5. `spt diagnose bundle` always uses `RedactionMode::Strict`.

## Redaction modes

- `None` — verbatim. Local debugging only.
- `Standard` (default) — replaces `secret://...` and inline plaintext
  password / token fields with `[REDACTED]`.
- `Strict` — `Standard` plus IP-address-like host/endpoint values.

## Privilege separation

`spt` is intended to run as a dedicated unprivileged user (e.g. `spt:spt`).
The systemd unit shipped under `/packaging/systemd/spt.service` sets:

    NoNewPrivileges=true
    PrivateTmp=true
    ProtectSystem=strict
    ProtectHome=read-only
    AmbientCapabilities=CAP_NET_BIND_SERVICE  # only when required

## Supply-chain

Releases are signed; verify before installing — see
[Installation](installation.md). The Rust dependency tree is audited via
`cargo deny` in CI; `cargo update` is forbidden in this repo (the pinned
lockfile is part of reproducibility).

## Reporting vulnerabilities

Email security@example.invalid (replace with the project's real address).
Include reproduction steps and the `spt --version` string.
