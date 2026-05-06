# SSH3 (experimental)

SSH3 is a draft protocol that maps SSH semantics onto HTTP/3 (QUIC + TLS 1.3
+ Extended CONNECT). `spt`'s SSH3 backend is **experimental** and ships in
**stub mode** in v1: every call to `Ssh3Protocol::connect` returns
`UnsupportedPlatform` with a clear reason.

## Status

Per spec §4.2, SSH3 must be compiled into default builds with no feature
gate, and every startup / `validate` / `doctor` / `tunnel run` MUST surface
an experimental warning unless the operator opts in. The stub satisfies all
of these constraints — see
[`crates/spt-ssh3/src/lib.rs`](../crates/spt-ssh3/src/lib.rs).

## Acknowledging experimental

    [[profiles]]
    name = "edge"
    protocol = "ssh3"
    endpoint = "https://edge.example.com:443/ssh"
    acknowledge_experimental = true   # silences the startup warning

`acknowledge_experimental = false` (or unset) leaves the warning enabled.

## What works

- Public type surface (`Ssh3Protocol`, `Ssh3Config`, `Ssh3Frame`,
  `Ssh3Settings`, `Ssh3StreamKind`).
- Config parsing and validation.
- The mandatory experimental warning on every connect attempt.

## What doesn't

- Live transport (returns `UnsupportedPlatform`).
- UDP forwards (require live transport).
- OIDC device-flow auth (parsed but not exercised).

## When not to use SSH3

Until the standards-track spec stabilises and the reference peer is
production-ready, SSH3 is unsuitable for production tunnels. Use SSH2.
