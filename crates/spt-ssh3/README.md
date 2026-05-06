# spt-ssh3

SSH3 backend for spt — adapter against the [francoismichel/ssh3] prototype's
TLS-1.3/QUIC + HTTP/3 Extended-CONNECT transport.

[francoismichel/ssh3]: https://github.com/francoismichel/ssh3

## Status: stub mode (v1)

This crate currently ships in **stub mode**. Concretely:

- `Ssh3Protocol::capabilities()` returns the real SSH3 capability set
  (TCP both ways, UDP both ways, multiplex, no SSH host keys, no multi-hop).
- `Ssh3Protocol::name()` returns `"ssh3"`.
- `Ssh3Protocol::connect()` always emits the spec-mandated experimental
  warning (unless `[profiles.ssh3] acknowledge_experimental = true`) and then
  returns `Error::UnsupportedPlatform("SSH3 backend disabled at build: …")`.
- The framing types (`Ssh3Frame`, `Ssh3FrameKind`, `Ssh3Settings`,
  `Ssh3StreamKind`) are real, with encode/decode helpers and capability-set
  satisfaction checks.

The supervisor and CLI compile against this crate exactly as they will against
the full implementation; only the I/O is missing.

## Why stub?

The Phase 3 task spec for `spt-ssh3` enumerates an MSRV escape hatch:

> quinn 0.11 + rustls 0.23 + h3 0.0.7 are all expected to compile under MSRV
> 1.83. If they don't (edition2024 trap), follow this fallback: pin to older
> versions if available; if still broken, ship a stub …

Empirically:

1. **SSH3 has no stable spec** — the wire protocol is the
   francoismichel/ssh3 reference, which is itself experimental. Real
   round-trip testing requires a self-hosted reference server (gated behind
   `SPT_SSH3_TEST_SERVER` per the task spec).
2. **MSRV pinning is fragile** — `Cargo.lock` is committed and must not be
   `cargo update`d (workspace state.md is explicit). Pulling in `quinn` +
   `h3` + `h3-quinn` + their transitive `rustls 0.23` graph drags many
   crates that have moved to `edition2024` (rust-version ≥ 1.85), beyond
   the workspace MSRV of 1.83.
3. **The escape hatch is pre-approved** for exactly this scenario, and
   the v1 milestone explicitly accepts stub-mode tests
   (capability assertion, experimental-warning emission, config validation).

## Path to a non-stub implementation

When MSRV is bumped past 1.85 (or when `quinn`/`h3` ship 1.83-compatible
releases), the planned wiring is:

1. Add `quinn`, `rustls`, `rustls-native-certs`, `rustls-pemfile`, `h3`,
   `h3-quinn`, `reqwest` (rustls-tls, default-features=false) to this crate's
   `[dependencies]`. The workspace already declares all of these in
   `[workspace.dependencies]` — no Cargo.toml root edit is needed.
2. Implement a real `Ssh3Session` with:
   - QUIC connect via `quinn::Endpoint::client` + a custom `rustls::ClientConfig`
     that consults `Ssh3TlsConfig` (system roots → optional CA file → SPKI pin
     via `spt_trust::TlsPin`, with `allow_self_signed` only honored when
     `acknowledge_experimental` is also set).
   - HTTP/3 setup via `h3::client::new` over `h3_quinn::Connection`.
   - SSH3 Extended CONNECT (`:method = CONNECT`, `:protocol = ssh3`,
     `:authority`, `:path` from `Ssh3Config::url_path`).
   - Authorization: bearer / basic from `AuthConfig`; OIDC device-flow via
     `reqwest` against `Ssh3AuthExtras::oidc_discovery_url`.
3. After CONNECT, send a `Settings` frame, read the peer's `Settings`,
   call `peer_settings.satisfies(&required)` — fail with `UnsupportedPlatform`
   on missing capabilities (this contract is already enforced by
   `Ssh3Settings::satisfies`).
4. Per-forward QUIC bidi streams for TCP; QUIC datagrams for UDP.
5. Keepalive: QUIC PING every `keepalive_secs`.

The public surface (config, frame types, capability set) does not change, so
swap-in is a non-breaking change to downstream crates.

## Tests

```text
cargo test -p spt-ssh3
```

Covers (stub mode):

- Capability assertion — `Ssh3Protocol::default().capabilities() == ProtocolCapabilities::ssh3()`.
- Experimental warning emission via `tracing-test`'s `#[traced_test]`,
  in both default and `acknowledge_experimental = true` modes.
- Config validation: `url_path` slash, `allow_self_signed` requires ack,
  `keepalive_secs > 0`.
- Frame round-trip, unknown-kind reject, truncated payload reject.
- Settings satisfaction — required-capability set check.

When `SPT_SSH3_TEST_SERVER` is set (full mode only — currently never), an
ignored integration test would round-trip a single TCP forward.
