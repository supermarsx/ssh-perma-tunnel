# Development Guide

This chapter is the reference for contributors working *on* `spt` (rather than
operators running it). It covers the toolchain, the workspace layout, how to
build, test, and lint, what CI gates a merge, and how to extend the codebase
without breaking its invariants.

For the runtime model — how the CLI, supervisor, transports, and forwarders fit
together at run time — read [Architecture Overview](architecture.md) first. This
guide deliberately does **not** repeat the subsystem map; it points at the crates
you touch when you change behaviour.

## 1. Prerequisites & toolchain

`spt` is a pure-Rust Cargo workspace. There is a single supported toolchain.

| Requirement | Value |
|-------------|-------|
| Rust MSRV | **1.88** (also the edition-2021 pin in `[workspace.package]`) |
| Components | `rustfmt`, `clippy` |
| Toolchain policy | MSRV is the *contract* — `fmt`, `clippy`, `typecheck`, and every `test`/`build` matrix job pin `1.88.0`. There is no separate "MSRV job"; MSRV is tested implicitly everywhere. |

Install the toolchain and components:

```bash
rustup toolchain install 1.88.0
rustup component add rustfmt clippy --toolchain 1.88.0
```

### Platform system dependencies

The default workspace build is self-contained (the SSH stack is pure-Rust
`russh`, not a C `libssh2` binding), but some feature-gated and OS-specific
paths link native libraries. The CI Linux jobs install:

```bash
sudo apt-get install -y pkg-config libssl-dev libdbus-1-dev \
                        libkrb5-dev clang libclang-dev libfuse-dev
```

- `libdbus-1-dev` — OS keychain integration (`spt-secrets` via `keyring`).
- `libkrb5-dev`, `clang`, `libclang-dev` — GSSAPI/Kerberos backend
  (`spt-auth-sspi`) and bindgen.
- `libfuse-dev` — only needed for the SFTP FUSE mount backend (see below).

**Windows notes.** Native builds use the MSVC toolchain
(`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`). Packaging the MSI needs
the WiX 3 toolset, and the Windows SFTP mount backend needs the Dokany2 driver
plus MSVC build tools (a C compiler is required even when Dokany is
pre-installed). None of that is needed for a plain `cargo build`/`cargo test`.

**macOS notes.** Native builds target `aarch64-apple-darwin` (Apple Silicon);
the Intel runner was retired from CI. The SFTP mount backend needs macFUSE.

### Feature flags

Most crates default to a **minimal** feature set; the interesting surfaces are
opt-in. The `all-features` CI job is what compiles and tests every gated path
(see [§5](#5-cicd)). The real flags in the tree:

| Feature | Crate(s) | Purpose |
|---------|----------|---------|
| `testing` | nearly every `spt-*` crate | Exposes in-crate test fixtures/mocks (mock SFTP server, capturing tracing layer, deterministic RNG seeds, stub servers) to downstream test crates. Gated so fixtures never ship in release builds. |
| `snmp` | `spt-bin`, `spt-cli` | Compiles the SNMPv3 agent surface (`spt-snmp`) and its CLI commands. |
| `otlp` | `spt-observability` | OpenTelemetry OTLP exporter (`opentelemetry*` deps). |
| `yubikey` | `spt-auth` | YubiKey OATH auth method. |
| `server` / `server-selfsigned` | `spt-ssh3` | The `spt ssh3-serve` role and self-signed cert helper (spt↔spt interop). |
| `transports` | `spt-events` | Email / WebPush notification sinks (default-on). |
| `clipboard` | `spt-tui` | Clipboard integration in the TUI (default-on). |
| `mount-fuse` | `spt-sftp` | Linux FUSE mount backend (`fuser` → libfuse; default-off so the workspace builds on hosts without `libfuse-dev`). |
| `mount-winfs` (alias `mount-winfsp`) | `spt-sftp` | Windows userspace-filesystem mount backend (Dokany2 via the MIT-licensed `dokan` crates). |

The `mount-*` deps are additionally scoped by `cfg(target_os = ...)`, so
enabling a backend on the wrong OS is a no-op stub rather than a build error.

## 2. Repository layout

The workspace is ~37 `spt-*` crates plus a handful of test/support members. The
root `Cargo.toml` lists them under `[workspace] members`; `default-members` is
just `crates/spt-bin` so a bare `cargo build` produces the `spt` binary.

Group crates by concern (see [Architecture Overview](architecture.md) for the
per-crate responsibilities and the runtime data flow — not repeated here):

| Concern | Crates |
|---------|--------|
| Binary / CLI / UI | `spt-bin`, `spt-cli`, `spt-tui`, `spt-mcp` |
| Core & config | `spt-core`, `spt-config`, `spt-config-crypt`, `spt-state` |
| Transports | `spt-ssh2`, `spt-ssh3`, `spt-obfs`, `spt-protocol`, `spt-net` |
| Forwarding & files | `spt-forward`, `spt-sftp`, `spt-ftp-translator` |
| Supervisor & resilience | `spt-supervisor`, `spt-chaos-proxy` |
| Auth / trust / secrets / keys | `spt-auth`, `spt-auth-sspi`, `spt-trust`, `spt-secrets`, `spt-key`, `spt-mem-hygiene` |
| Events / observability | `spt-events`, `spt-observability`, `spt-stats`, `spt-snmp`, `spt-winevent`, `spt-status-api` |
| Diagnostics / benchmark | `spt-diagnostics`, `spt-benchmark` |
| Service / updater | `spt-service`, `spt-updater` |
| DNS / firewall / scripting / remote config | `spt-dns`, `spt-firewall`, `spt-scripting`, `spt-remote-config` |

Convention inside a crate is a flat `src/` module tree with one file per
concern and a `testing.rs` module behind the `testing` feature. For example
`spt-config` splits into `schema.rs`, `validate.rs`, `load.rs`, `migrate.rs`,
`render.rs`, `diff.rs`, `mutate.rs`, …; `spt-forward` into `local_tcp.rs`,
`remote_tcp.rs`, `udp.rs`, `acl.rs`, `limits.rs`, `runner.rs`, …. When adding a
concern, add a module rather than growing an existing file.

### Excluded sub-workspaces (important)

Four paths are in the root `exclude` list and are **not** part of
`cargo … --workspace`:

| Path | What it is |
|------|------------|
| `tests/chaos` | Decoupled workspace with its **own `Cargo.lock`**. Spawns the real `spt` binary against `spt-chaos-proxy` + stub SSH/DNS servers. |
| `tests/property` | Decoupled workspace with its **own `Cargo.lock`**, pinning MSRV-clean `arbitrary`/`tempfile`. Property-based invariant suite. |
| `vendor/libgssapi-fork` | Vendored `libgssapi` fork (additive `gss_get_mic`/`gss_verify_mic` for RFC 4462 §3.5 MIC tokens); ships its own `[workspace]`. Routed in via `[patch.crates-io]`. |
| `tools/icon-build` | Standalone icon rasteriser; excluded so its image-codec dep tree doesn't bloat workspace builds. |

Both `tests/chaos` and `tests/property` keep a **separate `Cargo.lock` that pins
`spt-*` by version**. Any change to the main graph — including the automated
release version bump — desyncs those locks and breaks the `--locked` CI jobs.
See [§4](#4-testing) for the resync command.

## 3. Building & running

```bash
# Build just the binary (default-members):
cargo build

# Build everything in the workspace:
cargo build --workspace

# Run the CLI directly:
cargo run -p spt-bin -- --help
cargo run -p spt-bin -- tunnel run --config ./my-config.toml

# Compile/test every feature-gated surface (mirrors the `all-features` CI job):
cargo build --workspace --all-features
```

Default builds compile default features only. Feature-gated code (OTLP, SNMP,
YubiKey, ssh3 server, mount backends, hickory benchmark drivers, …) can silently
rot against dependency API changes with **no signal** from the default
`clippy`/`typecheck`/`test` jobs — which is exactly why the `all-features` job
exists. Build with `--all-features` locally before touching any gated module.

### Release profile

The release profile in the root `Cargo.toml` is hardened:

```toml
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
strip = "symbols"
panic = "abort"
overflow-checks = true   # sec-hardening
```

`overflow-checks = true` is load-bearing, not an oversight: for a network daemon
parsing untrusted wire bytes it turns any *undiscovered* integer-overflow into a
deterministic panic/abort rather than a silent wrap-then-OOB. **Intentional**
wraps must be spelled out with `wrapping_*` / `Wrapping` / `saturating_*` — do
not rely on release wrapping.

## 4. Testing

### The default workspace suite

```bash
cargo test --workspace
```

Unit tests live inline (`#[cfg(test)] mod tests`); integration tests live under
each crate's `tests/` directory. Note that many tests mutate **process-global**
state (`SPT_*` env vars, `EDITOR` overrides, loopback ports, supervisor test
hooks). CI runs the suite single-threaded for exactly this reason — reproduce a
flaky failure with:

```bash
cargo test --workspace -- --test-threads=1
```

### All-features suite

```bash
cargo test --workspace --all-features -- --test-threads=1
```

This is the only invocation that exercises the gated surfaces. Run it before
merging anything that touches feature-flagged code.

### Excluded sub-workspaces: chaos & property

These are **not** reached by `--workspace`. Run them via their own manifests:

```bash
# Property-based invariants (fast, deterministic, gates CI):
cargo test --manifest-path tests/property/Cargo.toml --locked

# Chaos / reconnect scenarios (spawns spt + chaos proxy on loopback):
cargo test --manifest-path tests/chaos/Cargo.toml --locked -- --test-threads=1
```

The chaos harness runs only its two PR-gating scenarios by default; the other
timing-sensitive scenarios are `#[ignore]`'d and run under `SPT_CHAOS_FULL=1`.

> **Critical maintenance gotcha.** `tests/chaos` and `tests/property` each carry
> their own `Cargo.lock` pinning `spt-*` by version. After **any** change to a
> main-workspace crate they depend on — or after the release version bump — you
> **must** resync both locks or the `--locked` CI jobs fail with "the lock file
> needs to be updated":
>
> ```bash
> cargo build --manifest-path tests/chaos/Cargo.toml
> cargo build --manifest-path tests/property/Cargo.toml
> ```
>
> Commit the regenerated `Cargo.lock` files alongside your change.

### Deterministic decoder-fuzz harnesses

Untrusted-input decoders carry in-tree, **deterministic** fuzz harnesses (plain
`cargo test` targets seeded with fixed RNG — not `cargo-fuzz`, so they run in CI
on every platform). They live next to the decoder they guard:

- `spt-snmp/tests/fuzz_ber.rs`, `fuzz_decoders.rs` — BER/SNMP length arithmetic.
- `spt-ssh3/tests/fuzz_h3.rs` — HTTP/3 + SSH3 frame parsing.
- `spt-obfs/tests/fuzz_decoders.rs`, `fuzz_obfs.rs`, `framing_negatives.rs` — obfuscation framing.
- `spt-trust/tests/fuzz_known_hosts.rs` — `known_hosts` parsing.
- `spt-ftp-translator/tests/fuzz_verbs.rs` — FTP verb parsing.

When you add or modify a decoder for attacker-reachable bytes, extend the
matching harness. These pair with the `overflow-checks = true` release profile
to catch the silent-wrap DoS class.

### Data-plane regression suite

Byte-for-byte forwarding correctness is covered by data-plane regression tests,
e.g. `spt-forward/tests/dataplane_bidir.rs`, `token_bucket_edges.rs`,
`spt-ssh2/tests/ssh2_dataplane.rs`, `spt-obfs/tests/meek_dataplane.rs` /
`obfs_gauntlet.rs`. Workspace-level end-to-end scenarios live in the
`spt-e2e-tests` member under `tests/e2e/` (each file wired via an explicit
`[[test]]` entry), covering reconnect, keepalive, multi-forward, UDP hops,
remote-config reload, and sealed-config tunnels. Additional harnesses live in
`tests/conformance`, `tests/openssh-interop`, `tests/stress`, and the
`#[ignore]`'d perf benches under `tests/perf-recovery` / `tests/perf-startup`.

### Capturing tracing output in tests (parallel-safe)

Do **not** install a global subscriber in tests — that races across the shared
process. Use `spt-observability`'s `testing` fixtures: `CapturingLayer` records
every `tracing::Event` into a shared `Vec`, and `with_capturing_subscriber`
installs it as the **thread-local** default via `tracing::subscriber::with_default`,
scoped to the closure. This keeps assertions on emitted spans/fields correct
even when the rest of the suite runs in parallel:

```rust
use spt_observability::testing::with_capturing_subscriber;

let events = with_capturing_subscriber(|layer| {
    do_the_thing();
    layer.events()
});
assert!(events.iter().any(|e| e.target.starts_with("spt_")));
```

### Local pre-push gate

Run these three before every push — they are the same gates CI applies (and
`fmt` runs first in CI, skipping everything downstream on failure):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test
```

Clippy is `pedantic`-level workspace-wide (with a curated allow-list in the root
`Cargo.toml`) and warnings are denied — treat a clippy warning as a build break.

## 5. CI/CD

Everything is in `.github/workflows/`. The main pipeline (`ci.yml`) runs on
push/PR to `main`:

| Job | Gate? | What it does |
|-----|-------|--------------|
| `fmt` | yes | `cargo fmt --all -- --check`. Fast style gate; runs first. |
| `clippy` | yes | `cargo clippy --workspace --all-targets --locked -- -D warnings`, pinned at MSRV. |
| `typecheck` | yes | `cargo check --workspace --locked`; fast type feedback in parallel with fmt/clippy. |
| `all-features` | yes | `clippy` + `test` with `--all-features` on Linux — the guard against feature-gated rot. |
| `chaos` | no (`continue-on-error`) | PR-gating chaos subset; flaky runs surface amber, never block. |
| `property` | yes | The property invariant suite; fast and deterministic, so it gates. |
| `prepare-release` | — | Computes the next `YY.N` once, bumps `Cargo.toml`/`Cargo.lock`, shares them as an artifact. |
| `test (× matrix)` | yes | Full test matrix across 5 native `OS×arch` targets (`x86_64`/`aarch64` Linux, `aarch64` macOS, `x86_64`/`aarch64` Windows), `--locked`, single-threaded. |
| `build (× matrix)` | yes | Release compile per target; uploads the raw binary. |
| `package (× matrix)` | yes | Turns each binary into tarball/deb/rpm/pkg/zip/msi. |
| `release` | main-only | Cuts the rolling release, tags, pushes the bump commit, publishes GitHub release + multi-arch GHCR image. |
| `pkg-*` | per-recipe | Homebrew/Scoop/Choco/Snap/Flatpak/AUR/Winget/Nix manifest smoke tests. |

Separate workflows:

- **`audit.yml`** — weekly `cargo audit` (Mondays) + manual dispatch. **Non-gating**: it opens/updates a tracking issue rather than failing a check. One accepted-risk suppression (`RUSTSEC-2023-0071`, the `rsa` Marvin timing oracle — unreachable because `spt` only uses RSA for signing/verification, never decryption).
- **`docs.yml`** — builds this mdBook (`docs-book/`) with a pinned mdBook and deploys to GitHub Pages on pushes that touch `docs-book/**`.
- **Docker** — folded into the `release` job of `ci.yml` (multi-arch buildx push to `ghcr.io/<owner>/spt`).

### Releases & branching

Releases are **rolling `26.x`** (encoded in Cargo as `0.26.N`; public tags drop
the `0.` → `v26.N`). CI **auto-cuts a release on every green push to `main`**:
the `release` job pushes a `release: <tag> [skip ci]` bump commit and tag. That
`[skip ci]` token is what stops the bump commit from re-triggering CI into an
infinite release loop — it is the **only** legitimate use of a skip token; do
not add `[skip ci]`/`[skip release]` to your own commits. **Branching is not
used**: development is main-only, so every merged change ships.

## 6. Contributing workflow

1. Work against `main` (no long-lived branches).
2. Keep changes crate-scoped; add a module rather than bloating a file.
3. Run the [pre-push gate](#local-pre-push-gate): `fmt`, then `clippy` (denied
   warnings), then `test`. If you touched feature-gated code, also run
   `--all-features`.
4. If you changed a main-graph crate or dependency, **resync the chaos and
   property `Cargo.lock`s** and commit them ([§4](#4-testing)).
5. Prefer conventional-commit-style messages (`fix(tui): …`, `refactor(config): …`,
   `feat(events): …`) — matching the existing history.
6. **Don't add dependencies casually.** The weekly `audit` job scans the
   committed `Cargo.lock`; a new dep is new advisory surface and new MSRV risk.
   Targeted `cargo update -p <crate>` for a security fix belongs in its own PR
   with a green build/clippy/test gate — never silently.
7. Never bypass hooks or the gates; if a gate is red, fix the cause.

## 7. Extending spt

These recipes are conceptual and point at the crate boundaries you actually
touch. Read the neighbouring modules in the target crate before starting —
each crate already has an established pattern to follow.

### Add a new event sink

Sinks live in `spt-events/src/sinks/`. Implement the sink over the crate's
dispatcher/bus abstractions (`bus.rs`, `dispatcher.rs`, `event.rs`), wire it
into the sink registry, and honour the binding evaluator (`binding.rs`) and
template rendering (`template.rs`). Add the config surface in `spt-config`
(see the config-option recipe below) and make sure output passes through
redaction. Network-backed sinks (email/WebPush) sit behind the `transports`
feature — keep new external transports feature-gated the same way.

### Add a new auth method

Auth method types and validation live in `spt-auth` (`method.rs`,
`validate.rs`, with per-method modules like `totp.rs`, `kbi.rs`,
`oidc_device_flow.rs`, `yubikey_oath.rs`). Add the method variant + its
validation, reference secrets symbolically via `secret_ref.rs` (never inline
plaintext), and wire the protocol-agnostic type through to the transport that
performs the exchange (`spt-ssh2` / `spt-ssh3`). GSSAPI/SSPI/Kerberos providers
live separately in `spt-auth-sspi`. Gate anything that pulls a heavy dep (e.g.
`yubikey`) behind a feature.

### Add a new transport or obfuscation

A tunnel backend implements the adapter trait(s) in `spt-protocol` (the same
contract `spt-ssh2` and `spt-ssh3` satisfy). An **obfuscation** layer instead
implements `ObfsTransport` in `spt-obfs` and is constructed through
`transport_for(&ObfsConfig)`; add the on-wire framing with a matching
`tests/fuzz_*.rs` negative/decoder harness and a `*_dataplane` regression test.
Either way, add the config surface and route address/bind handling through
`spt-net`.

### Add a new config option

This is a multi-step, cross-crate change — do all of it or the build breaks:

1. **Schema** — add the field to the relevant struct in `spt-config/src/schema.rs`
   with a serde default.
2. **Validate** — extend `spt-config/src/validate.rs` so invalid combinations are
   caught at load time (fail-closed; return a blocking diagnostic, not a panic).
   Add `migrate.rs` handling if the change affects the config `version`.
3. **Render/diff** — make sure `render.rs` and `diff.rs` round-trip the new
   field (there's a property invariant asserting TOML round-trip).
4. **Wire the consumer** — thread the value into the crate that acts on it
   (supervisor, a forward, a transport, a sink, …).
5. **Document** — add it to the [Configuration Reference](configuration-reference.md).
6. **Update the chaos build** — `tests/chaos` constructs config/spec literals
   directly. Adding a **required** field to a config struct breaks its compile,
   and a `--workspace` sweep won't catch it because chaos is an excluded
   sub-workspace. Build it explicitly:
   `cargo build --manifest-path tests/chaos/Cargo.toml`, then resync its lock.

## 8. Security invariants

These are non-negotiable. A change that weakens one should be treated as a
regression regardless of what else it does. See [Security](security.md) for the
full threat model.

- **No secret ever reaches logs, `Debug`, or any output sink.** Resolved secrets
  are wrapped in zeroizing types (`secrecy::SecretBox<Zeroizing<…>>`); string
  fields that may carry sensitive data use `spt-core`'s `RedactedString`. Every
  text output path (logs, events, MCP responses, diagnostic bundles, metrics)
  passes through `spt_core::redaction` before bytes leave the process. Never
  derive a plain `Debug` that prints secret bytes.
- **Constant-time trust comparisons.** Host-key / pin / CRL / TLS-pin checks in
  `spt-trust` (`known_hosts.rs`, `sha256_pin.rs`, `crl.rs`, `tls_pin.rs`) use
  `subtle` constant-time equality. Do not replace them with `==` on secret- or
  trust-material bytes.
- **Fail-closed validation.** Config validation blocks on error and defaults to
  the safe/off state (e.g. the updater ships `enabled = false`, `mode = "off"`,
  `require_minisign = true`). New options must default closed and reject invalid
  input at load time rather than degrading silently at run time.
- **Argv-only command sink — no shell.** External commands (post-install hooks,
  scripts, etc.) are executed via `std::process::Command` with explicit
  arguments and **no** shell interpretation. Never build a command string and
  hand it to a shell.
- **Sandboxed scripting.** Scripting hooks run through `spt-scripting`'s
  sandboxed Rhai engine (bounded, no ambient filesystem/network/process access).
  Do not add host functions that widen that sandbox without an explicit,
  reviewed capability gate.
