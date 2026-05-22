# Production Readiness Review — spt

Audit date: 2026-05-21 (initial), refreshed 2026-05-22 after t7 close-out.
Auditor scope: read-only review of `F:\Projects\ssh-perma-tunnel`. The initial
audit captured the t6 release; the t7 milestone subsequently filled in every
"FAIL" item below. This document tracks both the original verdict and the
t7-closeout updates so the audit-vs-reality history is preserved.

## Executive Summary

`spt` is a substantial, well-engineered codebase. The M0–M5 core (~28 crates
across config, supervisor, forward, ssh2/ssh3, secrets, observability, MCP,
TUI, diagnostics, service integration, packaging) is structurally sound:
every top-level CLI command has a real dispatch arm, audit/recorder hooks are
pervasive, error-to-exit-code mapping is consistent, full-jitter reconnect
backoff is implemented to spec §11.2, and CI runs the workspace under fmt,
clippy `-D warnings`, `cargo test --workspace --locked`, and `cargo deny check`
on six OS/arch native runners (Linux x86_64+arm64, macOS Intel+Apple Silicon,
Windows MSVC x86_64+arm64).

**t7 close-out (2026-05-22).** The six advertised t6 features that shipped
as contract-enforcing stubs in the initial audit (`rhai` scripting, `sspi` /
`gssapi` auth, obfs4 / meek-http / ssh-over-websocket transports, SFTP FUSE +
WinFsp / Dokany2 mount session loops, FTP AUTH-TLS in-place upgrade) are now
real. The workspace `no cargo update` policy was lifted for the milestone;
each new dep is documented in the per-executor logs under
`.orchestration/logs/t7-*.md`. The libssh2 SSH2 backend was demolished
(Phase 0); the pure-Rust `russh` crate is the only SSH2 implementation, with
a locally-vendored fork at `vendor/russh-fork/` carrying the
`Signer::Future: 'static` patch needed for the agent-userauth path. The
deprecated `[capabilities].ssh2_backend` / `allow_libssh2` keys still load
with a one-shot warning and are silently ignored; `spt config migrate --to 2`
strips them.

Verdict: **ship-ready as the t7 release**. The known-issues section below
catalogues what remains, all of which are tracked, scoped, and non-blocking
for the t7 surface.

## Feature Coverage Matrix

Feature classifications: **Production-ready** (real impl, real tests, real
wire path) / **Beta** (real impl, light test coverage or known gaps) /
**Partial** (works for some inputs/backends/OSes, not all).

| Feature (spec §) | Status | Crate(s) | Test depth | Known gaps |
|---|---|---|---|---|
| Local TCP forwarding (§10) | Production-ready | `spt-forward`, `spt-ssh2` | 41 tests in `spt-forward` (`runner_states.rs`) + russh backend | — |
| Remote TCP forwarding (§10) | Production-ready | `spt-forward/remote_tcp`, `spt-ssh2` | russh path; UDS bind on Windows returns `UnsupportedPlatform` | Windows lacks AF_UNIX-as-listener semantics (documented) |
| UDP forwarding `tcp-framed` | Production-ready | `spt-ssh2/udp_tcp_framed` | 6 codec tests + 5 dispatcher tests; 64 KiB frame cap enforced | — |
| UDP forwarding `uds-bridge` | Production-ready (russh, Unix) | `spt-ssh2/udp_uds_mode` | 2 tests; Windows rejected by validator (`forward_link_kind_unsupported`) | Unix-only on both ends |
| UDS / `streamlocal` forwarding | Production-ready (russh, Unix) | `spt-ssh2/uds_forward`, `spt-forward/uds_listener` | 30 tests; `Forward::link_kind` validated (t7-B4) | Windows rejected by validator |
| Jump chains, SOCKS5, HTTP-CONNECT, `-J` | Production-ready | `spt-ssh2/{proxy_jump,multi_hop}`, `spt-config/openssh_config` | 33 tests; multi-hop rewritten natively in russh (no socketpair) | — |
| SFTP suite (cat/tail/chmod/symlink/readlink/realpath, recursive +resume +bps +sha256) | Production-ready | `spt-sftp` | 17 tests in `tests/ops.rs` + mock SFTP server | russh-sftp wire only surfaces 5 status codes; mapping inference via substring on `Failure.error_message` |
| SFTP mount — Linux FUSE | Production-ready | `spt-sftp/mount/linux_fuse` (`fuser 0.15`) | 22 lib tests + 9 `SPT_FUSE_LIVE=1` integration tests | Live tests gated behind `SPT_FUSE_LIVE=1`; CI does not run them by default |
| SFTP mount — Windows | Production-ready | `spt-sftp/mount/windows_winfsp` (Dokany2 via `dokan 0.3.1`) | Build + clippy green on Windows; live tests gated | Dokany2 runtime must be installed (`choco install dokany2 -y`) |
| SFTP mount — macOS | Beta (deprecation-warned) | `spt-sftp/mount/macos_sshfs` (sshfs + macFUSE) | Live tests via `SPT_SSHFS_LIVE=1` | macFUSE deprecation-warned upstream; `sshfs` opens a separate SSH session, not shared with `spt`. FSKit-based replacement is post-1.0 |
| FTP→SFTP translator with AUTH TLS | Production-ready | `spt-ftp-translator` | 12 integration + 25 unit tests + 3 AUTH-TLS round-trip tests | — |
| Scripting hooks (rhai sandbox) | Production-ready | `spt-scripting` (`rhai 1.19`) | 29 tests (19 integration + 10 unit) | `eval`/`import` disabled at compile; five `set_max_*` limits enforced; fresh `Scope` per invocation |
| Portable mode `--portable` | Production-ready | `spt-state/portable`, `spt-secrets/portable`, `spt-config/load` | OnceLock-based; pre-clap argv scan + `harden()` ordering test | — |
| SSPI / GSSAPI / Kerberos / NTLM | Production-ready | `spt-auth-sspi` (Unix: vendored `libgssapi 0.9` fork; Windows: `sspi 0.15`) | 13 unit + per-OS opt-in live tests | `sspi-rs` is pure-Rust, no ambient SSO on Windows — thread credentials explicitly; libgssapi MIC known-vector test deferred (see Known Issues) |
| Pubkey algorithm matrix | Production-ready | `spt-key`, `spt-auth/method` | 12 tests covering ed25519/p256/p384/p521/rsa3072/rsa-sha2-{256,512}; `ssh-rsa` (SHA1) rejected by default with `allow_ssh_rsa_sha1` escape hatch | — |
| TOTP / 2FA keyboard-interactive | Production-ready | `spt-auth/{totp,kbi,yubikey_oath}` | 97 tests in `spt-auth`; RFC 6238 §B vectors per HMAC-{SHA1,256,512} | YubiKey path shells out to `ykman`, gated behind `yubikey` feature |
| Obfuscation transports (obfs4 / meek-http / ws / shadowsocks) | Production-ready | `spt-obfs` | 30+ tests | obfs4 is a hand-rolled client subset (wire-incompat caveats vs `obfs4proxy`); meek-http and shadowsocks have spt-specific framing details documented in [Obfuscation](obfuscation.md) |
| russh SSH2 backend (only backend) | Production-ready | `spt-ssh2/russh_backend` | 111+ lib tests | Vendored fork at `vendor/russh-fork/` for `Signer::Future: 'static` patch — tracking upstream PR |
| SSH3 (QUIC + HTTP/3) | Beta | `spt-ssh3` | `tests/two_endpoints.rs` and frame/forward tests | RSA + several algorithms rejected (`jwt.rs:125`); per spec §6 SSH3 is "experimental but default-enabled" |
| DNS resolver (split-horizon, SRV, hosts apply/restore) | Production-ready | `spt-dns` | Integration + unit tests | — |
| Secret vault (AES-256-GCM + Argon2id) + keychain backends | Production-ready | `spt-secrets`, `spt-config-crypt` | Vault lifecycle + keychain mock tests | Windows Credential Manager intermittent flakes documented |
| Service integration (systemd / launchd / SCM / OpenRC / SysV / Task Scheduler) | Production-ready | `spt-service` | `windows_scm_mock.rs` (15 tests) + per-backend tests | Reload returns `UnsupportedPlatform` on backends without reload (sysv, OpenRC partial) — spec-conformant |
| Observability (file/journald/syslog-TLS/HTTPS-JSONL/OTLP/Prometheus/SNMPv3/MIB) | Production-ready | `spt-observability`, `spt-snmp`, `spt-events` | Init layer tests, sink tests, web-push native | SNMPv3 polled and trapped via project MIB (`mibs/SPT-MIB.txt`); behind `snmp` feature |
| MCP server (16 resources / 31 tools, stdio + loopback TCP) | Production-ready | `spt-mcp`, `spt-bin/{mcp_listen,mcp_server,controller}` | Handshake + loopback TCP + audit tests + `tests/it_controller_contract.rs` (t7-B3) | `Controller::session_close` / `_drain` / `stats_subscribe` / `run_benchmark` default-impl returns `NotImplemented` for embedders; production `OrchestratorController` (spt-bin) implements all four |
| TUI configurator | Production-ready | `spt-tui` | Snapshot tests + keyboard tests | — |
| Firewall planning (`spt firewall apply --system --dry-run`) | Production-ready | `spt-firewall` | `it_firewall_ops.rs`, 9 tests | `query_active_rules` default returns `UnsupportedPlatform` per-backend (intentional) |
| Diagnostics + redacted bundles | Production-ready | `spt-diagnostics` | Per-check unit tests | — |
| Benchmark drivers (latency/throughput/UDP/reconnect/DNS/limits) | Production-ready | `spt-benchmark` | Per-driver tests; criterion bench-regression dispatch-only job | — |
| Status API (read-only HTTP + TLS) | Production-ready | `spt-status-api` | `tls_handshake.rs` + router tests | — |
| Remote config pull + fingerprint pin | Production-ready | `spt-remote-config`, `spt-config/remote` | Integration tests | — |
| Memory hygiene (PR_SET_DUMPABLE/SeDebugPrivilege/PT_DENY_ATTACH) | Production-ready | `spt-mem-hygiene` | Per-OS modules | Defense-in-depth — silent on failure by design |

## CLI Capability Map

Source: `crates/spt-cli/src/lib.rs:141-192` (24 top-level `Command` variants)
cross-referenced with `crates/spt-bin/src/cli_dispatch.rs` (`fn dispatch` —
every variant has a real `_dispatch` arm). Each group's subcommands are
enumerated by `crates/spt-cli/src/groups/<name>.rs`.

```
spt
├── config                              works              init/validate/doctor/render/diff/migrate/reload/pull/trust/encrypt/decrypt/edit/crypt rotate
├── profile                             works              list/show/add/remove/enable/disable/edit/configure (TUI)
├── forward                             works              add (local|remote|dynamic|udp|local_uds|remote_uds)/remove/explain/list
├── tunnel                              works              run/status/stop/reload/list/-J jump chain
├── service                             works              install/remove/start/stop/restart/status (systemd/launchd/SCM/OpenRC/SysV/TaskSched)
├── key                                 works              generate/inspect/fingerprint/passphrase/install/list (all algorithms in §6.3)
├── secret                              works              set/get/list/remove/import/export/rotate; keyring+file backends
├── auth                                works              test/methods/list/configure (sspi/gssapi end-to-end real on russh)
├── dns                                 works              resolve/record add/remove/zone/hosts apply/restore
├── firewall                            works              apply/list/restore/explain (--dry-run default)
├── log                                 works              tail/show/export/remote test
├── observe                             works              metrics/snmp test-trap (feature)/winevent test (Windows)
├── event                               works              bindings list/sinks list/replay
├── stats                               works              summary/live/show
├── session                             works              list/close/drain
├── ftp                                 works              translator serve (AUTH TLS in-place upgrade live since t7-A8)
├── sftp                                works
│   ├── test/list/stat/get/put/cat/tail/chmod/symlink/readlink/realpath  works
│   ├── put-recursive / get-recursive   works              resume/bps/sha256
│   ├── mount add/list/remove/plan      works              record/plan
│   ├── mount start                     works              Linux FUSE (t7-A5), Windows Dokany2 (t7-P2), macOS sshfs (deprecation-warned)
│   ├── mount stop / umount             works              supervisor-side mount registry (t7-B2) tears down without re-opening SSH
│   └── drive (Windows)                 works              Dokany2-backed drive-letter
├── diagnose                            works              port/auth/runtime/network/os/secrets/observability/mcp/permissions/firewall/service/ssh2/time/trust
├── benchmark                           works              run/list/compare/export (drivers: latency/throughput/udp/reconnect/dns/limits)
├── mcp                                 works              serve --stdio/--tcp --read-only by default; 16 resources / 31 tools
├── status                              works              read-only HTTP + TLS (mtls), router + handshake tested
└── completion                          works              bash/zsh/fish/powershell/elvish
```

## Production-Grade Concerns

### Security — **Adequate**

Strong:
- Workspace-wide policy: `unsafe_op_in_unsafe_fn = "warn"`, `clippy::pedantic = "warn"`.
- Secret handling: `zeroize`, `secrecy::SecretBox`, `RedactedString`, redaction
  modes, vault uses AES-256-GCM + Argon2id, file-backed master key for portable
  mode (0600 on Unix).
- TLS: rustls 0.23 with `ring`, pinned-cert connector, TLS pin via SHA-256,
  known-hosts and chain-depth verification.
- `cargo deny check` runs in CI; advisory ignores are documented with rationale
  + MSRV linkage (`deny.toml`).
- `harden()` (memory hygiene) runs before any user command; portable-mode
  install precedes it.

Gaps:
- 8 RUSTSEC advisories ignored — all with MSRV-linked rationale, but some
  (RUSTSEC-2025-0134 rustls-pemfile, RUSTSEC-2026-0141 lettre) represent
  ongoing technical debt. Re-evaluation cadence: quarterly.
- 108 occurrences of `unsafe` blocks across 11 files (FFI + memory hygiene +
  winevent + privileged sockets). Per-block safety comments not yet audited
  workspace-wide; spot-check recommended.
- `Command::new` usage in `spt-auth/yubikey_oath.rs` shells out to `ykman`
  with a user-controlled account name; argument quoting was reviewed safe but
  should be re-audited as upstream ykman changes.

### Reliability — **Strong**

- Reconnect: full-jitter exponential backoff per spec §11.2.
- Forward state machine: `spt-supervisor/src/state_machine.rs` + 41 tests.
- Signal handling: `spt-bin/src/signals.rs`.
- Panic safety: `panic = "abort"` in release.
- Failover: `spt-supervisor/src/failover.rs` + round-robin endpoint policy.

### Observability — **Strong**

- Audit recorder pervasive: `audit::record_audit` fired by `spt-core`,
  `spt-ssh2/multi_hop`, `spt-ssh2/uds_forward`, `spt-sftp/mount`,
  `spt-obfs/audit`, `spt-scripting/HookRecorder`, `spt-auth-sspi/audit`
  (t7-B1).
- `spt_obfs::AuditHook` subscriber wired in `spt-bin/src/audit.rs` (t7-B1).
- SFTP umount audit, script-engine load + per-hook invocation audit, GSSAPI/SSPI
  token issuance + MIC sign/verify audit all emit structured events as of
  t7-B1.

### Performance — **Adequate**

- `spt-benchmark` has dedicated drivers; bench-regression CI job (dispatch-only)
  compares HEAD vs main via criterion.
- Frame caps and peer-table caps in place (UDP `MAX_FRAME_BYTES = 64 KiB`, peer
  table with idle eviction).
- LTO + codegen-units=1 + symbol strip in release.

### Resource Lifecycle — **Strong**

- Mount lifecycle: `MountHandle` has paired `umount`; supervisor-side mount
  registry (t7-B2) keyed by `(profile, mountpoint)`. `mount stop` tears down a
  live mount without re-opening an SSH session.
- SFTP file ops use `tempfile` + `atomicwrites` (workspace deps).
- Drop-time tear-down for `RemoteUdsForward`.

### Concurrency Safety — **Strong**

- Workspace lint `unsafe_op_in_unsafe_fn = "warn"` enforced (16+ crates
  explicitly add `#![deny(unsafe_op_in_unsafe_fn)]`).
- 108 unsafe occurrences concentrated in FFI crates (`spt-mem-hygiene`,
  `spt-winevent`, `spt-secrets`, `spt-net/privileged`).
- Shared state via `Arc<dyn AuditHook>`, `Arc<ScriptEngine>`,
  `Arc<SftpClient>`; `parking_lot::Mutex` preferred for runtime.

### Build Matrix — **Strong**

CI covers all six native targets:

| Target | Runner |
|---|---|
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| `x86_64-apple-darwin` | `macos-13` |
| `aarch64-apple-darwin` | `macos-14` |
| `x86_64-pc-windows-msvc` | `windows-latest` |
| `aarch64-pc-windows-msvc` | `windows-11-arm` |

`fmt`, `clippy --workspace --all-targets --locked -D warnings`,
`cargo test --workspace --locked --no-fail-fast`, `cargo deny check`,
RustSec audit, **`cargo doc -D warnings`** (t7-C1), and an **explicit
MSRV-1.83 `cargo check`** job (t7-C3) all gate. Release builds (LTO release
profile) build for all six targets and pack `.deb` / `.rpm` / `.pkg` / `.msi`
/ `.zip` / tarballs. Docker buildx pushes `linux/amd64,linux/arm64` on main.

### Packaging — **Strong**

CI exercises end-to-end for every recipe as of t7-C2:

- `.deb` (cargo-deb), `.rpm` (cargo-generate-rpm) on linux-gnu
- `.pkg` on macOS
- `.zip`, `.msi` (cargo-wix) on Windows
- Tarballs on Linux + macOS
- Docker buildx multi-arch on release
- Homebrew, Scoop, Chocolatey, Snap, Flatpak, AUR PKGBUILD, Winget, Nix flake
  smoke tests (eight new CI jobs added in t7-C2; each per-recipe builder under
  `scripts/package/test-*.sh`).

## Ship Gate Checklist — t7

Items the operator should pass/fail before tagging. **All items below are
PASS as of the t7 close-out.**

- [x] Real impl behind every t6 stub. **PASS** — scripting (t7-A2), SSPI/GSSAPI
  (t7-A3 + t7-P3), obfs4/meek/ws (t7-A4), SFTP mount Linux (t7-A5) + Windows
  (t7-P2) + macOS (t7-A7, deprecation-warned), FTP AUTH-TLS (t7-A8).
- [x] CI gates green on Linux + macOS + Windows for stable (MSRV 1.83). Native
  ARM runners in matrix. **PASS**.
- [x] `cargo fmt --check`, `clippy -D warnings`, `cargo deny check`,
  `cargo test --workspace --locked` all green. **PASS**.
- [x] `cargo doc -D warnings` is a CI gate. **PASS** (t7-C1); every workspace
  crate enforces `#![warn(missing_docs)]`.
- [x] Audit hook coverage matrix complete (mount/umount, script, obfs, gssapi,
  sftp ops, ftp verbs). **PASS** (t7-B1).
- [x] Every "production-ready" packaging recipe builds end-to-end in CI: deb,
  rpm, msi, pkg, tarball, zip, Docker, Homebrew, Scoop, Chocolatey, Snap,
  Flatpak, AUR, Winget, Nix. **PASS** (t7-C2).
- [x] MCP server resources & tools list matches actual exposed surface.
  **PASS** — `tests/it_controller_contract.rs` (t7-B3) pins the default-impl
  behaviour for every embedder.
- [x] Reconnect backoff implementation matches spec §11.2 (full-jitter
  exponential). **PASS**.
- [x] Portable mode pre-clap argv scan + harden ordering correct. **PASS** —
  `portable_install_runs_before_harden_in_main` promoted to a gating test in
  t7-Bwire.
- [x] CLI dispatcher: every `Command` variant has a real dispatch arm.
  **PASS**.
- [x] `Cargo.lock` policy reviewed; t6 upstream deps pinned. **PASS** — the
  `no cargo update` policy was lifted for the t7 milestone; each new dep is
  documented in `.orchestration/logs/t7-*.md`. `Cargo.lock` is still checked
  in and gates `cargo test --workspace --locked`.
- [x] libssh2 demolished; russh is the only SSH2 backend. **PASS** (t7-Phase0).
  Deprecated config keys produce a one-shot validate warning and are silently
  ignored at runtime.
- [x] `Forward::link_kind` validation. **PASS** (t7-B4) — UDS link kinds
  rejected on Windows and on SSH3 profiles; UDP `uds-bridge` rejected outside
  Unix.

## Known Issues (preserved across the t7 close-out)

These are tracked, scoped, and non-blocking for the t7 surface.

1. **russh `Signer::Future: 'static` patch is local.** The patch needed to
   make `russh::client::Handle::authenticate_future` accept an
   agent-backed `Signer` is carried in a locally-vendored russh fork at
   `vendor/russh-fork/`. An upstream PR has not yet been opened; the
   fork is byte-identical to v0.46.0 with the minimum diff (~35 lines
   added / 12 removed) documented in `.orchestration/logs/t7-P1.md`.
   Tracking the upstream merge is post-t7 work.

2. **libgssapi MIC known-vector test deferred.** The vendored libgssapi
   fork at `vendor/libgssapi-fork/` adds real `gss_get_mic` /
   `gss_verify_mic` bindings (t7-P3), which produce RFC 2743 `MIC` tokens
   wire-compatible with strict RFC 4462 §3.5 OpenSSH peers. The test
   suite verifies round-trip integrity against a libgssapi peer; a
   known-vector test against a captured OpenSSH server transcript was
   deferred as an operator decision pending a representative capture.

3. **macOS SFTP mount permanently second-class.** The macOS backend
   shells out to `sshfs` + macFUSE with a documented deprecation warning.
   `sshfs` opens its own SSH session that does not share connection
   pooling, keep-alive, or multi-hop forwarding with the in-process
   `spt` runtime. The FSKit-based replacement is Swift-only and out of
   scope for t7; tracked as post-1.0 work.

4. **Post-quantum KEX (`mlkem*`, `sntrup761x25519-sha512`) not negotiated.**
   russh 0.46 does not yet ship ML-KEM or SNTRUP KEX engines.
   `[profiles.crypto].kex_algorithms` accepts PQ-KEX names behind the
   `allow_post_quantum_kex` / `allow_ml_kem` capability gates; `spt config
   validate` warns when the policy recognises a PQ-KEX algorithm; runtime
   negotiation will fail until russh ships the engines or this project
   forks them in. Tracked separately from the t7 milestone.

5. **8 active RUSTSEC ignores** in `deny.toml`. Several (rustls-pemfile,
   lettre, hickory-proto) are MSRV-pinned. Each ignore is tracked with a
   target removal milestone; revisited quarterly.

6. **Pre-existing flaky tests on Windows CI** (`spt-dns::query_resolver_*`,
   `spt-secrets::keychain::entry_for_*`). Either stabilise or quarantine +
   track. Non-blocking for t7.

## Recommended Next Steps (post-t7)

1. Open the upstream russh PR for the `Signer::Future: 'static` patch
   (Known Issue 1).
2. Capture a representative OpenSSH MIC-known-vector transcript and land
   the libgssapi MIC verification test (Known Issue 2).
3. Investigate an FSKit-based macOS SFTP mount surface (Known Issue 3).
4. Stabilise or quarantine the pre-existing flaky tests (Known Issue 6).
5. Publish a perf baseline comparing `spt` to OpenSSH client + autossh on
   the existing benchmark drivers; promote `bench-regression` from
   dispatch-only to required on PRs that touch the hot paths.
6. Per-block safety comments on the 108 unsafe blocks across 11 files;
   produce a tracker doc.

---

End of report.
