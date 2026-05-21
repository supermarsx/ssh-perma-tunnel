# Production Readiness Review — spt

Audit date: 2026-05-21. Auditor scope: read-only review of `F:\Projects\ssh-perma-tunnel` at HEAD `863ed5c`. No code was modified.

## Executive Summary

`spt` is a substantial, well-engineered codebase. The M0–M5 core (~28 crates across config, supervisor, forward, ssh2/ssh3, secrets, observability, MCP, TUI, diagnostics, service integration, packaging) is structurally sound: every top-level CLI command has a real dispatch arm, audit/recorder hooks are pervasive, error-to-exit-code mapping is consistent, full-jitter reconnect backoff is implemented to spec §11.2, and CI runs the workspace under fmt, clippy `-D warnings`, `cargo test --workspace --locked`, and `cargo deny check` on six OS/arch native runners (Linux x86_64+arm64, macOS Intel+Apple Silicon, Windows MSVC x86_64+arm64).

The most recent milestone (`t6`) is the production-readiness liability. Six advertised t6 features ship as **contract-enforcing stubs** because workspace policy forbids `cargo update`, and the upstream crates required to deliver them are **absent from `Cargo.lock`** — verified directly: no entries for `rhai`, `sspi`, `cross-krb5`, `obfs4`, `tokio-tungstenite`, `blake3`, `fuser`, or `winfsp`. The stub pattern is honest at the trait/test layer but invisible at the CLI: `spt sftp mount add`, `spt ftp translator serve`, `[profiles.transport.obfuscation]`, `[profiles.auth].method = "sspi"`, `[profiles.script]` hooks, and obfuscation transports all parse successfully and only fail at run-time with `Error::UnsupportedPlatform` (exit 10). Critically, **SFTP mount fails on every platform regardless of feature flag** — the `mount-fuse` and `mount-winfsp` features compile but their `mount()` bodies still return errors (`linux_fuse.rs:55-63`, `windows_winfsp.rs:60`, launcher path `windows_winfsp.rs:85`).

Other ship blockers: the MCP `Controller` trait surfaces session/stats/benchmark methods that the default `NoopController` returns `NotImplemented` for (the production `OrchestratorController` *does* implement them, so this is a hazard for downstream embedders, not the binary); 19 of 35 crates do not enforce `#![warn(missing_docs)]`; several flaky tests (`spt-dns::query_resolver_*`, `spt-secrets::keychain::entry_for_*`) are documented as pre-existing; and the t6 follow-up list in `t6-Bwire.md` still has five open items (script-engine threading, FTP AUTH-TLS post-handshake split, supervisor-side mount registry, obfs audit subscriber wiring, portable-mode test pollution).

Verdict: **ship as 0.x with the t6 features explicitly marked experimental**, not 1.0-ready. Core unblocks 1.0 once the lockfile policy is revisited and the t6 stubs are either filled in or moved behind a `--features experimental` gate in the CLI.

## Feature Coverage Matrix

Feature classifications: **Production-ready** (real impl, real tests, real wire path) / **Beta** (real impl, light test coverage or known gaps) / **Stub** (contract-enforcing stub returning `UnsupportedPlatform` / `Other` until upstream dep lands) / **Partial** (works for some inputs/backends/OSes, not all).

| Feature (spec §) | Status | Crate(s) | Test depth | Known gaps |
|---|---|---|---|---|
| Local TCP forwarding (§10) | Production-ready | `spt-forward`, `spt-ssh2` | 41 tests in `spt-forward` (`runner_states.rs`) + russh + libssh2 backends | — |
| Remote TCP forwarding (§10) | Production-ready | `spt-forward/remote_tcp`, `spt-ssh2` | russh + libssh2 paths; `BindAddr::Unix` returns `UnsupportedPlatform` (libssh2/Windows) | libssh2 backend cannot do `BindAddr::Unix` (`remote_tcp.rs:43`) |
| UDP forwarding `tcp-framed` (§10, t6-e1) | Production-ready | `spt-ssh2/udp_tcp_framed` | 6 codec tests + 5 dispatcher tests; 64 KiB frame cap enforced | — |
| UDP forwarding `uds-bridge` (t6-e1) | Partial (russh only) | `spt-ssh2/udp_uds_mode` | 2 tests; libssh2 returns `UnsupportedPlatform` with stable tag | libssh2 backend unsupported by design |
| UDS / `streamlocal` forwarding (t6-e2) | Partial (russh only) | `spt-ssh2/uds_forward`, `spt-forward/uds_listener` | 30 tests (10 + 11 + 6 + 3) | libssh2 + Windows return `UnsupportedPlatform`; `Forward::link_kind` validation deferred to Bwire (`t6-e2.md:84-92`) |
| Jump chains, SOCKS5, HTTP-CONNECT, `-J` (t6-e3) | Production-ready | `spt-ssh2/{proxy_jump,multi_hop}`, `spt-config/openssh_config` | 33 tests; both proxy kinds verified against `tokio::io::duplex()` | — |
| SFTP suite (cat/tail/chmod/symlink/readlink/realpath, recursive +resume +bps +sha256) (t6-e4) | Production-ready | `spt-sftp` | 17 tests in `tests/ops.rs` + mock SFTP server | russh-sftp wire only surfaces 5 status codes; mapping inference via substring on `Failure.error_message` (`t6-e4.md:54-69`) |
| **SFTP mount (FUSE / WinFsp / sshfs)** (t6-e5) | **Stub — fails on every platform** | `spt-sftp/mount/{linux_fuse,windows_winfsp,macos_sshfs}` | 18 tests but every test asserts the failure path (`tests/mount.rs:76, 93, 110, 124`) | **Feature ON or OFF, `mount()` returns `Err`**: linux_fuse.rs:55-63 ("not yet wired"); windows_winfsp.rs:60 + :85 ("operator-gated"); macos_sshfs requires `SPT_SSHFS_BIN`. **CLI exposes `spt sftp mount add/start/stop` with no `experimental` flag.** |
| FTP→SFTP translator passive-only (t6-e6) | Beta | `spt-ftp-translator` | 12 integration + 25 unit tests, real rustls TLS via existing dep | AUTH TLS post-handshake split deferred — session closes after `234` reply rather than upgrading in place (`t6-e6.md:30-43`); supervisor-side `Ssh2SftpFactory` not wired (Bwire item 3) |
| Scripting hooks (rhai sandbox) (t6-e7) | **Stub** | `spt-scripting` | 25 tests against in-process stub interpreter | **`rhai` absent from `Cargo.lock`**; ships byte-count heuristic that mimics `max_operations` / `max_call_levels` enforcement but cannot run any actual scripts. `engine` feature gated off (`t6-e7.md:15-44`). |
| Portable mode `--portable` (t6-e8) | Production-ready | `spt-state/portable`, `spt-secrets/portable`, `spt-config/load` | OnceLock-based; pre-clap argv scan in `spt-bin/src/main.rs:52-70`, then `harden()` at :77 | Bwire still cites `OnceLock` pollution making child-process integration test harness deferred (`t6-Bwire.md:179`) |
| SSPI / GSSAPI / Kerberos / NTLM (t6-e9) | **Stub** | `spt-auth-sspi` | 19 tests against mock provider with deterministic key-XOR MIC | **`sspi`, `cross-krb5`, `libgssapi` all absent from `Cargo.lock`**. Every `provider_for` returns `UnsupportedBackend:`-prefixed `UnsupportedPlatform`. libssh2 cannot do `gssapi-with-mic` per RFC 4462 by design (`t6-e9.md:9-31`). |
| Pubkey algorithm matrix (t6-e11) | Production-ready | `spt-key`, `spt-auth/method` | 12 tests covering ed25519/p256/p384/p521/rsa3072/rsa-sha2-{256,512}; `ssh-rsa` (SHA1) rejected by default with `allow_ssh_rsa_sha1` escape hatch | — |
| TOTP / 2FA keyboard-interactive (t6-e12) | Production-ready | `spt-auth/{totp,kbi,yubikey_oath}` | 97 tests in `spt-auth`; RFC 6238 §B vectors per HMAC-{SHA1,256,512} | YubiKey path shells out to `ykman`, gated behind `yubikey` feature, unconditional `UnsupportedPlatform` otherwise (`yubikey_oath.rs`) |
| Obfuscation transports (obfs4 / meek-http / ws / shadowsocks) (t6-e13) | **Stub (3 of 4)** | `spt-obfs` | 32 tests, all assert the stub path; Shadowsocks AEAD framing is real | **`obfs4`, `tokio-tungstenite`, `blake3` absent from `Cargo.lock`**; Shadowsocks substitutes HMAC-SHA256 KDF for BLAKE3 (`shadowsocks.rs`). `ObfsTransport::connect` returns `UnsupportedPlatform` with `"Cargo.lock"` substring on every transport except Shadowsocks's framing-only tests. |
| russh SSH2 backend | Production-ready | `spt-ssh2/russh_backend` | 111+ lib tests | Agent + GSSAPI/SSPI auth return `UnsupportedPlatform` (`russh_backend.rs:384-393`) |
| libssh2 SSH2 backend (legacy lane) | Partial | `spt-ssh2` (default-off features per `ssh2 = { default-features = false }`) | Backend tests via `async-ssh2-lite` | UDS, UDP `uds-bridge`, dynamic SOCKS-with-russh-only ops, GSSAPI all unsupported |
| SSH3 (QUIC + HTTP/3) | Beta | `spt-ssh3` | `tests/two_endpoints.rs` and frame/forward tests | RSA + several algorithms rejected (`jwt.rs:125`); UDS forward unsupported (`forward.rs:88-104`); per spec §6 SSH3 is "experimental but default-enabled" |
| DNS resolver (split-horizon, SRV, hosts apply/restore) | Production-ready | `spt-dns` | Integration + unit tests | `query_resolver_*` documented as flaky on Windows CI (`t6-Bwire.md:155-157`) |
| Secret vault (AES-256-GCM + Argon2id) + keychain backends | Production-ready | `spt-secrets`, `spt-config-crypt` | Vault lifecycle + keychain mock tests | Windows Credential Manager intermittent flakes documented |
| Service integration (systemd / launchd / SCM / OpenRC / SysV / Task Scheduler) | Production-ready | `spt-service` | `windows_scm_mock.rs` (15 tests) + per-backend tests | Reload returns `UnsupportedPlatform` on backends without reload (sysv, OpenRC partial) — spec-conformant |
| Observability (file/journald/syslog-TLS/HTTPS-JSONL/OTLP/Prometheus/SNMPv3/MIB) | Production-ready | `spt-observability`, `spt-snmp`, `spt-events` | Init layer tests, sink tests, web-push native | SNMPv3 polled and trapped via project MIB (`mibs/SPT-MIB.txt`); behind `snmp` feature |
| MCP server (16 resources / 31 tools, stdio + loopback TCP) | Production-ready | `spt-mcp`, `spt-bin/{mcp_listen,mcp_server,controller}` | Handshake + loopback TCP + audit tests | `Controller::session_close` / `_drain` / `stats_subscribe` / `run_benchmark` default-impl returns `NotImplemented` for embedders; production `OrchestratorController` (spt-bin) implements all four |
| TUI configurator | Production-ready | `spt-tui` | Snapshot tests + keyboard tests | — |
| Firewall planning (`spt firewall apply --system --dry-run`) | Production-ready | `spt-firewall` | `it_firewall_ops.rs`, 9 tests | `query_active_rules` default returns `UnsupportedPlatform` per-backend (intentional) |
| Diagnostics + redacted bundles | Production-ready | `spt-diagnostics` | Per-check unit tests | — |
| Benchmark drivers (latency/throughput/UDP/reconnect/DNS/limits) | Production-ready | `spt-benchmark` | Per-driver tests; criterion bench-regression dispatch-only job | — |
| Status API (read-only HTTP + TLS) | Production-ready | `spt-status-api` | `tls_handshake.rs` + router tests | — |
| Remote config pull + fingerprint pin | Production-ready | `spt-remote-config`, `spt-config/remote` | Integration tests | — |
| Memory hygiene (PR_SET_DUMPABLE/SeDebugPrivilege/PT_DENY_ATTACH) | Production-ready | `spt-mem-hygiene` | Per-OS modules | Defense-in-depth — silent on failure by design |

## CLI Capability Map

Source: `crates/spt-cli/src/lib.rs:141-192` (24 top-level `Command` variants) cross-referenced with `crates/spt-bin/src/cli_dispatch.rs` (`fn dispatch` lines 65-92 — every variant has a real `_dispatch` arm). Each group's subcommands are enumerated by `crates/spt-cli/src/groups/<name>.rs`. To keep the map decision-useful rather than exhaustive, leaves are listed only where their status differs from the group default.

```
spt
├── config                              works              init/validate/doctor/render/diff/migrate/reload/pull/trust/encrypt/decrypt/edit/crypt rotate
├── profile                             works              list/show/add/remove/enable/disable/edit/configure (TUI)
├── forward                             works              add (local|remote|dynamic|udp)/remove/explain/list
│   └── add local/remote                works              russh + libssh2
│   └── add … --kind local_uds          partial (russh)    libssh2 + Windows = UnsupportedPlatform (spt-forward/uds_listener.rs:91)
│   └── add … udp (--udp-mode uds-bridge) partial (russh)  libssh2 = UnsupportedPlatform (udp_uds_mode.rs:42)
├── tunnel                              works              run/status/stop/reload/list/-J jump chain
├── service                             works              install/remove/start/stop/restart/status (systemd/launchd/SCM/OpenRC/SysV/TaskSched)
├── key                                 works              generate/inspect/fingerprint/passphrase/install/list (all algorithms in §6.3)
├── secret                              works              set/get/list/remove/import/export/rotate; keyring+file backends
├── auth                                works              test/methods/list/configure
├── dns                                 works              resolve/record add/remove/zone/hosts apply/restore
├── firewall                            works              apply/list/restore/explain (--dry-run default)
├── log                                 works              tail/show/export/remote test
├── observe                             works              metrics/snmp test-trap (feature)/winevent test (Windows)
├── event                               works              bindings list/sinks list/replay
├── stats                               works              summary/live/show
├── session                             works              list/close/drain
├── ftp                                 beta               translator serve (t6-e6 — AUTH TLS post-handshake split deferred)
├── sftp                                mixed
│   ├── test/list/stat/get/put/cat/tail/chmod/symlink/readlink/realpath  works
│   ├── put-recursive / get-recursive   works              resume/bps/sha256
│   ├── mount add/list/remove/plan      works              record/plan only
│   ├── mount start                     STUB ON ALL OS     linux_fuse.rs:55-63, windows_winfsp.rs:60+:85, macos_sshfs needs SPT_SSHFS_BIN
│   ├── mount stop / umount             works              idempotent no-op when nothing mounted
│   └── drive (Windows)                 STUB               same as mount start
├── diagnose                            works              port/auth/runtime/network/os/secrets/observability/mcp/permissions/firewall/service/ssh2/time/trust
├── benchmark                           works              run/list/compare/export (drivers: latency/throughput/udp/reconnect/dns/limits)
├── mcp                                 works              serve --stdio/--tcp --read-only by default; 16 resources / 31 tools
├── status                              works              read-only HTTP + TLS (mtls), router + handshake tested
└── completion                          works              bash/zsh/fish/powershell/elvish
```

Stub features that are reachable by the CLI but never advertised as experimental in `--help`:

* `spt sftp mount add` + `mount start` — fails on every platform.
* Top-level config keys `[profiles.transport]` (obfuscation) and `[profiles.script]` accepted by validate, fail at connect.
* `[profiles.auth].method = "sspi"` / `"gssapi"` accepted by validate, fails at connect with `UnsupportedBackend:` marker.
* `spt ftp translator serve` accepts `--bind` and `--pasv-range` but `translator_serve` returns `InvalidConfig` until Bwire wires `Ssh2SftpFactory` (`t6-e6.md:73-74`).

## Production-Grade Concerns

### Security — **Adequate, with gaps**

Strong:
- Workspace-wide policy: `unsafe_op_in_unsafe_fn = "warn"`, `clippy::pedantic = "warn"` (`Cargo.toml:283-288`).
- Secret handling: `zeroize`, `secrecy::SecretBox`, `RedactedString`, `redaction.rs` redaction modes, vault uses AES-256-GCM + Argon2id, file-backed master key for portable mode (0600 on Unix).
- TLS: rustls 0.23 with `ring`, pinned-cert connector (`spt-trust/pinned_connector.rs`), TLS pin via SHA-256 (`spt-trust/tls_pin.rs`), known-hosts and chain-depth verification.
- `cargo deny check` runs in CI; advisory ignores are documented with rationale + MSRV linkage (`deny.toml:11-19`).
- `harden()` (memory hygiene) runs before any user command (`spt-bin/src/main.rs:77`), portable-mode install precedes it (lines 54-70).

Gaps:
- `cargo audit` is also run in CI (`rustsec/audit-check@v2`), but **8 RUSTSEC advisories are ignored** — all with MSRV-linked rationale, but some (RUSTSEC-2025-0134 rustls-pemfile, RUSTSEC-2026-0141 lettre) are non-trivial and represent ongoing technical debt rather than dismissable.
- 108 occurrences of `unsafe` blocks across 11 files (FFI + memory hygiene + winevent + privileged sockets). `spt-mem-hygiene/src/{linux,macos,windows}.rs` and `spt-secrets/src/{secret_alloc,passphrase,mlock}.rs` are the hot zones. Per-block safety comments not audited here; spot-check recommended before 1.0.
- `Command::new` usage in `spt-auth/yubikey_oath.rs` shells out to `ykman` with a user-controlled account name; argument quoting looked safe (passed as positional `arg(name)` to `Command`) but should be re-audited.
- FTP translator AUTH TLS upgrade is incomplete — the current code closes the connection after `234` reply rather than upgrading in place (`t6-e6.md:30-43`). An operator who relies on this for client-cert FTPS will see a clean disconnect with no plaintext fallback, which is the safer half of the failure mode.

### Reliability — **Strong**

- Reconnect: full-jitter exponential backoff per spec §11.2 (`spt-supervisor/src/reconnect.rs:1-91`). Cap, reset_after, max_attempts all honoured; `next_delay` takes an explicit RNG for deterministic tests.
- Forward state machine: `spt-supervisor/src/state_machine.rs` + `spt-forward/runner_states.rs` (41 tests).
- Signal handling: `spt-bin/src/signals.rs`.
- Panic safety: `panic = "abort"` in release (`Cargo.toml:310`) — failures are loud, not silent.
- Failover: `spt-supervisor/src/failover.rs` + round-robin endpoint policy (`round_robin.rs`).

### Observability — **Strong on legacy paths, gaps on t6 features**

- Audit recorder pervasive: `audit::record_audit` fired by `spt-core`, `spt-ssh2/multi_hop`, `spt-ssh2/uds_forward`, `spt-sftp/mount`, `spt-obfs/audit`, `spt-scripting/HookRecorder`.
- 18 files reference audit; `MountAttempt` / `UmountSucceeded` events recorded (t6-Bwire test #7), `ssh-over-shadowsocks` transport name recorded (test #4), `audit.ssh.hop_transition` fired per proxy hop.
- **Gaps documented in t6 logs but not yet wired**: `spt_obfs::AuditHook` has no real subscriber attached (t6-Bwire follow-up 4); GSSAPI/SSPI token issuance audit hook deferred (t6-e9 follow-up "Bwire"); SFTP umount via `mount_stop` does not consult an audit hook (t6-Bwire decision §3). Script-engine load + per-hook invocation audit is `tracing::warn` only, not a structured audit event.

### Performance — **Adequate**

- `spt-benchmark` has dedicated drivers; bench-regression CI job (dispatch-only) compares HEAD vs main via criterion.
- Spot-check on blocking calls in async: `spt-supervisor` has 1 `std::fs` and 2 `std::sync::Mutex` references — `live_connector.rs` and `round_robin.rs`. These appear in tooling/static paths, not on the hot path. `parking_lot::Mutex` is the workspace default for runtime locks.
- Frame caps and peer-table caps in place (UDP `MAX_FRAME_BYTES = 64 KiB`, peer table with idle eviction).
- LTO + codegen-units=1 + symbol strip in release (`Cargo.toml:305-310`).

### Resource Lifecycle — **Adequate**

- Mount lifecycle: `MountHandle` has paired `umount`. Drop-time tear-down for `RemoteUdsForward` (t6-e2). RAII handles in `spt-ssh2/uds_forward.rs`.
- SFTP file ops use `tempfile` + `atomicwrites` (workspace deps).
- t6-Bwire follow-up #3 notes the supervisor still lacks a "real mount registry" — `mount stop` cannot tear down a live mount without re-opening an SSH session. Combined with the mount stub status, this is moot today but blocks 1.0.

### Concurrency Safety — **Strong**

- Workspace lint `unsafe_op_in_unsafe_fn = "warn"` enforced (16 crates explicitly add `#![deny(unsafe_op_in_unsafe_fn)]`).
- 108 unsafe occurrences concentrated in FFI crates (`spt-mem-hygiene`, `spt-winevent`, `spt-secrets`, `spt-net/privileged`). Audit recommended but pattern is correct.
- Shared state via `Arc<dyn AuditHook>`, `Arc<ScriptEngine>`, `Arc<SftpClient>`; `parking_lot::Mutex` preferred for runtime, `std::Mutex` reserved for non-async test/recorder paths.

### Build Matrix — **Strong**

CI (`.github/workflows/ci.yml`) covers, on every push and PR, all six native targets:

| Target | Runner | Tests run? |
|---|---|---|
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` | yes |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` | yes (native ARM runner) |
| `x86_64-apple-darwin` | `macos-13` | yes |
| `aarch64-apple-darwin` | `macos-14` | yes |
| `x86_64-pc-windows-msvc` | `windows-latest` | yes |
| `aarch64-pc-windows-msvc` | `windows-11-arm` | yes |

`fmt`, `clippy --workspace --all-targets --locked -D warnings`, `cargo test --workspace --locked --no-fail-fast`, `cargo deny check`, RustSec audit all gate. Release builds (LTO release profile) build for all six targets and pack `.deb` / `.rpm` / `.pkg` / `.msi` / `.zip` / tarballs. Docker buildx pushes `linux/amd64,linux/arm64` on main.

Dispatch-only jobs (workflow_dispatch): `coverage` (llvm-cov + Codecov), `fuzz` (60s × 10 cargo-fuzz targets), `openssh-interop` (against docker-compose'd openssh fixture), `bench-regression` (criterion compare).

Gaps: MSRV is implicitly tested by every job pinning to 1.83.0, but there is no explicit `cargo +1.83 check -D warnings` separate from the existing matrix — fine since the toolchain pin is consistent. `cargo doc -D warnings` is NOT a CI gate; given `#![warn(missing_docs)]` is only on 16/35 crates this isn't blocking, but should land before 1.0.

### Packaging — **Scaffolded broadly, end-to-end-tested narrowly**

Packaging directory inventory: `aur`, `choco`, `completions`, `deb`, `docker`, `flathub`, `flatpak`, `homebrew`, `launchd`, `man`, `msi`, `nix`, `openrc`, `pkg`, `rpm`, `scoop`, `snap`, `snapcraft`, `systemd`, `sysv`, `windows-gpo`, `winget`.

CI exercises end-to-end (`scripts/package/pack-*.sh`):
- `.deb` (cargo-deb), `.rpm` (cargo-generate-rpm) on linux-gnu
- `.pkg` on macOS
- `.zip`, `.msi` (cargo-wix) on Windows
- Tarballs on Linux + macOS
- Docker buildx multi-arch on release

NOT exercised in CI (scaffolded only): Homebrew formula, Scoop manifest, Chocolatey, Snap, Flatpak, AUR PKGBUILD, Winget, Nix flake. Each ships a `readme.md` — would need a per-recipe audit to confirm their build instructions actually work against a clean release artifact.

### Documentation — **Adequate, with claim-vs-reality drift on t6 features**

26 docs files in `docs/`. The root `readme.md` advertises (lines 12-30) every M1–M7 capability without any "experimental" caveat. Specific claims requiring revision before 1.0:

- "An encrypted **secret vault**" — accurate.
- "**Service integration** for systemd, launchd, Windows SCM, OpenRC, SysV, and Task Scheduler." — accurate (Task Scheduler returns `UnsupportedPlatform` for reload, which is documented).
- "An embedded **Model Context Protocol** (MCP) server with 16 read-only resources and 31 tools." — needs cross-check with `crates/spt-mcp/src/{resources,tools}.rs` to confirm counts; the production `OrchestratorController` does implement the optional methods so the count is achievable.
- **Not mentioned in readme**: scripting hooks (stub), SSPI/GSSAPI (stub), FTP translator (beta), SFTP mount (stub), obfuscation transports (stub). This is honest by omission — but the spec §7 CLI tree publishes them, so an operator running `spt --help` will see them as first-class.

`docs/sftp.md` would need to clearly mark mount as "experimental, requires operator-installed FUSE / WinFsp / sshfs and is not yet wire-complete in any backend". I did not verify each doc against shipped behaviour — recommend a docs-pass before 1.0.

## Risk Ledger (Top 10)

Ranked by blast radius × likelihood.

1. **SFTP mount fails on every platform regardless of feature flag, but `spt sftp mount add/start` is exposed without warnings.** Signal: `crates/spt-sftp/src/mount/linux_fuse.rs:55-63`, `windows_winfsp.rs:60` and `:85`, `macos_sshfs.rs` (requires `SPT_SSHFS_BIN`). Mitigation: gate `mount start` behind `--experimental` until at least one platform has a wired session loop; document the matrix honestly.

2. **t6 stub features (`scripting`, `sspi`/`gssapi`, `obfs4`, `meek-http`, `ssh-over-websocket`) fail at run-time, not at config-validate.** Signal: `t6-e7.md:15-44`, `t6-e9.md:14-31`, `t6-e13.md:21-43`. Cargo.lock confirmed absent for all upstream deps. Mitigation: either (a) reverse the no-`cargo update` policy and pin the upstream deps, or (b) make `spt config validate` reject these config keys unless a feature flag is on, so failure is at parse time not connect time.

3. **The MCP `Controller` default-impl trait methods that downstream embedders rely on return `NotImplemented`.** Signal: `crates/spt-mcp/src/controller.rs:63,70,83,91`. Production `OrchestratorController` overrides them (`spt-bin/src/controller.rs:204,214,231,255`), so the spt binary itself works. Mitigation: document this clearly in the MCP integration guide; consider promoting the default-impl to a panic so embedders catch the gap at compile time.

4. **`Cargo.lock` is treated as immutable, which permanently freezes the t6 feature set.** Signal: workspace policy referenced in every t6 executor log. Mitigation: revisit the policy; document explicitly that t6 features are blocked on a controlled lockfile bump.

5. **Audit hook coverage gaps on t6 features.** Signal: `t6-Bwire.md:164-178` follow-ups 1, 4. `spt_obfs::AuditHook` has no real subscriber; SFTP umount and script-engine invocation don't fire audit events. Mitigation: implement the audit subscriber in `spt-bin/src/audit.rs` (or equivalent) before 1.0.

6. **libssh2 backend has silent feature parity gaps that operators can hit by config.** Signal: every `russh_backend.rs:140,237,384,390,817,827` returns `UnsupportedPlatform`; same for `forward.rs:34`, `uds_forward.rs`, `udp_uds_mode.rs`. Mitigation: surface a clear warning at config validate when `ssh2_backend = "libssh2"` is combined with a feature the backend can't do.

7. **8 active RUSTSEC ignores** in `deny.toml`. Several (rustls-pemfile, lettre, hickory-proto) are MSRV-pinned and represent ongoing technical debt. Mitigation: track each ignore with a target removal milestone; revisit MSRV bump cadence quarterly.

8. **Pre-existing flaky tests on Windows CI** (`spt-dns::query_resolver_*`, `spt-secrets::keychain::entry_for_*`). Signal: `t6-Bwire.md:155-162`. Mitigation: either stabilise (port retry, slower Credential Manager probes with backoff) or quarantine + track.

9. **`Forward::link_kind` validation absent — kebab-cased link kinds (`local_uds`, `remote_uds`) accepted into config without backend-capability check.** Signal: `t6-e2.md:84-92`. Mitigation: extend `spt-config/validate.rs` to reject `link_kind` values the configured `ssh2_backend` can't fulfil.

10. **Memory-hygiene `harden()` failures are silent by design.** Signal: `spt-bin/src/main.rs:77`. Defensible philosophically (defense-in-depth shouldn't gate startup) but means failures in `PR_SET_DUMPABLE`, `SeDebugPrivilege` drop, or `PT_DENY_ATTACH` go unnoticed in production. Mitigation: emit a structured audit event on each failure even when overall startup continues.

## Ship Gate Checklist

Items the operator should pass/fail before tagging 1.0.

- [ ] Real impl behind every t6 stub OR stubs clearly marked "experimental" in `--help` text and config-validate output. **FAIL** today — exposed without warnings.
- [x] CI gates green on Linux + macOS + Windows for stable (MSRV 1.83). Native ARM runners in matrix. **PASS** (`.github/workflows/ci.yml:117-174`).
- [x] `cargo fmt --check`, `clippy -D warnings`, `cargo deny check`, `cargo test --workspace --locked` all green. **PASS** (`ci.yml:86-115`).
- [ ] `cargo doc -D warnings` is a CI gate. **FAIL** — `cargo doc` is not in CI; only 16/35 crates enforce `#![warn(missing_docs)]`.
- [ ] Security review of secret handling, FFI, TLS, command-spawn paths. **PARTIAL** — code structure is correct; line-by-line audit not done in this report.
- [ ] Reconnect logic stress-tested under network chaos (drop, latency, partition). **PARTIAL** — `tests/stress/` and `tests/perf-recovery/` exist; need to confirm coverage.
- [ ] Audit hook coverage matrix complete (mount/umount, script, obfs, gssapi, sftp ops, ftp verbs). **FAIL** — five audit-hook follow-ups still open in t6-Bwire.
- [x] Every "production-ready" packaging recipe builds end-to-end in CI: deb, rpm, msi, pkg, tarball, zip, Docker. **PASS** for these seven; **FAIL** for Homebrew, Scoop, Chocolatey, Snap, Flatpak, AUR, Winget, Nix (scaffolded only).
- [ ] `docs/security.md`, `docs/configuration.md`, `docs/forwards.md`, `docs/auth.md`, `docs/observability.md` accurate vs. shipped behavior. **NOT VERIFIED** in this audit.
- [x] MCP server resources & tools list matches actual exposed surface. **PASS** (production `OrchestratorController` implements every method).
- [ ] Performance baseline benchmarked vs. OpenSSH + autossh. **PARTIAL** — bench-regression dispatch-only job exists but there is no published baseline.
- [x] Reconnect backoff implementation matches spec §11.2 (full-jitter exponential). **PASS** (`spt-supervisor/src/reconnect.rs:6-91`).
- [x] Portable mode pre-clap argv scan + harden ordering correct. **PASS** (`spt-bin/src/main.rs:52-85`).
- [x] CLI dispatcher: every `Command` variant has a real dispatch arm. **PASS** (`spt-bin/src/cli_dispatch.rs:65-92`).
- [ ] `Cargo.lock` policy reviewed; t6 upstream deps either pinned or features explicitly disabled at CLI. **FAIL** — current state is "advertised at CLI, fails at runtime".

## Recommended Next Steps

In priority order.

1. **Gate the t6 stub features at the CLI surface.** Either reject `[profiles.transport]`, `[profiles.script]`, `[profiles.auth].method = "sspi"/"gssapi"` at `spt config validate` unless a `--features experimental` build flag is on, or annotate them in `--help` / `clap` `long_help` as experimental with a clear note that they currently fail at runtime. This is the single highest-impact change for production correctness.
2. **Revisit the no-`cargo update` workspace policy.** It is the structural cause of risks 2 and 4. A controlled lockfile bump (with `rust-toolchain.toml` MSRV unchanged) would unblock `rhai`, `sspi`, `cross-krb5`, `obfs4`, `tokio-tungstenite`, `blake3`, `fuser`. If the policy must hold, declare these features off-roadmap.
3. **Wire the SFTP mount session loops** OR rename `mount` group to `mount-plan` / mark the active verbs experimental until at least one platform has end-to-end mount functionality. This is currently the most misleading CLI surface.
4. **Close the t6-Bwire follow-up list** (5 items): script-engine threading, FTP AUTH-TLS post-handshake split, supervisor mount registry, obfs audit subscriber, portable-mode child-process test harness.
5. **Add `cargo doc -D warnings` to CI** and roll `#![warn(missing_docs)]` to the remaining 19 crates.
6. **Stabilise or quarantine flaky tests** (`spt-dns::query_resolver_*`, `spt-secrets::keychain::entry_for_*`).
7. **Surface a config-validate warning when `ssh2_backend = "libssh2"` is combined with a feature the libssh2 backend can't do** (UDS forward, UDP `uds-bridge`, GSSAPI, dynamic SOCKS with russh-only ops).
8. **Audit the 108 unsafe blocks across 11 files** with per-block safety comments; produce a tracker doc.
9. **Publish a perf baseline** comparing `spt` to OpenSSH client + autossh on the existing benchmark drivers; promote `bench-regression` from dispatch-only to required on PRs that touch the hot paths.
10. **Add end-to-end CI tests for the secondary packaging recipes** (Homebrew, Scoop, Chocolatey, etc.) — at minimum a build-only smoke that the recipe parses and pulls the published artifact.

---

End of report.
