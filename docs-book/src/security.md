# Security

## Scope and threat model

`spt` is a **client-only** tool. It connects to existing SSH and SSH3 servers and maintains port forwards through them. There is no server role and no inbound internet-facing listener beyond the local forwards the operator deliberately configures.

`spt` defends against the following threats:

- **Plaintext secret exposure** in logs, status snapshots, MCP responses, diagnostic bundles, and Prometheus metrics exposition. Every output path passes through the redaction layer before bytes reach disk or network.
- **Unauthorised reconfiguration via the MCP tool surface.** The MCP server is read-only by default; mutating tools require an explicit allow-list in `[mcp].allow_write_tools`.
- **Replay or tampering of remote-config documents.** Remote configuration is fetched over HTTPS only and is verified against a SHA-256 body-fingerprint pin. Trusting the TLS certificate alone is insufficient: the pin covers the fetched body, and optionally an Ed25519 signature anchored to a `signing_pubkey` you supply. `require_signature = true` rejects any unsigned or untrusted-key body.
- **Concurrent supervisors corrupting state.** The state directory is protected by an `fs4` exclusive lock (`<state_dir>/spt.lock`) backed by a PID file; a second `spt tunnel run` against the same state directory exits immediately with code 16 (`StateLockFailed`).

`spt` explicitly does **not** protect against a malicious local root user or an adversarial remote SSH server. Protecting the config filesystem from untrusted writes is the operator's responsibility.

The SSH3 transport (over QUIC/HTTP3) is functional but is excluded from the security scope until SSH3 reaches standards-track status; reports against it are accepted on a best-effort basis only.

## Trust boundaries

| Boundary | Control |
|---|---|
| Local client to spt | Loopback bind by default; per-forward CIDR ACLs. See [Forwarding](forwarding.md). |
| spt to remote endpoint | Host-key (`known_hosts`) or SHA-256 pin; TLS certificate pin for SSH3. See [Trust](trust.md). |
| spt to secret backend | OS keychain ACL; vault passphrase / Argon2id key derivation. See [Secrets](secrets.md). |
| spt to MCP client | Stdio or loopback TCP only; read-only by default. See [MCP](mcp.md). |
| Operator to config disk | Mode 0640 root:spt recommended; service runs as `spt:spt`. |

## Secret handling

Secrets are never written as plaintext into the config file. Instead, config fields reference secrets symbolically:

- `secret://<namespace>/<name>` — resolved from the configured backend (keychain, vault, or file).
- `env:<VARIABLE_NAME>` — resolved from the process environment.
- `file:///absolute/path` — read from a file at resolution time.

The resolver tries backends in the order: keychain, vault, env, file. The resolved bytes are wrapped in `secrecy::SecretBox<Zeroizing<Vec<u8>>>`, zeroed on drop, and never printed via the derived `Debug` implementation.

Every text output (logs, events, MCP responses, diagnostic bundles) passes through `spt_core::redaction` before it reaches any sink. The `spt diagnose bundle` command always applies `RedactionMode::Strict`.

For the full secret-management reference see [Secrets](secrets.md).

## Three-tier redaction

`spt` ships three named redaction modes, configured per-sink via `[logging].redact`:

| Mode | What is replaced |
|---|---|
| `None` | Nothing. Verbatim output. For local debugging only. |
| `Standard` | `secret://...` references and inline plaintext password or token fields are replaced with `[REDACTED]`. This is the default. |
| `Strict` | Everything in Standard plus IP-address-like host and endpoint values. Used automatically by `spt diagnose bundle`. |

## Privilege separation

`spt` is designed to run as a dedicated unprivileged user. The systemd unit shipped under `packaging/systemd/spt.service` applies:

```
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
AmbientCapabilities=CAP_NET_BIND_SERVICE  # only when low-port binds are required
```

See [Service](service.md) for installation details.

## Process memory hardening

At startup `spt-bin` calls `spt_mem_hygiene::harden()`, which applies a set of OS-level mitigations on a best-effort basis. Failure of any individual step is recorded in a `HardeningReport` and logged to the operator channel; it never aborts the process. The report can be serialised into `spt diagnose bundle`.

| Platform | Step | What it prevents |
|---|---|---|
| Linux | `prctl(PR_SET_DUMPABLE, 0)` | Core dumps; `/proc/self/mem` reads by other UIDs; non-privileged `ptrace(PTRACE_ATTACH)`. |
| Linux | `prctl(PR_SET_NO_NEW_PRIVS, 1)` | `execve` from granting new privileges through set-uid binaries. Permanent once set. |
| Linux | `setrlimit(RLIMIT_CORE, {0, 0})` | Belt-and-braces core-dump suppression for kernels that ignore `PR_SET_DUMPABLE` on some paths. |
| Windows | `SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)` | Critical-error and GP-fault WER dialogs that can leak register state in screenshots. |
| Windows | `SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy)` | Legacy `AppInit_DLLs` and extension-DLL injection. |
| Windows | `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` | Ad-hoc `VirtualProtect(PAGE_EXECUTE_*)` and JIT-style RWX page creation. |
| Windows | `AdjustTokenPrivileges` to drop `SeDebugPrivilege` | Cross-process memory read from an unexpectedly-elevated context. |
| macOS | `setrlimit(RLIMIT_CORE, {0, 0})` | Core dumps. |
| macOS | `ptrace(PT_DENY_ATTACH)` | Debugger attach. Gated behind the `macos-anti-debug` Cargo feature, which is **off by default** because it can break Apple notarization tooling, `Instruments.app`, and crash reporters. |

These mitigations layer on top of the systemd hardening directives and the MAC profiles described below. The in-process primitives apply even when `spt` is run directly from the CLI without a service manager.

## Mandatory-access-control profiles

Profiles ship under `packaging/security/`. They are not installed automatically; activate them after the service is running cleanly.

### AppArmor (Debian / Ubuntu)

The profile at `packaging/security/apparmor/spt` denies `ptrace`, raw `/proc/<pid>/mem` reads, mount/umount/pivot\_root, `sys_module`, and all writes outside `/var/lib/spt`, `/var/log/spt`, and `/run/spt`.

```sh
sudo cp packaging/security/apparmor/spt /etc/apparmor.d/spt
sudo apparmor_parser -r /etc/apparmor.d/spt
sudo aa-complain /etc/apparmor.d/spt     # observe first
# review journalctl -k | grep apparmor= for DENIED lines
sudo aa-enforce /etc/apparmor.d/spt
```

### SELinux (Fedora / RHEL / CentOS)

The targeted module under `packaging/security/selinux/` declares the `spt_t` domain, `spt_exec_t` entry-point, and `spt_etc_t` / `spt_var_lib_t` / `spt_var_log_t` / `spt_var_run_t` file types.

```sh
cd packaging/security/selinux
make && sudo make install && sudo make relabel
ps -eZ | grep spt    # expect: ...:spt_t:s0 .../spt
```

### seccomp (containers and hardened runtimes)

`packaging/security/seccomp/spt.json` is an OCI-runtime seccomp profile (`defaultAction: SCMP_ACT_ERRNO`) with an explicit allow-list covering the syscalls the supervisor actually uses and an explicit deny-list for `ptrace`, `process_vm_readv/writev`, `kcmp`, `pivot_root`, mount/umount2, `perf_event_open`, `bpf`, and the module-loading family.

```sh
podman run --security-opt seccomp=packaging/security/seccomp/spt.json ...
docker run  --security-opt seccomp=packaging/security/seccomp/spt.json ...
```

A standalone test crate validates all three profiles without requiring a Linux host:

```sh
cargo test --manifest-path packaging/security/tests-rs/Cargo.toml
```

## Capability policy

The `[capabilities]` table in the config file gates higher-risk optional surfaces. All capabilities are off by default unless explicitly enabled. Key entries:

| Field | Controls |
|---|---|
| `ssh2_backend` | SSH2 implementation: `russh` (default) or `libssh2` (legacy migration path). |
| `allow_libssh2` | Permit the legacy libssh2 SSH2 backend. |
| `allow_gssapi` | SSH GSSAPI/Kerberos authentication and key exchange. |
| `allow_gssapi_delegation` | GSSAPI credential delegation. Off by default to prevent inadvertent ticket forwarding. |
| `allow_sspi` | Windows SSPI/Negotiate authentication. |
| `allow_ntlm_fallback` | NTLM fallback through SSPI/Negotiate. |
| `allow_post_quantum_kex` | Post-quantum SSH key exchange. Offered **by default** (`mlkem768x25519-sha256` first, classical fallback); set to `false` to strip it and offer classical KEX only. |
| `allow_ml_kem` | ML-KEM hybrid SSH key exchange. Part of the default offer; set to `false` to strip it. |
| `require_post_quantum_kex` | Restrict eligible SSH2 profiles to the supported post-quantum KEX only (drops classical fallback, fails closed). Requires `allow_post_quantum_kex = true`. |
| `allow_dynamic_proxy` | SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT proxy listeners. |
| `allow_sftp` | SFTP operations over SSH. |
| `allow_filesystem_mounts` | Filesystem mounts backed by SFTP. |
| `allow_windows_drive_mounts` | Windows drive-letter mounts backed by SFTP. |
| `allow_windows_event_log` | Windows Event Log registration and writes. |
| `allow_gpo_policy_writes` | CLI writes to the Windows GPO registry policy hive. |

## Post-quantum key exchange

Both transports negotiate a **hybrid post-quantum key exchange by default**, so recorded traffic is protected against "harvest-now, decrypt-later" attacks without operator action:

- **SSH2** offers `mlkem768x25519-sha256` first with classical fallback, governed by the `[capabilities]` knobs above (`allow_post_quantum_kex`, `allow_ml_kem`, `require_post_quantum_kex`).
- **SSH3** offers the TLS-1.3 hybrid group **`X25519MLKEM768`** first on its QUIC handshake, with classical X25519 / P-256 / P-384 as fallback (the direct analogue of the SSH2 default). For `spt`-to-`spt` SSH3 the responder always offers the group, so both ends negotiate post-quantum automatically. Because the exchange is hybrid, it is never weaker than classical X25519, and a non-PQ peer still connects over classical X25519.

The SSH3 post-quantum group is supplied by a **per-connection** `aws-lc-rs` crypto provider that applies only to the SSH3 QUIC configuration; the process-global rustls provider used by the status API, syslog TLS, and the remote-config HTTP client is left on `ring` and is unaffected. An operator can force the classical-only handshake with `post_quantum = false` in a profile's `[profiles.tls]` table (see [transports.md](transports.md)); this reproduces the pre-PQ behaviour exactly.

## Fuzz harnesses and decoder hardening

The original standalone cargo-fuzz workspace was absorbed into the regular test suite so the harnesses run in CI without a separate fuzzer toolchain. Deterministic, fixed-seed fuzz tests are integrated into the following crates:

| Crate | Harness | Wire surface covered |
|---|---|---|
| `spt-snmp` | `tests/fuzz_decoders.rs` | BER decoder, SNMPv3 message parser, USM authenticate |
| `spt-trust` | `tests/fuzz_known_hosts.rs` | `known_hosts` file parser |
| `spt-ftp-translator` | `tests/fuzz_verbs.rs` | FTP verb parser |
| `spt-obfs` | `tests/fuzz_decoders.rs` | obfs4 frame decoder, Shadowsocks AEAD decrypt |
| `spt-ssh3` | inline tests in `src/frame.rs` and `src/h3_raw.rs` | SSH3 frame decoder, HTTP3 raw layer |

Each harness uses a deterministic SplitMix64 PRNG seeded from a fixed constant so every CI run produces the identical input stream. Assertions verify that the decoder handles every input without panicking or overflowing, regardless of whether it returns an error. Run under `--release` to exercise the release-profile overflow-checks path:

```sh
cargo test -p spt-snmp --release --test fuzz_decoders
cargo test -p spt-trust --release --test fuzz_known_hosts
```

## Release hardening

The workspace `Cargo.toml` sets `overflow-checks = true` in the release profile:

```toml
# [profile.release]
overflow-checks = true
```

This turns integer wrap-around in release builds into a caught panic rather than silent undefined behaviour. Arithmetic that must wrap uses `wrapping_*`, `Wrapping`, or `saturating_*` explicitly. The intent is to convert the silent-wrap-then-crash class of denial-of-service bugs (common in length-field arithmetic in network decoders such as QPACK and SNMP) into deterministic panics.

## Exit codes

There are 38 stable exit codes defined in `crates/spt-core/src/exit_code.rs` under spec §7.4. Their numeric values are contractually fixed and will never be reused. See the complete table in [Troubleshooting](troubleshooting.md) and the source of truth at `crates/spt-core/src/exit_code.rs`.

Categories:

- **0** — success.
- **1–3** — argument, config, and generic runtime errors.
- **4–8** — connection lifecycle: required-profile failure, auth, trust, local bind, remote bind.
- **9–15** — infrastructure: service manager, unsupported platform, DNS, network, keepalive, reload, logging.
- **16–23** — state and resource management: lock, secrets, crypto, keys, permission, resource, rate limit, failover.
- **24–31** — observability, MCP, partial results, health checks, versioning, internal errors.
- **32–37** — diagnostics and benchmark operations.

## Supply chain

Releases are signed; verify before installing — see [Installation](installation.md). The dependency tree is audited with `cargo deny` and `cargo audit` can be run locally against the current RustSec advisory database. `Cargo.lock` is checked in and gates `cargo test --workspace --locked` in CI.

## Reporting vulnerabilities

Use the "Report a vulnerability" button on the repository's Security tab (GitHub Security Advisories), or email `security@spt.invalid`. Include the `spt --version` output, steps to reproduce, and any relevant redacted config or trace output. We aim to acknowledge within 3 business days and resolve or disclose within 90 days.
