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

## Process memory hardening

At startup `spt-bin` calls [`spt_mem_hygiene::harden()`][hcrate] which applies
the best-effort OS-level mitigations summarised below. Failures of any one
primitive are logged but never abort the process — a hardened-when-possible
service is more useful than a refuse-to-start one. The returned
`HardeningReport` is rendered to the operator log and can be JSON-serialised
into `spt diagnose bundle`.

| Platform | Primitive | What it blocks |
|----------|-----------|-----------------|
| Linux    | `prctl(PR_SET_DUMPABLE, 0)` | Core dumps; `/proc/self/mem` access from other UIDs; non-privileged `ptrace(PTRACE_ATTACH)`. |
| Linux    | `prctl(PR_SET_NO_NEW_PRIVS, 1)` | `execve(2)` cannot grant new privileges (setuid binaries become no-ops). Permanent. |
| Linux    | `setrlimit(RLIMIT_CORE, {0, 0})` | Belt-and-braces core-dump disable for kernels that ignore `PR_SET_DUMPABLE` on some paths. |
| Windows  | `SetErrorMode(SEM_FAILCRITICALERRORS \| SEM_NOGPFAULTERRORBOX)` | "Abort/Retry/Ignore" critical-error and GP-fault Windows Error Reporting dialogs (which can leak register state in screenshots / freeze service). |
| Windows  | `SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy)` | Legacy `AppInit_DLLs` / extension-DLL injection. |
| Windows  | `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` | Ad-hoc `VirtualProtect(PAGE_EXECUTE_*)` / JIT-style RWX pages. |
| Windows  | `AdjustTokenPrivileges` → drop `SeDebugPrivilege` | Cross-process memory read of arbitrary processes (defence-in-depth even if the process is unexpectedly run with admin context). |
| macOS    | `setrlimit(RLIMIT_CORE, {0, 0})` | Core dumps. |
| macOS    | `ptrace(PT_DENY_ATTACH)` (feature `macos-anti-debug`, **off by default**) | Debugger attach. Off by default because it can break Apple notarization tooling, `Instruments.app`, and crash reporters. |

[hcrate]: ../crates/spt-mem-hygiene/

The mitigations are deliberately layered with the existing
`systemd` hardening (`NoNewPrivileges=true`, `ProtectSystem=strict`, etc.)
and AppArmor / SELinux / seccomp profiles under
`packaging/security/` — the syscall-level primitives apply even when the
service manager does not (e.g. plain CLI runs, Windows services).

## Mandatory-access-control profiles

Profile artifacts ship under `packaging/security/`. They are *not*
installed by the distro packages by default — install + activate them as
part of operator onboarding once the service is running cleanly.

### Debian / Ubuntu — AppArmor

The profile lives at `packaging/security/apparmor/spt`. It denies
`ptrace`, raw `/proc/<pid>/mem` reads, mount/umount/pivot_root,
`sys_module`, and writes outside `/var/lib/spt`, `/var/log/spt`, and
`/run/spt`.

```sh
sudo cp packaging/security/apparmor/spt /etc/apparmor.d/spt
sudo apparmor_parser -r /etc/apparmor.d/spt   # load into kernel
sudo aa-complain /etc/apparmor.d/spt          # observe-only first
# ... exercise spt for a representative session, inspect
# `journalctl -k | grep apparmor=` for any "DENIED" lines, adjust ...
sudo aa-enforce /etc/apparmor.d/spt           # confine
```

To remove: `sudo apparmor_parser -R /etc/apparmor.d/spt && sudo rm /etc/apparmor.d/spt`.

### Fedora / RHEL / CentOS — SELinux

A targeted module ships under `packaging/security/selinux/`. It declares
the `spt_t` domain, `spt_exec_t` entry-point, and `spt_etc_t` /
`spt_var_lib_t` / `spt_var_log_t` / `spt_var_run_t` file types, with
transitions from `sysadm_t`, `user_t`, and `init_t`.

Build + install (requires the `selinux-policy-devel` package):

```sh
cd packaging/security/selinux
make                 # produces spt.pp
sudo make install    # semodule -i spt.pp
sudo make relabel    # restorecon the spt-labeled paths
```

Verify the running domain:

```sh
ps -eZ | grep spt    # expect: ...:spt_t:s0 .../usr/local/bin/spt ...
```

To remove: `sudo make uninstall` (runs `semodule -r spt`).

### Containers / hardened runtimes — seccomp

`packaging/security/seccomp/spt.json` is an OCI-runtime-style seccomp
profile (`defaultAction: SCMP_ACT_ERRNO`) with explicit allow-list of
the syscalls the supervisor + forwards + observability stack actually
need, plus an explicit deny-list for `ptrace`, `process_vm_readv/writev`,
`kcmp`, `pivot_root`, `mount`/`umount2`, `swapon`/`swapoff`, `reboot`,
the `init_module` / `finit_module` / `delete_module` / `kexec_load`
trio, `perf_event_open`, and `bpf`.

Drop-in use from `runc` / `crun` / `containerd`:

```sh
podman run --security-opt seccomp=packaging/security/seccomp/spt.json ...
docker run  --security-opt seccomp=packaging/security/seccomp/spt.json ...
```

Standalone systemd units can reference the same allow-list via
`SystemCallFilter=` (translate the JSON allow-list verbatim) — or rely
on the in-process loader: `spt_mem_hygiene` will, when compiled with
the `seccomp` feature, apply this allow-list to the running process via
`libseccomp` immediately after `harden()`. Until that feature lands,
operators should treat the JSON as the canonical reference for any
external sandbox (Bubblewrap, Firejail, Kubernetes
`securityContext.seccompProfile`, etc.). The OCI form is reusable in
all four runtimes without re-encoding.

### Verifying the artifacts

A tiny standalone test crate parses + compiles the three profiles
without needing a Linux host:

```sh
cargo test --manifest-path packaging/security/tests-rs/Cargo.toml
```

`seccomp_json_parses` always runs (pure JSON). `apparmor_profile_parses`
and `selinux_te_compiles` skip on non-Linux or when the relevant
parser (`apparmor_parser`, `checkmodule`) is absent.

## Supply-chain

Releases are signed; verify before installing — see
[Installation](installation.md). The Rust dependency tree is audited via
`cargo deny` and `cargo audit` can be run locally against the current
RustSec advisory database (CVSS 4.0 formats included) when an audit pass is
needed; CI no longer runs them as a gating job.

The workspace's earlier "no `cargo update`" policy was lifted for the t7
milestone so the t6 stub features (`rhai`, `sspi`, `libgssapi`, `obfs4`,
`tokio-tungstenite`, `blake3`, `fuser`, `dokan`) could land as real
implementations. Each new dep is documented in the corresponding
`.orchestration/logs/t7-*.md` log; `Cargo.lock` is still checked in and
gates `cargo test --workspace --locked` in CI.

## Reporting vulnerabilities

Email security@example.invalid (replace with the project's real address).
Include reproduction steps and the `spt --version` string.
