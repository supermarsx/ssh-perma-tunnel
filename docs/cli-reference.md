# CLI Reference

`spt` is structured as a Docker-style command tree with 26 top-level groups.
The canonical flag listing is generated from the Clap command tree and is
available through:

- `spt --help`
- `spt <group> --help`
- `spt <group> <subcommand> --help`
- the generated man pages under `packaging/man/`

This page is the maintained operator index for the command surface, config
surfaces, completion support, and exit-code contract.

## Global Flags

| Flag | Env | Notes |
|------|-----|-------|
| `--config PATH` | `SPT_CONFIG` | Path to a single config file. |
| `--config-dir PATH` | | Directory of `*.toml` configs, loaded lexically. |
| `--config-url URL` | `SPT_CONFIG_URL` | HTTPS remote config. |
| `--config-fingerprint SHA256` | | SHA-256 pin for `--config-url`. |
| `--state-dir PATH` | `SPT_STATE_DIR` | Override runtime state directory. |
| `--profile NAME` | | Restrict operations to one profile where supported. |
| `--output FORMAT` | | `human`, `json`, `jsonl`, or `yaml`. |
| `--json` | | Convenience alias for `--output json`. |
| `--log-level LEVEL` | | `error`, `warn`, `info`, `debug`, or `trace`. |
| `--color MODE` | `NO_COLOR` | `auto`, `always`, or `never`. |
| `--quiet`, `--verbose` | | Reduce or increase output. |
| `--dry-run` | | Plan without mutating where supported. |

## Commands

| Group | Command surface |
|-------|-----------------|
| `config` | `init`, `validate`, `doctor`, `render`, `diff`, `migrate`, `reload`, `pull`, `trust add-url`, `encrypt`, `decrypt`, `edit`, `crypt rotate` |
| `profile` | `list`, `show`, `add`, `configure`, `set`, `enable`, `disable`, `remove`, `test` |
| `forward` | `list`, `show`, `add local`, `add remote`, `explain`, `test`, `throttle`, `remove` |
| `tunnel` | `run`, `status`, `stats`, `sessions`, `stop`, `reload`, `health`, `failover` |
| `service` | `install`, `uninstall`, `start`, `stop`, `restart`, `status`, `render` |
| `key` | `generate`, `inspect`, `public`, `change-passphrase`, `sign-cert`, `verify-cert`, `install-public` |
| `secret` | `store init`, `set`, `get`, `list`, `rotate`, `remove`, `doctor` |
| `auth` | `test`, `ssh3-login` |
| `dns` | `serve`, `status`, `query`, `upstream set`, `record add`, `record remove`, `hosts render`, `hosts apply`, `hosts restore` |
| `firewall` | `plan`, `apply`, `remove`, `status`, `interfaces`, `bind-preview`, `gateway show`, `gateway set`, `policy list`, `policy show`, `policy set`, `policy unset` |
| `log` | `tail`, `test`, `export`, `remote list`, `remote test`, `remote status`, `remote drain` |
| `observe` | `metrics`, `windows-event install-source`, `windows-event uninstall-source`, `windows-event test`; SNMP subcommands are present only in `--features snmp` builds |
| `event` | `list`, `test`, `replay`, `sink list`, `sink test` |
| `stats` | `summary`, `live`, `connections`, `throughput`, `errors`, `export` |
| `session` | `list`, `show`, `close`, `drain`, `top` |
| `ftp` | `translator serve` |
| `sftp` | `test`, `list`, `stat`, `get`, `put`, `mkdir`, `rm`, `rmdir`, `rename`, `cat`, `tail`, `chmod`, `symlink`, `readlink`, `realpath`, `put-recursive`, `get-recursive`, `mount list`, `mount add`, `mount remove`, `mount plan`, `mount start`, `mount stop`, `umount`, `drive list`, `drive add`, `drive remove`, `drive plan` |
| `diagnose` | `run`, `network`, `auth`, `trust`, `dns`, `bind`, `port`, `service`, `secrets`, `observability`, `mcp`, `bundle` |
| `benchmark` | `run`, `latency`, `throughput`, `udp`, `reconnect`, `dns`, `limits`, `report compare`, `report export` |
| `mcp` | `serve`, `inspect`, `policy show`, `policy set` |
| `status` | (no subcommands) — show overall app status: daemon, tunnels, forwards, subsystems, services |
| `status-api` | `serve`, `show`, `token rotate` — controls for the read-only HTTP status API |
| `completion` | `generate bash`, `generate zsh`, `generate fish`, `generate powershell`, `generate elvish` |
| `about` | (overview), `list`, `show <crate>`, `licenses`, `export <path>` |
| `kill` | (no subcommands) — terminate every running spt instance on this host |
| `update` | `check`, `download`, `apply`, `now`, `status`, `history` (auto-updater; **off by default**) |

### `about` — bundled-library attribution

`spt about` surfaces every library linked into the binary. The data is
captured at build time from `cargo metadata`, so there is no runtime
dependency on cargo and no network access — the inventory is baked into the
binary.

```
spt about                              # overview: spt version + top 20 deps
spt about list                         # full list, one line per crate
spt about list --format=json           # structured array (jq-friendly)
spt about list --format=markdown       # distribution-friendly attribution
spt about list --license=MIT           # filter by SPDX substring (case-insensitive)
spt about list --include-dev           # include dev/test deps (default: runtime-only)
spt about show clap                    # detailed view for one library
spt about licenses                     # SPDX-grouped histogram (compliance audits)
spt about export attribution.md        # write attribution.{md,json,txt}
```

Vendored forks (`vendor/russh-fork`, `vendor/libgssapi-fork`) are flagged as
locally patched. Workspace crates are flagged as part of the binary itself
and excluded from the "bundled libraries" overview count.

### `kill` — terminate every running spt instance

`spt kill` enumerates running processes on the host (via `sysinfo`) and
signals every one whose executable basename matches `spt` (Unix) or
`spt.exe` (Windows). The current process is skipped by default so an
operator running `spt kill` in a still-active session doesn't terminate
their own shell.

```
spt kill                           # graceful SIGTERM / TerminateProcess, 5s grace
spt kill --force                   # SIGKILL / unconditional TerminateProcess
spt kill --dry-run                 # list would-be targets, signal nothing
spt kill --include-self            # also kill the calling spt
spt kill --name spt-bin            # substring override (case-insensitive)
spt kill --timeout 30s             # extend the platform terminate grace window
```

Platform mechanism:

| OS      | Signal | Wait |
|---------|--------|------|
| Unix    | `nix::sys::signal::kill(pid, SIGTERM \| SIGKILL)` | `kill -0` probe loop until ESRCH or timeout |
| Windows | `OpenProcess(PROCESS_TERMINATE \| PROCESS_SYNCHRONIZE)` + `TerminateProcess` | `WaitForSingleObject(timeout)` |

Per-process failures (permission denied, race-with-exit) are reported but
don't abort the overall command — `spt kill` returns success if at least
one target was signalled, error only if every targeted PID failed.

### `update` — autonomous upgrade (off by default)

`spt update` polls a configured release source, optionally downloads + verifies
+ installs new artifacts, and notifies the supervisor to restart. **Both the
background polling thread and the auto-install path are disabled by default.**
The operator opts in via `[updater]` in the config (see
[`docs/updater.md`](updater.md) for the schema reference).

| Command | Behavior |
|---------|----------|
| `spt update check` | One-shot poll; prints whether a newer version is available. Honours `[updater].source` but doesn't require `enabled = true`. |
| `spt update download [--target X]` | Stage the artifact under `[updater.staging].dir`; does not install. |
| `spt update apply` | Install the staged artifact (atomic swap). |
| `spt update now` | check + download + apply in one go. |
| `spt update status` | Last check, next-scheduled tick, current/latest version, staged artifact. |
| `spt update history` | Past update events from the audit log. |

Manual `spt update *` commands work even when `[updater].enabled = false` —
`enabled` only gates the *background thread* the supervisor would otherwise
spawn. Verification (minisign signature on the artifact) is **required by
default**; the operator can opt out with `[updater.verify].require_minisign =
false` for private mirrors that don't replay signatures.

See [`docs/updater.md`](updater.md) for the full schedule grammar, source-
backend matrix, and operational details.

### `status` — app-status overview

> **Breaking rename (26.x):** `spt status` no longer controls the HTTP status
> API. It is now a read-only **app-status overview**. The former server
> controls moved to [`spt status-api`](#status-api--read-only-http-status-api-controls)
> (`spt status serve|status|token` → `spt status-api serve|show|token`). Scripts
> that called the old subcommands must be updated.

`spt status` (no subcommands) prints a single overview of the local daemon and
everything it is running. It is purely read-only: it reads
`<state_dir>/runtime.json` (written by a running daemon), the `status.json`
snapshot, and — when reachable — the loaded config. No subsystem is contacted
over the network and nothing is mutated.

Liveness is reported as **RUNNING** only when `runtime.json` is present, its
recorded PID is alive, and the snapshot is not stale; otherwise the state is
reported as not-running, dead (PID gone), or stale. When the daemon is not
running but a `--config` is supplied, configured-but-inactive subsystems are
listed from the config.

| Flag | Notes |
|------|-------|
| `--detail` | Verbose per-component fields (per-forward direction/transport/conns/bytes, full subsystem detail). Default output is concise. |
| `--output FORMAT` | Local override of the global `--output`; emits the combined machine structure as `json`/`yaml`. |
| `--json` | Convenience alias for `--output json` (local; shadows the global `--json`). |
| `--watch` | Human-only live view: clears and reprints the overview roughly every 2s until `Ctrl-C`. Rejected with `InvalidArgs` when combined with a machine output format. |

Sections shown:

- **Daemon** — PID, version, uptime (from `started_at`), resolved config path, state directory.
- **Profiles / Tunnels** — per-tunnel state, endpoint, reconnect/failover counts, and byte totals.
- **Forwards** — per-forward state and listener→target; direction, transport, connection count, and byte counters under `--detail`.
- **Subsystems** — status API (bind, auth mode, TLS), MCP (bind), DNS (bind, mode), metrics (file path), remote-config poller (enabled + interval), and events (sink count + kinds).
- **Services** — a brief pointer line (`see spt service status`).

### `status-api` — read-only HTTP status API controls

`spt status-api` is the group that controls the read-only HTTP status API
server. It is the renamed-and-cleaned successor to the old `spt status` group;
in particular the awkward `spt status status` inspection command is now
`spt status-api show`.

| Command | Behavior |
|---------|----------|
| `spt status-api serve [--config PATH] [--bind ADDR]` | Run the read-only HTTP status API server. Formerly `spt status serve`. |
| `spt status-api show [--detail]` | Show the current status-API server configuration/state. Formerly `spt status status`. |
| `spt status-api token rotate [--print-token] [--bytes N]` | Rotate the status-API bearer token (default 32 bytes). Formerly `spt status token rotate`. |

## Capability Notes

- SSH2 and SSH3 profiles are configured with TOML and managed with
  `profile`, `forward`, `tunnel`, and `service` commands.
- SSH3 remains experimental and requires `acknowledge_experimental = true`
  on SSH3 profiles.
- UDP forwarding is SSH3-only; SSH2 UDP forwards validate as unsupported.
- Interface-specific binds use per-forward `bind_mode`, `bind_interface`,
  `bind_interface_preference`, and `bind_ipv6`, plus global `[network]`
  defaults.
- Gateway, interface, offload, load-balancing, and failover settings live in
  `[network]` and `[profiles.failover]`. Use `spt firewall gateway show|set`
  to manage `[network.interface]`, `[network.gateway]`, `[network.offload]`,
  and `[network.load_balance]` from the CLI.
- Profile endpoint load balancing and failover can be managed with dotted
  profile mutations, for example:
  `spt profile set edge endpoints.0.name=primary endpoints.0.host=gw-a endpoints.0.weight=80 failover.mode=weighted failover.fail_after=3`.
- Windows GPO-style policy is surfaced through `spt firewall policy`; Windows
  writes target `HKCU` or `HKLM\Software\Policies\spt`, while non-Windows
  hosts return `UnsupportedPlatform` for policy writes. The
  `Capabilities.AllowGpoPolicyWrites` policy can disable those writes.
- `[capabilities]` gates the new production feature families: russh SSH2
  backend selection, GSSAPI/SSPI, PQ/ML-KEM KEX,
  SOCKS4/SOCKS4A/SOCKS5/HTTP CONNECT, SFTP, filesystem and Windows drive
  mounts, Windows Event Log, and GPO writes.
- `[profiles.auth] method = "gssapi" | "kerberos" | "sspi" | "negotiate"`
  is validated and translated into explicit auth methods. Runtime
  negotiation is real as of t7 (Unix via vendored `libgssapi`, Windows
  via `sspi 0.15`); see [Authentication](auth.md).
- PQ/ML-KEM KEX names in `[profiles.crypto].kex_algorithms` are validated
  behind `allow_post_quantum_kex` and `allow_ml_kem`. Current SSH2 backends
  return explicit unsupported-feature diagnostics for ML-KEM/SNTRUP runtime
  negotiation rather than silently falling back.
- `spt sftp` requires SSH2 profiles with `[capabilities].allow_sftp = true`.
  `spt sftp mount|drive` manages `[[profiles.sftp_mounts]]` entries and runs
  the platform helper directly: Linux via `fuser`, Windows via Dokany2,
  macOS via shell-out to `sshfs` + macFUSE (deprecation-warned). See
  [SFTP](sftp.md) for the per-OS matrix.
- The SSH2 backend is the pure-Rust `russh` crate; libssh2 was removed
  in t7. The deprecated `[capabilities].ssh2_backend` and
  `[capabilities].allow_libssh2` keys are accepted at load with a
  one-shot warning and silently ignored at runtime. Run
  `spt config migrate --to 2` to strip them.
- Remote logging supports `syslog_udp`, `syslog_tcp`, `syslog_tls`,
  `https_jsonl`, and `otlp` config kinds. The live writer implementation
  covers the syslog transports and CLI testing/status/drain paths.
- MCP is disabled by default; `spt mcp serve` requires `[mcp].enabled = true`
  or `--enable`.
- SNMP is disabled by default and build-gated. Default builds do not expose
  `spt observe snmp`; `--features snmp` builds expose SNMP commands and
  require a configured production `observability.snmp.enterprise_id`.
- DNS resolver and hosts-file mutation are opt-in.

## Config Surfaces

The TOML schema documents and validates these operational surfaces:

- `[runtime]`, `[runtime.threads]`, `[runtime.reload]`,
  `[runtime.remote_config]`
- `[logging]`, `[[logging.remote]]`
- `[network]`, `[network.interface]`, `[network.gateway]`,
  `[network.offload]`, `[network.load_balance]`
- `[dns]`, managed records, hosts-file settings, resolver settings
- `[firewall]`
- `[observability.metrics]`, `[observability.snmp]`,
  `[observability.windows_event]`
- `[events]`, `[[events.bindings]]`, `[[events.sinks]]`
- `[mcp]`
- `[diagnostics]`
- `[benchmark]`
- `[[profiles]]`, `[profiles.auth]`, `[profiles.trust]`, `[profiles.tls]`,
  `[profiles.crypto]`, `[profiles.keepalive]`, `[profiles.reconnect]`,
  `[profiles.failover]`, unstable-connection detection, limits, forwards,
  `[[profiles.sftp_mounts]]`, DNS names, bind/interface policy,
  observability tags, and diagnostics tags

See `docs/configuration.md` for the schema walkthrough and examples.

## Shell Completions

Completions are generated from the live command tree:

```text
spt completion generate bash
spt completion generate zsh
spt completion generate fish
spt completion generate powershell
spt completion generate elvish
```

The package manifests install or generate completions for the relevant shell
paths, including bash, zsh, fish, PowerShell, and Homebrew's completion helper.
Committed completion artifacts live under `packaging/completions/` and are
regenerated with:

```text
cargo run -p spt-bin --bin spt-completions -- --out packaging/completions
```

The shipped paths are:

- bash: `share/bash-completion/completions/spt`
- zsh: `share/zsh/site-functions/_spt`
- fish: `share/fish/vendor_completions.d/spt.fish`
- PowerShell: `share/powershell/Modules/spt/spt.psm1`
- Elvish: `share/elvish/lib/spt.elv`

## Man Pages

Committed man pages live under `packaging/man/`:

- `spt.1`
- `spt-auth.1`
- `spt-benchmark.1`
- `spt-completion.1`
- `spt-config.1`
- `spt-diagnose.1`
- `spt-dns.1`
- `spt-event.1`
- `spt-firewall.1`
- `spt-forward.1`
- `spt-key.1`
- `spt-log.1`
- `spt-mcp.1`
- `spt-observe.1`
- `spt-profile.1`
- `spt-secret.1`
- `spt-service.1`
- `spt-session.1`
- `spt-sftp.1`
- `spt-stats.1`
- `spt-status.1`
- `spt-status-api.1`
- `spt-tunnel.1`

Regenerate them after CLI changes with:

```text
cargo run -p spt-bin --bin spt-mangen -- --out packaging/man
```

## Exit Codes

The binary uses stable process exit codes from `crates/spt-core/src/exit_code.rs`.
The numeric value of each code is part of the public CLI contract and never
changes. The full table (kept in lockstep with the `ExitCode` enum) is:

| Code | Name | Meaning |
|------|------|---------|
| 0 | `Success` | Successful completion. |
| 1 | `InvalidArgs` | Invalid command-line arguments. |
| 2 | `InvalidConfig` | Configuration file failed to load or validate. |
| 3 | `RuntimeFailure` | Generic runtime failure not covered by a more specific code. |
| 4 | `RequiredProfileFailed` | One or more profiles marked `required` failed to start or stay up. |
| 5 | `AuthFailed` | Authentication to a remote endpoint failed. |
| 6 | `TrustFailed` | Trust verification (host key, TLS pin, certificate) failed. |
| 7 | `LocalBindFailed` | A local listening bind failed. |
| 8 | `RemoteBindFailed` | A remote/forwarded bind failed. |
| 9 | `ServiceManagerFailed` | A service-manager operation (install, start, stop, ...) failed. |
| 10 | `UnsupportedPlatform` | Platform or feature is not supported. |
| 11 | `DnsFailed` | DNS resolution or the internal DNS resolver failed. |
| 12 | `NetworkUnreachable` | Network unreachable or connection refused. |
| 13 | `KeepaliveTimeout` | Keepalive timed out. |
| 14 | `ReloadFailed` | `config reload` failed. |
| 15 | `LoggingSinkUnavailable` | A required logging sink is unavailable. |
| 16 | `StateLockFailed` | State directory or state-lock acquisition failed. |
| 17 | `SecretUnavailable` | A referenced secret is unavailable, locked, or denied. |
| 18 | `SecretCryptoFailed` | Secret encryption or decryption failed. |
| 19 | `KeyFailure` | Key generation, parsing, or file-permission check failed. |
| 20 | `PermissionDenied` | Permission denied. |
| 21 | `ResourceExhausted` | Resource exhausted or out-of-memory. |
| 22 | `RateLimited` | A rate limit or throttle policy rejected the operation. |
| 23 | `FailoverExhausted` | All failover targets exhausted. |
| 24 | `SnmpOrMetricsFailed` | SNMP agent or metrics exporter failed. |
| 25 | `WindowsEventLogFailed` | A Windows Event Log operation failed. |
| 26 | `McpFailed` | MCP server policy or operation failed. |
| 27 | `RemoteSinkRejected` | A remote observability sink rejected delivered data. |
| 28 | `PartialDegraded` | Partial success with degraded non-required profiles. |
| 29 | `HealthCheckFailed` | A health check failed. |
| 30 | `VersionOrMigrationFailed` | Schema version or migration failure. |
| 31 | `InternalError` | Internal error (assertion, invariant, or `unreachable`). |
| 32 | `DiagnosticFailed` | A diagnostic check reported failure. |
| 33 | `DiagnosticBundleFailed` | Diagnostic bundle generation failed. |
| 34 | `BenchmarkFailed` | A benchmark run failed. |
| 35 | `BenchmarkRefused` | Benchmark refused by safety policy. |
| 36 | `SessionNotFound` | Session not found. |
| 37 | `SessionCloseFailed` | Session close or drain failed. |

### `tunnel health` exit contract

`spt tunnel health` does **not** use the table above. It is a probe command
whose exit status encodes the health verdict directly (analogous to
`systemctl is-active`), so monitoring tooling can branch on `$?`:

| Code | Verdict | Meaning |
|------|---------|---------|
| 0 | green | All checked profiles are healthy. |
| 1 | yellow | Degraded — at least one profile is reconnecting or partially up. |
| 2 | red | Unhealthy — one or more checked profiles are down. |
| 3 | unknown | Health could not be determined (no running supervisor / no state). |

These values are scoped to `tunnel health` and intentionally overlap the
numeric range of the global table; do not interpret a `tunnel health` exit of
`2` as `InvalidConfig`. The same contract is shown in `spt tunnel health
--help`.
