# CLI Reference

`spt` is structured as a Docker-style command tree with 20 top-level groups.
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
| `config` | `init`, `validate`, `doctor`, `render`, `diff`, `migrate`, `reload`, `pull`, `trust add-url` |
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
| `diagnose` | `run`, `network`, `auth`, `trust`, `dns`, `bind`, `port`, `service`, `secrets`, `observability`, `mcp`, `bundle` |
| `benchmark` | `run`, `latency`, `throughput`, `udp`, `reconnect`, `dns`, `limits`, `report compare`, `report export` |
| `mcp` | `serve`, `inspect`, `policy show`, `policy set` |
| `status` | `serve`, `status`, `token rotate` |
| `completion` | `generate bash`, `generate zsh`, `generate fish`, `generate powershell`, `generate elvish` |

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
- Windows GPO-style policy is surfaced through `spt firewall policy`; Windows
  writes target `HKCU` or `HKLM\Software\Policies\spt`, while non-Windows
  hosts return `UnsupportedPlatform` for policy writes. The
  `Capabilities.AllowGpoPolicyWrites` policy can disable those writes.
- `[capabilities]` gates the new production feature families: russh SSH2
  backend selection, GSSAPI/SSPI, PQ/ML-KEM KEX, SOCKS/HTTP CONNECT, SFTP,
  filesystem and Windows drive mounts, Windows Event Log, and GPO writes.
- `ssh2_backend = "russh"` is the runtime default. Use
  `ssh2_backend = "libssh2"` with `allow_libssh2 = true` only for legacy
  migration cases such as SSH agent auth or multi-hop chains until their russh
  actor path is complete.
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
  `[profiles.failover]`, unstable-connection detection, limits, forwards, DNS
  names, bind/interface policy, observability tags, and diagnostics tags

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
- `spt-stats.1`
- `spt-status.1`
- `spt-tunnel.1`

Regenerate them after CLI changes with:

```text
cargo run -p spt-bin --bin spt-mangen -- --out packaging/man
```

## Exit Codes

The binary uses stable process exit codes from `crates/spt-core/src/exit_code.rs`.
The most common are:

| Code | Name | Meaning |
|------|------|---------|
| 0 | `Success` | Successful completion. |
| 1 | `InvalidArgs` | Bad CLI arguments. |
| 2 | `InvalidConfig` | Config failed to load or validate. |
| 3 | `RuntimeFailure` | Generic runtime failure. |
| 5 | `AuthFailed` | Authentication failed. |
| 6 | `TrustFailed` | Host key or TLS pin verification failed. |
| 8 | `UnsupportedFeature` | Requested capability is not supported. |
| 9 | `ServiceManagerFailed` | Native service manager operation failed. |
| 16 | `StateLockFailed` | Another `spt` process owns the state lock. |
| 17 | `SecretUnavailable` | Secret could not be resolved. |
| 19 | `KeyFailure` | Key generation, parsing, or certificate failure. |
| 20 | `PermissionDenied` | OS-level permission denied. |
| 22 | `ConfigReloadRejected` | Reload was rejected. |
| 23 | `Timeout` | Operation timed out. |
| 24 | `OutOfMemory` | Memory allocation failure or configured memory cap. |
| 26 | `McpFailed` | MCP server or policy failure. |
