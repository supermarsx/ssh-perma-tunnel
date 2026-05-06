# CLI Reference

`spt` is structured as a Docker-style command tree with 17 top-level groups.
Run `spt --help` (or `spt <group> --help`) for the canonical, machine-generated
listing. This guide covers the commands implemented today plus the milestone
each not-yet-wired command lands in.

## Global flags

| Flag                  | Env             | Notes                                  |
|-----------------------|-----------------|----------------------------------------|
| `--config PATH`       | `SPT_CONFIG`    | Path to a single config file.          |
| `--config-dir PATH`   |                 | Directory of `*.toml` configs (lex).   |
| `--config-url URL`    | `SPT_CONFIG_URL`| HTTPS-only remote config.              |
| `--config-fingerprint`|                 | SHA-256 pin for `--config-url`.        |
| `--state-dir PATH`    | `SPT_STATE_DIR` | Override runtime state directory.      |
| `--profile NAME`      |                 | Limit operations to one profile.       |
| `--output FORMAT`     |                 | `human` (default), `json`, `jsonl`, `yaml`. |
| `--json`              |                 | Alias for `--output json`.             |
| `--log-level LEVEL`   |                 | `error|warn|info|debug|trace`.        |
| `--color MODE`        | `NO_COLOR`      | `auto|always|never`.                   |
| `--quiet` / `--verbose` |               | Reduce / increase output.              |
| `--dry-run`           |                 | Plan, never mutate.                    |

## Implemented in M0

These are wired end-to-end by the binary:

- `spt config validate` — load, validate, and report.
- `spt config render` — re-emit canonical TOML; `--redacted` to mask.
- `spt config diff` — field-level diff between two configs.
- `spt profile list / show / add / remove` — read/write the TOML.
- `spt profile configure --tui` — interactive editor (ratatui).
- `spt forward list / add / remove` — TOML mutation.
- `spt tunnel run` — acquire state lock, write status snapshot, wait on signals.
- `spt tunnel status` — print the latest snapshot from `<state_dir>/status.json`.
- `spt tunnel stop / reload` — signal the running supervisor (Unix).
- `spt service install / uninstall / start / stop / restart / status / render`.
- `spt key generate / inspect` — Ed25519 / ECDSA-P256 / RSA via `ssh-key`.
- `spt secret set / get / remove / doctor` — keychain-backed.
- `spt dns hosts render / apply / restore` — managed-block hosts file.
- `spt firewall plan / apply --dry-run / interfaces`.
- `spt observe metrics` — read `<state_dir>/metrics.prom`.
- `spt log tail` — last 200 lines of `<state_dir>/spt.log`.
- `spt diagnose run / bundle` — structured checks + redacted bundle.
- `spt benchmark report compare` — diff two saved benchmark JSONs.
- `spt mcp serve --enable --stdio` — JSON-RPC MCP server.
- `spt completion generate <shell>` — bash, zsh, fish, powershell, elvish.

## Tracked in later milestones

A small set of subcommands return a structured "not yet implemented" error
in M0:

| Command                          | Milestone |
|----------------------------------|-----------|
| `config init / migrate / pull`   | M0+ / M5 |
| `config doctor`                  | M3       |
| `config trust add-url`           | M5       |
| `profile set / enable / disable` | M2       |
| `profile test`                   | M3       |
| `forward show / explain / test / throttle` | M2-M4 |
| `tunnel stats / sessions / failover / health` | M3-M4 |
| `auth test / ssh3-login`         | M1+      |
| `secret store init / list / rotate` | M1     |
| `dns serve / status / query / record / upstream` | M2 |
| `firewall status / bind-preview` | M3       |
| `log test / export`              | M3       |
| `observe snmp / windows-event`   | M3       |
| `event ...`                      | M3       |
| `stats live / connections / throughput / errors / export` | M4 |
| `session show / close / drain / top` | M4   |
| `diagnose port / network / auth / trust / dns / bind / secrets / observability / mcp` | M5 |
| `benchmark run / latency / throughput / udp / reconnect / dns / limits` | M6 |
| `benchmark report export`        | M6       |
| `mcp inspect / policy`           | M7+      |

## Exit codes

The binary uses 38 stable exit codes from spec §7.4. The most common:

| Code | Name                  | Meaning                                |
|------|-----------------------|----------------------------------------|
| 0    | Success               | Successful completion.                 |
| 1    | InvalidArgs           | Bad CLI arguments.                     |
| 2    | InvalidConfig         | Config failed to load or validate.     |
| 3    | RuntimeFailure        | Generic runtime failure (incl. stubs). |
| 5    | AuthFailed            | Auth to a remote endpoint failed.      |
| 6    | TrustFailed           | Host key / TLS pin verification failed.|
| 16   | StateLockFailed       | Another spt process is running.        |
| 17   | SecretUnavailable     | Secret is not resolvable.              |
| 19   | KeyFailure            | Key generation / parse / mode check.   |
| 20   | PermissionDenied      | OS-level permission denied.            |
| 26   | McpFailed             | MCP server / policy failure.           |

Full mapping: see `crates/spt-core/src/exit_code.rs`.
