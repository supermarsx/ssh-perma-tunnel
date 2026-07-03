# CLI Overview

`spt` is the unified command-line interface for ssh-perma-tunnel (release 26.46).
It exposes the full runtime — tunnels, forwards, profiles, secrets, keys, services,
DNS, firewall rules, observability, diagnostics, and more — through a single
Docker-style command tree.

## Invocation shape

```
spt [GLOBAL OPTIONS] <group> <subcommand> [subcommand flags] [positional args]
```

Every invocation begins with zero or more global options, then a mandatory
**group** name, then the group's own subcommand and flags. Global options may
appear before the group name or anywhere after it — clap propagates them with
`global = true`.

```
# All equivalent:
spt --config /etc/spt/spt.toml tunnel run --foreground
spt tunnel run --foreground --config /etc/spt/spt.toml
spt tunnel --config /etc/spt/spt.toml run --foreground
```

## Global options

These flags are accepted at any position in the command line and apply to
every subcommand. They can also be set through environment variables where
noted.

| Flag | Short | Env var | Argument | Default | Effect |
|------|-------|---------|----------|---------|--------|
| `--config` | | `SPT_CONFIG` | `PATH` | — | Path to a single TOML config file. |
| `--config-dir` | | | `PATH` | — | Directory of `*.toml` configs loaded in lexical order. |
| `--config-url` | | `SPT_CONFIG_URL` | `URL` | — | HTTPS URL of a remote config to fetch. |
| `--config-fingerprint` | | | `SHA256` | — | SHA-256 SPKI pin for `--config-url`; required when the URL is not in the trust store. |
| `--state-dir` | | `SPT_STATE_DIR` | `PATH` | OS-standard | Override the runtime state directory (sockets, logs, vault). |
| `--portable` | | | | off | Keep all runtime state next to the executable; no OS install required. Pre-scanned by the binary before clap runs so paths are resolved before the runtime is built. |
| `--profile` | | | `NAME` | — | Restrict operations to the named profile where the subcommand supports filtering. |
| `--output` | | | `FORMAT` | `human` | Output format: `human`, `json`, `jsonl`, or `yaml`. |
| `--json` | | | | off | Convenience alias for `--output json`. |
| `--log-level` | | | `LEVEL` | `info` | Tracing log level: `error`, `warn`, `info`, `debug`, or `trace`. |
| `--color` | | | `MODE` | `auto` | Color policy: `auto` (TTY detection), `always`, or `never`. |
| `--no-color` | | | | off | Legacy alias for `--color never`. |
| `--quiet` | `-q` | | | off | Suppress non-essential output. |
| `--verbose` | `-v` | | | 0 | Increase verbosity; repeat for more (`-vv`, `-vvv`). |
| `--dry-run` | | | | off | Print what would happen without making changes. |

### Portable mode

When `--portable` is passed, `spt` stores all runtime state (sockets, logs,
vault, cached configs, staged updates) in a `data/` subdirectory adjacent to
the executable. This makes a fully self-contained deployment possible on any
host without administrator privileges or standard OS install locations.

The flag is pre-scanned from raw `argv` before the clap parser initialises so
that state-directory resolution happens before the supervisor or runtime touches
the filesystem. As a result, `--portable` can appear anywhere in the command
line and still take effect.

### Dry-run

`--dry-run` is a global flag that any subcommand may honour. When set,
subcommands that would mutate system state (firewall rules, service units,
config files, secret store, applied hosts file) print the planned actions
instead of executing them. Subcommands that are inherently read-only ignore the
flag silently.

## Config resolution

`spt` assembles its effective configuration from up to four sources, applied in
this order (later values override earlier ones where keys overlap):

1. **Default compiled-in values** — minimal safe defaults baked into the binary.
2. **File(s)** — `--config PATH` (single file) or `--config-dir PATH` (directory
   of `*.toml` files in lexical order). The `SPT_CONFIG` environment variable is
   equivalent to `--config`.
3. **Remote URL** — `--config-url URL` fetches a TOML document over HTTPS. The
   `SPT_CONFIG_URL` environment variable is equivalent. When a SHA-256
   fingerprint is supplied via `--config-fingerprint` or the trust store
   (`spt config trust add-url`), the fetched content is verified before use.
   A local atomic cache is maintained so the tunnel can start even when the
   remote URL is temporarily unavailable.
4. **CLI overrides** — subcommand-specific flags (for example, `spt profile set`
   `KEY=VALUE` pairs) overlay the loaded config in memory for the duration of
   the invocation.

When no explicit config source is given, `spt` searches the OS-standard
locations in order:

- `$XDG_CONFIG_HOME/ssh-perma-tunnel/config.toml` (Linux)
- `~/.config/ssh-perma-tunnel/config.toml` (Linux fallback)
- `~/Library/Application Support/ssh-perma-tunnel/config.toml` (macOS)
- `%APPDATA%\ssh-perma-tunnel\config.toml` (Windows)

Use `spt config init` to create a starter file and `spt config validate` to
check it before starting tunnels.

## Output formats

Most subcommands support machine-readable output in addition to the default
human-readable text. The format is selected globally with `--output` or with
the shorthand `--json` alias:

| Value | Description |
|-------|-------------|
| `human` | Formatted text for interactive terminal use (default). |
| `json` | Single JSON object or array on stdout. |
| `jsonl` | One JSON record per line (newline-delimited; suitable for streaming). |
| `yaml` | YAML document. |

Many subcommands also expose a local `--json` flag that is equivalent to
`--output json` for that invocation. The global `--output` flag always wins
over the local `--json` flag when both are given.

## Exit codes

`spt` defines 38 stable, named exit codes that are guaranteed not to change
across minor releases. The full table and the rationale behind each code are
documented in [security.md](security.md). The most important ones for scripting
are:

| Code | Meaning |
|------|---------|
| 0 | Success. |
| 1 | General / unexpected error. |
| 2 | Configuration error (parse failure, validation, missing required field). |
| 3 | Authentication failure (key rejected, wrong passphrase, certificate expired). |
| 4 | Network unreachable / connection refused. |
| 5 | Timeout. |
| 6 | Permission denied (OS-level, not auth). |
| 7 | Not found (profile, forward, secret, service). |
| 38 | Dry-run completed (would have mutated state). |

Exit code 38 is returned instead of 0 when `--dry-run` is passed to a
subcommand that would otherwise mutate state, so callers can detect dry-run
completion without parsing stdout.

## Shell completions

Completion scripts are generated at runtime from the live clap tree, so they
always reflect the exact build in use:

```
spt completion generate bash   | sudo tee /etc/bash_completion.d/spt
spt completion generate zsh    > ~/.zsh/completions/_spt
spt completion generate fish   > ~/.config/fish/completions/spt.fish
spt completion generate powershell >> $PROFILE
spt completion generate elvish > ~/.config/elvish/completions/spt.elv
```

## Command groups

The table below lists every top-level group with a one-line purpose and a link
to the matching section of the [full command reference](cli-reference.md).

| Group | Purpose | Reference |
|-------|---------|-----------|
| `config` | Manage configuration files (init, validate, render, diff, migrate, reload, pull, trust, encrypt/decrypt, gen-key). | [config](cli-reference.md#config) |
| `profile` | Manage SSH2/SSH3 tunnel profiles — add, configure, test, enable, disable, remove. | [profile](cli-reference.md#profile) |
| `forward` | Define and manage local, remote, and dynamic forwards. | [forward](cli-reference.md#forward) |
| `tunnel` | Start, stop, inspect, reload, failover, and live-monitor tunnels. | [tunnel](cli-reference.md#tunnel) |
| `service` | Install, uninstall, start, stop, restart, and inspect native OS services. | [service](cli-reference.md#service) |
| `key` | Generate, inspect, sign, verify, and install SSH keys and certificates. | [key](cli-reference.md#key) |
| `secret` | Manage the secret vault and OS keychain references. | [secret](cli-reference.md#secret) |
| `auth` | Authentication helpers (profile test, SSH3 OIDC device-flow login). | [auth](cli-reference.md#auth) |
| `dns` | Built-in DNS resolver: serve, query, manage records, render/apply/restore hosts file. | [dns](cli-reference.md#dns) |
| `firewall` | Plan, apply, and remove OS firewall/packet-filter rules; manage gateway and policy. | [firewall](cli-reference.md#firewall) |
| `log` | Tail logs, probe remote sinks, export structured log archives. | [log](cli-reference.md#log) |
| `observe` | Emit Prometheus/JSON metrics; SNMP agent (feature-gated); Windows Event Log integration. | [observe](cli-reference.md#observe) |
| `event` | List, test, and replay event bindings; manage event sinks. | [event](cli-reference.md#event) |
| `stats` | Snapshot summaries, live counters, connection tables, throughput windows, error reports. | [stats](cli-reference.md#stats) |
| `session` | List, show, close, drain, and live-top active sessions. | [session](cli-reference.md#session) |
| `ftp` | RFC 959/3659 FTP-to-SFTP translator service (passive-only). | [ftp](cli-reference.md#ftp) |
| `sftp` | One-shot SFTP file operations (get, put, list, cat, chmod, …) and FUSE/WinFsp mount management. | [sftp](cli-reference.md#sftp) |
| `diagnose` | Targeted checks — network, auth, trust, DNS, bind, port probe, service, secrets, observability, MCP — and support-bundle export. | [diagnose](cli-reference.md#diagnose) |
| `benchmark` | Controlled latency, throughput, UDP, reconnect, DNS, and limits benchmarks against forwards. | [benchmark](cli-reference.md#benchmark) |
| `mcp` | Start the built-in Model Context Protocol server; inspect capabilities; manage policy. | [mcp](cli-reference.md#mcp) |
| `ssh3-serve` | Run the spt SSH3 (QUIC/HTTP3) responder — the server half of an spt-to-spt SSH3 tunnel. | [ssh3-serve](cli-reference.md#ssh3-serve) |
| `status` | One-shot or live overview of the daemon, tunnels, profiles, forwards, and subsystems. | [status](cli-reference.md#status) |
| `status-api` | Serve, inspect, and manage tokens for the read-only HTTP status API. | [status-api](cli-reference.md#status-api) |
| `completion` | Generate shell completion scripts (bash, zsh, fish, powershell, elvish). | [completion](cli-reference.md#completion) |
| `about` | List bundled libraries, their licenses, and export attribution data. | [about](cli-reference.md#about) |
| `kill` | Terminate every running `spt` instance on this host. | [kill](cli-reference.md#kill) |
| `update` | Embedded auto-updater: check, download, apply, or run a one-shot full update. | [update](cli-reference.md#update) |

For a complete flag listing for any command, pass `--help`:

```
spt --help
spt <group> --help
spt <group> <subcommand> --help
```
