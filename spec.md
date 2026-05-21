# SSH Permanent Tunnel Tool Specification

Version: 0.2
Date: 2026-05-05
Repository: `ssh-perma-tunnel`

## 1. Purpose

This project provides a Rust-based command-line tool for establishing and maintaining permanent SSH tunnels. The tool is intended for operators and developers who need local or reverse port forwards that survive network failures, host restarts, service restarts, DNS changes, and normal operational drift.

Primary examples include:

- Exposing a remote SMTP relay locally, such as `127.0.0.1:2525 -> smtp.internal:25`.
- Reaching private databases, admin panels, or internal services through a bastion or jump host.
- Holding reverse tunnels open for controlled inbound access to a local service.
- Forwarding TCP services over SSH2 and TCP or UDP services over SSH3.
- Providing an internal DNS resolver so clients can use stable internal names and preserve names used for TLS SNI.

The product is intentionally limited to:

- Rust implementation.
- CLI operation.
- Config-file driven behavior.
- SSH2 and SSH3 tunnel protocols only.
- Cross-platform operation on Linux, macOS, and Windows.
- Local MCP integration for controlled CLI/config management.

There is no graphical interface, web console, REST API, or background control socket in scope for the core product.

## 2. Design Goals

1. Permanent operation: tunnels should remain available for months without manual restart.
2. Predictable recovery: connection loss, DNS changes, authentication failures, bind failures, and service restarts should have explicit retry and failure policies.
3. Safe defaults: local binds default to loopback, trust verification is strict, secrets are redacted, and SSH3 is marked experimental.
4. Cross-platform service management: the same CLI should install, run, stop, inspect, and remove system services on supported operating systems.
5. Rich observability: logs, status output, event history, byte counters, and error categories should be usable in incident response.
6. Configuration as source of truth: runtime state can exist, but desired tunnel behavior comes from config files.
7. Protocol clarity: SSH2 and SSH3 behavior should be modeled separately instead of hiding major protocol differences behind vague compatibility claims.
8. Built-in manageability: every major concern should have its own Docker-style command group with deep help text and examples.
9. Internal service discovery: tunnel endpoints should be easy to address by meaningful internal names, including names used by TLS SNI.
10. Secure credential handling: passwords, key passphrases, tokens, and generated key material must be encrypted at rest and minimized in memory.
11. Full observability: local logs, remote logs, metrics, SNMP, Windows Event Log, event bindings, and MCP inspection must all be supported.
12. Controlled resource use: bandwidth throttles, connection limits, rate limits, retry budgets, and failover policies must be configurable.
13. Full configurability: every runtime capability, timing, protocol option, listener policy, diagnostic behavior, event action, and observability sink must be configurable by file and manageable by CLI.

## 3. Non-Goals

The tool MUST NOT attempt to provide:

- SSH1 support.
- Telnet, raw TLS, WireGuard, OpenVPN, or generic proxy tunneling outside SSH2 or SSH3.
- A GUI, tray application, browser UI, or mobile UI.
- A persistent REST, GraphQL, gRPC, or WebSocket management API.
- A general SSH client replacement for interactive shells, file copy, SCP, SFTP, or remote command execution.
- A general SSH server.
- Full VPN semantics, TUN/TAP devices, network routes, or transparent packet interception.
- Plaintext secret storage in config files, state files, logs, command histories, or generated examples.
- Browser proxy features outside explicit SSH2 dynamic port forwarding.

## 4. Protocol Scope

Capability policy:

- Capabilities listed in this specification are required product capabilities unless explicitly marked as an out-of-scope non-goal.
- If a required product capability depends on a remote SSH server or SSH3 peer capability, the CLI MUST implement local support and fail with a clear `unsupported_feature` diagnostic when the peer cannot negotiate it.
- Dynamic proxy support is scoped to explicit SSH2 client-side dynamic port
  forwards. It MUST accept SOCKS4, SOCKS4A, SOCKS5, and HTTP CONNECT when
  enabled by capability policy.

### 4.1 SSH2

SSH2 support targets the standardized SSHv2 protocol family:

- SSH transport layer as defined by RFC 4253.
- SSH connection protocol as defined by RFC 4254.
- TCP forwarding through `direct-tcpip`, `tcpip-forward`, and `forwarded-tcpip` channels.

Required SSH2 capabilities:

- Client authentication using public keys.
- Client authentication using password, keyboard-interactive, and agent-backed identities when configured.
- Host key verification using OpenSSH-compatible `known_hosts`.
- Local TCP forwarding.
- Remote TCP forwarding.
- Dynamic TCP proxy forwarding over SSH2 `direct-tcpip`.
- Multiple forwards over a single SSH session.
- Keepalive and reconnect handling.
- Jump-host chains using SSH2 TCP forwarding.
- SSH agent authentication.
- OpenSSH user certificates.
- Password authentication from a non-interactive secret source.
- Keyboard-interactive authentication only when all prompts can be answered from config-backed secret providers.
- SSH key generation for supported key types.
- Encrypted private key output and passphrase rotation.
- Key inspection, fingerprinting, and public-key export.
- OS keychain-backed secret retrieval on Linux, macOS, and Windows.

SSH2 limitations:

- UDP forwarding is not part of standard SSH2 forwarding and MUST NOT be advertised as an SSH2 capability.
- Dynamic proxy forwarding is supported for SOCKS4, SOCKS4A, SOCKS5, and HTTP
  CONNECT over SSH2 `direct-tcpip`.
- SSH agent forwarding is out of scope for tunnel operation and MUST be disabled by default.
- X11 forwarding is out of scope.
- PTY allocation and shell sessions are out of scope.

### 4.2 SSH3

SSH3 support targets the experimental SSH-over-HTTP/3 work that has also been renamed in IETF draft materials as "Remote terminal over HTTP/3 connections." The implementation MUST treat SSH3 as experimental until the protocol has a stable standards-track specification and compatible production implementations.

Known SSH3/RTH3 characteristics relevant to this tool:

- Runs SSH connection semantics over HTTP/3.
- Uses QUIC and TLS 1.3 for secure channel establishment.
- Uses HTTP authentication mechanisms for user authentication.
- Can support TCP forwarding over reliable QUIC streams.
- Can support UDP forwarding over QUIC datagrams where the peer supports it.
- Uses X.509/TLS server authentication rather than SSH2 host keys.
- Can use URL paths or URI templates to identify the remote terminal endpoint.

Required SSH3 capabilities:

- SSH3 MUST be compiled into default builds and usable without a build-time feature gate.
- Profiles select SSH3 with `protocol = "ssh3"`.
- Strict TLS certificate verification by default.
- URL/path configuration for the remote endpoint.
- Version negotiation fields compatible with the selected draft or implementation.
- Local TCP forwarding.
- Clear failure messages when the remote peer lacks required forwarding features.
- Local UDP forwarding.
- Remote TCP forwarding.
- Remote UDP forwarding.
- Bearer-token authentication.
- HTTP Basic authentication from a secret provider.
- Public-key style authentication if supported by the selected draft/prototype.
- OIDC device-flow login as a CLI preflight command that writes token material to a configured secret location.
- OS keychain-backed token and password retrieval on Linux, macOS, and Windows.

SSH3 limitations:

- SSH3 MUST remain enabled by default, but diagnostics MUST label it experimental while the relevant protocol draft is non-final.
- SSH3 profiles MUST surface an explicit warning in `validate`, `doctor`, and first-run logs unless the config sets `acknowledge_experimental = true`.
- SSH3 support MUST NOT silently fall back to SSH2, HTTP/2, raw TLS, or another protocol.
- QUIC-over-TCP or HTTP/2 fallback is out of scope for the MVP unless a later draft stabilizes that behavior.

## 5. Product Shape

The tool is a single CLI binary named `spt` by default. Packaging MAY install aliases such as `ssh-perma-tunnel`, but documentation and examples should use `spt`.

Execution modes:

- Foreground mode: `spt tunnel run` starts tunnel supervision in the current terminal.
- Service mode: the same binary is launched by systemd, launchd, Windows Service Control Manager, or another supported OS service manager.
- Inspection mode: commands such as `spt tunnel status`, `spt log tail`, and `spt config validate` read config and state files.
- Setup mode: commands such as `spt service install` generate native service definitions.
- Management mode: commands such as `spt profile add`, `spt forward add`, `spt secret set`, and `spt dns record add` update config files with validation and atomic backups.
- MCP mode: `spt mcp serve` exposes a local Model Context Protocol server for controlled inspection and config edits only when MCP is explicitly enabled.

The CLI MUST be the primary control interface. MCP support is a local integration surface that delegates to the same validation and config-writing machinery as the CLI. All durable desired state MUST live in config files. Runtime state files may be used for status inspection, lock ownership, counters, and event history.

## 6. Core Concepts

Profile:

A named unit of tunnel supervision. A profile owns one SSH session, one remote endpoint, authentication settings, reconnect policy, and one or more forwards.

Forward:

A single local or remote port forwarding rule inside a profile.

Session:

The live SSH2 or SSH3 authenticated connection to the remote endpoint.

Listener:

A local or remote socket bound to accept forwarded traffic.

Target:

The host and port reached after traffic enters a forward.

Supervisor:

The runtime component that starts profiles, applies backoff, tracks health, reloads config, and shuts down cleanly.

State directory:

A local directory containing lock files, status snapshots, counters, PID files where relevant, and short event history.

Transparent DNS resolver:

A disabled-by-default local resolver that maps configured names to tunnel listener addresses, remote targets, or service aliases and transparently forwards all other DNS queries to chosen upstream DNS servers. It allows applications to connect to names such as `smtp.relay.spt.local` instead of raw local ports, which preserves hostnames used for TLS SNI when the client supports normal DNS resolution.

Secret store:

The encrypted at-rest storage and OS keychain integration used for passwords, tokens, key passphrases, and generated credential material.

Event binding:

A configured reaction to an event, such as writing a Windows Event Log entry, emitting an SNMP trap, sending remote logs, running an approved local command, or notifying an MCP client.

Observability sink:

A destination for logs, metrics, traces, health events, SNMP data, or Windows events.

Firewall and bind policy:

The configuration that controls which IP address, loopback address, interface, wildcard address, or OS firewall rule is used for each listener.

MCP server:

A local Model Context Protocol server that exposes resources and tools for config inspection, status inspection, log querying, diagnostics, and guarded config mutations.

## 7. Command-Line Interface

### 7.1 Global Flags

The CLI MUST support:

```text
spt [GLOBAL OPTIONS] <group> <command> [COMMAND OPTIONS]
spt --help
spt <group> --help
spt <group> <command> --help

GLOBAL OPTIONS:
  --config <path>
  --config-dir <path>
  --config-url <https-url>
  --config-fingerprint <sha256>
  --state-dir <path>
  --profile <name>
  --output <human|json|jsonl|yaml>
  --json
  --log-level <error|warn|info|debug|trace>
  --color <auto|always|never>
  --quiet
  --verbose
  --dry-run
```

Config resolution order:

1. Explicit `--config` path.
2. Explicit `--config-dir` path, loading `*.toml` in lexical order.
3. Explicit `--config-url` HTTPS URL with required trust validation.
4. Environment variable `SPT_CONFIG`.
5. Environment variable `SPT_CONFIG_URL`.
6. Platform default config path.

Remote config requirements:

- Remote config URLs MUST use HTTPS.
- Remote config TLS verification MUST be strict by default.
- Remote config SHOULD be pinned with `--config-fingerprint` or config trust policy for unattended service use.
- HTTP, plaintext, self-signed without pinning, and redirect-to-insecure config URLs MUST be rejected.
- Remote config fetches MUST use bounded timeouts, size limits, ETag or content fingerprinting, and atomic local cache writes.
- A cached remote config MAY be used during transient fetch failure only when policy explicitly allows it.
- Remote config credentials MUST use `secret://` references or OS keychain references.

Default config paths:

- Linux: `$XDG_CONFIG_HOME/ssh-perma-tunnel/config.toml`, then `~/.config/ssh-perma-tunnel/config.toml`.
- macOS: `~/Library/Application Support/ssh-perma-tunnel/config.toml`.
- Windows: `%APPDATA%\ssh-perma-tunnel\config.toml`.

System service config defaults:

- Linux: `/etc/ssh-perma-tunnel/config.toml`.
- macOS: `/Library/Application Support/ssh-perma-tunnel/config.toml`.
- Windows: `%ProgramData%\ssh-perma-tunnel\config.toml`.

### 7.2 Command Organization

Commands MUST be grouped by concern in a Docker-style shape:

```text
spt config <command>
spt profile <command>
spt forward <command>
spt tunnel <command>
spt service <command>
spt key <command>
spt secret <command>
spt auth <command>
spt dns <command>
spt firewall <command>
spt log <command>
spt observe <command>
spt event <command>
spt stats <command>
spt session <command>
spt diagnose <command>
spt benchmark <command>
spt mcp <command>
spt completion <command>
```

Each command group MUST provide:

- A concise overview in `<group> --help`.
- At least three examples in help output when the group has mutating commands.
- JSON output with global `--output json`; command-local `--json` is a convenience alias for the same output mode.
- A `--dry-run` mode for commands that modify config, services, secrets, keys, or local DNS state.
- Atomic config writes with a timestamped backup for config-mutating commands.

### 7.3 Required Commands

Config commands:

```text
spt config init [--path <path>] [--example <smtp|jump|reverse|ssh3|dns|observability|mcp>]
spt config validate [--strict]
spt config doctor [--network] [--service] [--secrets] [--dns] [--observability]
spt config render [--redacted|--json]
spt config diff --from <path> --to <path>
spt config migrate --from-version <n> --to-version <n>
spt config reload [--mode <signal|watch|service|none>] [--wait]
spt config pull --url <https-url> [--fingerprint <sha256>] [--out <path>] [--cache]
spt config trust add-url --url <https-url> --fingerprint <sha256>
```

Profile commands:

```text
spt profile list [--json]
spt profile show <name> [--redacted|--json]
spt profile add <name> --protocol <ssh2|ssh3> --host <host> --user <user>
spt profile configure [--name <name>] [--tui|--no-tui] [--from-template <name>]
spt profile set <name> <key=value>...
spt profile enable <name>
spt profile disable <name>
spt profile remove <name>
spt profile test <name> [--connect-only|--bind-only|--auth-only|--trust-only|--dns-only]
```

Forward commands:

```text
spt forward list [--profile <name>] [--json]
spt forward show <profile>/<forward> [--friendly|--json]
spt forward add local --profile <name> --listen <addr:port> --to <host:port> [--tcp|--udp]
spt forward add remote --profile <name> --listen <addr:port> --to <host:port> [--tcp|--udp]
spt forward explain <profile>/<forward>
spt forward test <profile>/<forward> [--connect] [--dns-name <name>]
spt forward throttle <profile>/<forward> [--in <rate>] [--out <rate>] [--connections <n>]
spt forward remove <profile>/<forward>
```

Tunnel runtime commands:

```text
spt tunnel run [--foreground] [--once] [--profiles <a,b,c>]
spt tunnel status [--watch] [--json]
spt tunnel stats [--profile <name>] [--forward <name>] [--interval <duration>] [--json]
spt tunnel sessions [--profile <name>] [--forward <name>] [--json]
spt tunnel stop [--profile <name>] [--grace <duration>]
spt tunnel reload [--wait]
spt tunnel health [--json]
spt tunnel failover <profile> [--to <endpoint>] [--reason <text>]
```

Service commands:

```text
spt service install --config <path> [--user|--system] [--name <name>]
spt service uninstall --config <path> [--user|--system] [--name <name>]
spt service start --config <path> [--user|--system] [--name <name>]
spt service stop --config <path> [--user|--system] [--name <name>]
spt service restart --config <path> [--user|--system] [--name <name>]
spt service status --config <path> [--user|--system] [--name <name>] [--json]
spt service render --config <path> [--user|--system] [--format <unit|plist|windows>]
```

Key and authentication commands:

```text
spt key generate --type <ed25519|ecdsa-p256|rsa> --out <path> [--bits <n>] [--comment <text>] [--encrypt]
spt key inspect <path> [--fingerprint <sha256|md5>] [--json]
spt key public <path> [--out <path>]
spt key change-passphrase <path>
spt key sign-cert --ca-key <path> --public-key <path> --principal <name> --out <path>
spt key verify-cert <path>
spt key install-public --profile <name> --key <path> [--remote-command <command>]
spt auth test <profile>
spt auth ssh3-login <profile>
```

Secret commands:

```text
spt secret store init [--backend <auto|keychain|vault>]
spt secret set <name> [--prompt|--from-env <env>|--from-file <path>]
spt secret get <name> [--reveal]
spt secret list [--json]
spt secret rotate <name>
spt secret remove <name>
spt secret doctor
```

DNS commands:

```text
spt dns serve [--foreground] [--config <path>]
spt dns status [--json]
spt dns query <name> [--type <A|AAAA|SRV|TXT>]
spt dns upstream set <addr:port>...
spt dns record add <name> --addr <addr> [--ttl <duration>]
spt dns record remove <name>
spt dns hosts render [--out <path>]
spt dns hosts apply [--path <hosts-file>] [--backup]
spt dns hosts restore [--backup <path>]
```

Firewall and binding commands:

```text
spt firewall plan [--profile <name>] [--forward <name>] [--json]
spt firewall apply [--profile <name>] [--forward <name>] [--user|--system] [--dry-run]
spt firewall remove [--profile <name>] [--forward <name>] [--user|--system] [--dry-run]
spt firewall status [--json]
spt firewall interfaces [--json]
spt firewall bind-preview --forward <profile>/<forward> [--json]
```

Logging, observability, and event commands:

```text
spt log tail [--follow] [--profile <name>] [--since <duration>] [--json]
spt log test --sink <name>
spt log export --format <jsonl|csv> --since <duration>
spt observe metrics [--format <prometheus|json>]
spt observe snmp serve [--foreground]
spt observe snmp test-trap --sink <name>
spt observe windows-event install-source [--source <name>]
spt observe windows-event test [--source <name>]
spt event list [--json]
spt event test <binding-name>
spt event replay --since <duration> --binding <name>
spt event sink test <sink-name> [--json]
spt event sink list [--json]
```

Stats commands:

```text
spt stats summary [--profile <name>] [--forward <name>] [--json]
spt stats live [--interval <duration>] [--profile <name>] [--forward <name>]
spt stats connections [--profile <name>] [--forward <name>] [--json]
spt stats throughput [--profile <name>] [--forward <name>] [--window <duration>] [--json]
spt stats errors [--since <duration>] [--profile <name>] [--json]
spt stats export --format <json|jsonl|csv|prometheus> --since <duration>
```

Session commands:

```text
spt session list [--profile <name>] [--forward <name>] [--json]
spt session show <session-id> [--json]
spt session close <session-id> [--grace <duration>] [--reason <text>]
spt session drain --profile <name> [--forward <name>] [--timeout <duration>]
spt session top [--sort <age|bytes|rate|errors>] [--limit <n>]
```

Diagnostic commands:

```text
spt diagnose run [--all] [--offline|--online] [--profile <name>] [--report <path>] [--json]
spt diagnose network [--profile <name>] [--endpoint <name>] [--json]
spt diagnose auth <profile> [--json]
spt diagnose trust <profile> [--json]
spt diagnose dns [--name <name>] [--json]
spt diagnose bind [--profile <name>] [--forward <name>] [--json]
spt diagnose port --host <host> --port <port> [--tcp|--udp] [--autodetect-service] [--json]
spt diagnose service --config <path> [--user|--system] [--json]
spt diagnose secrets [--json]
spt diagnose observability [--sink <name>] [--json]
spt diagnose mcp [--json]
spt diagnose bundle --out <path> [--redacted] [--since <duration>]
```

Benchmark commands:

```text
spt benchmark run --profile <name> --forward <name> [--duration <duration>] [--connections <n>] [--json]
spt benchmark latency --profile <name> --forward <name> [--samples <n>] [--json]
spt benchmark throughput --profile <name> --forward <name> [--duration <duration>] [--payload-size <size>] [--json]
spt benchmark udp --profile <name> --forward <name> [--duration <duration>] [--packet-size <size>] [--pps <n>] [--json]
spt benchmark reconnect --profile <name> [--iterations <n>] [--json]
spt benchmark dns --name <name> [--samples <n>] [--json]
spt benchmark limits --profile <name> --forward <name> [--json]
spt benchmark report compare --baseline <path> --candidate <path>
spt benchmark report export --format <json|jsonl|csv|markdown> --out <path>
```

MCP commands:

```text
spt mcp serve [--stdio|--listen <127.0.0.1:port>] [--read-only] [--config <path>] [--enable]
spt mcp inspect [--json]
spt mcp policy show
spt mcp policy set <key=value>...
```

Completion commands:

```text
spt completion generate <bash|zsh|fish|powershell>
```

Command behavior:

- `config validate` checks syntax, schema, paths, port definitions, protocol support, and obvious security mistakes.
- `profile configure` provides an interactive TUI wizard for creating and editing profiles while still writing normal TOML config.
- `profile configure --tui` MUST expose every profile capability, including SSH2/SSH3 protocol settings, auth, trust, crypto, timings, reconnect, instability detection, failover, forwards, DNS names, bind/interface policy, bandwidth limits, event bindings, diagnostics, and observability tags.
- `config doctor` performs environment checks, including service manager availability, file permissions, key readability, DNS resolution, keychain access, remote logging reachability, SNMP settings, Windows Event Log access, and port bind availability.
- `tunnel run --once` starts configured tunnels and exits non-zero if any required profile fails its startup checks.
- `tunnel status` reads state files and native service state; it MUST NOT require a REST-style management daemon.
- `stats` commands read counters, current session tables, and state snapshots without requiring a management daemon.
- `session` commands inspect and manage currently active forwarded connections and SSH/SSH3 sessions.
- `diagnose` commands perform targeted checks and can emit a redacted support bundle.
- `benchmark` commands generate controlled load against configured forwards and MUST honor configured throttles, safety limits, and redaction.
- `firewall` commands inspect, preview, apply, and remove OS firewall or packet-filter rules required by configured binds.
- `log tail` reads configured log files, remote sink checkpoints where supported, or native service log backends.
- `config reload` follows the configured reload policy and explains when reload is disabled by policy.
- `service` commands MUST always operate on one config file. Profile subsets are runtime filters only and MUST NOT create separate service definitions.
- `mcp serve` MUST refuse to start unless `[mcp].enabled = true` or `--enable` is explicitly provided.

### 7.4 Exit Codes

Required exit codes:

```text
0   Success
1   Invalid command-line arguments
2   Invalid configuration
3   Runtime failure
4   One or more required profiles failed
5   Authentication failed
6   Trust verification failed
7   Local bind failed
8   Remote bind failed
9   Service manager operation failed
10  Unsupported platform or unsupported feature
11  DNS resolution or internal DNS failure
12  Network unreachable or connection refused
13  Keepalive timeout
14  Config reload failed
15  Logging sink unavailable
16  State lock or state directory failure
17  Secret unavailable, locked, or denied
18  Secret encryption or decryption failed
19  Key generation, key parsing, or key permission failure
20  Permission denied
21  Resource exhaustion or out-of-memory condition
22  Rate limit or throttle policy rejected the operation
23  Failover targets exhausted
24  SNMP or metrics exporter failure
25  Windows Event Log operation failed
26  MCP server or MCP policy failure
27  Remote observability sink rejected data
28  Partial success with degraded non-required profiles
29  Health check failed
30  Version or migration failure
31  Internal error
32  Diagnostic check failed
33  Diagnostic bundle generation failed
34  Benchmark failed
35  Benchmark refused by safety policy
36  Session not found
37  Session close or drain failed
```

## 8. Configuration Format

The primary config format MUST be TOML. JSON output MAY be available for rendered config and status, but JSON MUST NOT replace TOML as the user-facing config format.

The config schema MUST be versioned:

```toml
version = 1
```

The tool MUST reject unknown top-level tables in strict mode. By default, unknown keys SHOULD produce warnings to support forward compatibility.

### 8.1 Full SSH2 Example

```toml
version = 1

[runtime]
state_dir = "~/.local/state/ssh-perma-tunnel"
required_profiles = ["smtp-relay"]
shutdown_grace = "20s"

[runtime.threads]
model = "multi_thread"
orchestrator_threads = 1
service_threads = 2
logging_threads = 1
dns_threads = 1
observability_threads = 1
blocking_worker_threads = 4
idle_tick = "1s"

[runtime.reload]
mode = "watch"
debounce = "2s"
require_valid_config = true

[runtime.remote_config]
enabled = false
url = ""
fingerprint_sha256 = ""
cache_file = "~/.local/state/ssh-perma-tunnel/remote-config.toml"
allow_cached_on_failure = true

[logging]
level = "info"
format = "json"
destinations = ["file", "remote-syslog"]
file = "~/.local/state/ssh-perma-tunnel/spt.jsonl"
rotate = "daily"
max_files = 14
redact = ["secrets", "usernames"]

[[logging.remote]]
name = "remote-syslog"
type = "syslog_tls"
endpoint = "logs.example.com:6514"
ca_file = "/etc/ssl/certs/ca-certificates.crt"

[secrets]
backend = "auto"
vault_file = "~/.local/state/ssh-perma-tunnel/secrets.vault"
encrypt_at_rest = true
memory_protection = "best_effort"

[dns]
enabled = false
mode = "transparent_forwarder"
bind = "127.0.0.1:5353"
zone = "spt.local"
ttl = "30s"
auto_records = true
upstream = ["1.1.1.1:53", "8.8.8.8:53"]
hosts_file_mode = "render_only"

[firewall]
enabled = true
manager = "auto"
apply_rules = false
bind_policy = "explicit"
default_interface = ""
allow_all_interfaces = false

[observability.metrics]
enabled = true
format = "prometheus"
state_file = "~/.local/state/ssh-perma-tunnel/metrics.prom"

[observability.snmp]
enabled = true
version = "v3"
engine_id = "80004fb805737074"
bind = "127.0.0.1:1161"
trap_sinks = ["noc"]

[[observability.snmp.traps]]
name = "noc"
endpoint = "snmp-noc.example.com:162"
user = "spt"
auth_secret = "secret://snmp/auth"
privacy_secret = "secret://snmp/privacy"

[[events.bindings]]
name = "smtp-failed-remote-log"
on = ["profile.failed", "forward.bind_failed"]
actions = ["remote-log", "windows-event", "email-ops", "push-ops"]
min_level = "warn"

[[events.sinks]]
name = "email-ops"
type = "email"
smtp = "smtp.relay.spt.local:2525"
from = "spt@example.com"
to = ["ops@example.com"]

[[events.sinks]]
name = "push-ops"
type = "webhook_post"
url = "https://hooks.example.com/spt"
auth = "secret://events/push-token"

[[profiles]]
name = "smtp-relay"
enabled = true
protocol = "ssh2"
host = "bastion.example.com"
port = 22
user = "relay"
connect_timeout = "10s"

[profiles.connection]
connect_timeout = "10s"
auth_timeout = "20s"
handshake_timeout = "15s"
channel_open_timeout = "10s"
tcp_nodelay = true
socket_keepalive = true
keepalive_idle = "60s"
keepalive_interval = "30s"
keepalive_retries = 3

[profiles.crypto]
policy = "modern"
allow_deprecated = false
warn_on_deprecated = true
ciphers = []
kex_algorithms = []
macs = []

[profiles.auth]
method = "public_key"
identity_file = "~/.ssh/id_ed25519"
passphrase = "secret://ssh/smtp-relay/passphrase"
agent = false

[profiles.trust]
mode = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict = true

[profiles.keepalive]
interval = "30s"
timeout = "10s"
max_missed = 3

[profiles.reconnect]
initial_delay = "1s"
max_delay = "5m"
jitter = "20%"
reset_after = "10m"
max_attempts = 0

[profiles.instability]
enabled = true
window = "10m"
max_disconnects = 3
max_keepalive_misses = 6
max_latency_p95 = "2s"
action = "mark_degraded"

[[profiles.endpoints]]
name = "primary"
host = "bastion.example.com"
port = 22
priority = 10

[[profiles.endpoints]]
name = "secondary"
host = "bastion-dr.example.com"
port = 22
priority = 20

[profiles.limits]
max_active_connections = 512
max_new_connections_per_second = 100
max_bytes_per_second_in = "20MiB"
max_bytes_per_second_out = "20MiB"

[[profiles.forwards]]
name = "smtp"
type = "local"
transport = "tcp"
bind = "127.0.0.1:2525"
bind_interface = "loopback"
bind_mode = "specific_ip"
target = "smtp.internal:25"
dns_names = ["smtp.relay.spt.local"]
sni_name = "smtp.relay.spt.local"
target_resolve = "remote"
required = true
on_bind_conflict = "fail"
idle_timeout = "10m"
max_connections = 256
max_bytes_per_second_in = "5MiB"
max_bytes_per_second_out = "5MiB"
```

### 8.2 SSH2 Jump Host Example

```toml
version = 1

[[profiles]]
name = "postgres-through-bastion"
enabled = true
protocol = "ssh2"
host = "bastion.example.com"
port = 22
user = "ops"

[profiles.auth]
method = "agent"

[profiles.trust]
mode = "known_hosts"
strict = true

[[profiles.forwards]]
name = "postgres"
type = "local"
transport = "tcp"
bind = "127.0.0.1:15432"
target = "db01.internal:5432"
target_resolve = "remote"
required = true
```

For multi-hop chains, each hop MUST be declared explicitly:

```toml
[[profiles]]
name = "two-hop-admin"
enabled = true
protocol = "ssh2"
host = "jump1.example.com"
port = 22
user = "ops"

[[profiles.hops]]
name = "jump2"
protocol = "ssh2"
host = "jump2.internal"
port = 22
user = "ops"
target_resolve = "previous-hop"

[[profiles.forwards]]
name = "admin-ui"
type = "local"
transport = "tcp"
bind = "127.0.0.1:18443"
target = "admin.internal:443"
target_resolve = "remote"
```

### 8.3 SSH3 Example

```toml
version = 1

[[profiles]]
name = "ssh3-dns"
enabled = true
protocol = "ssh3"
acknowledge_experimental = true
endpoint = "https://edge.example.com:443/ssh3?user={username}"
user = "netops"
connect_timeout = "10s"

[profiles.auth]
method = "bearer_token"
token = "secret://ssh3/edge/token"

[profiles.tls]
server_name = "edge.example.com"
system_roots = true
ca_file = ""
pin_sha256 = []
allow_self_signed = false

[profiles.ssh3]
draft = "michel-remote-terminal-http3-00"
protocol_token = "remote-terminal"
enable_datagrams = true

[[profiles.forwards]]
name = "dns"
type = "local"
transport = "udp"
bind = "127.0.0.1:1053"
target = "dns.internal:53"
target_resolve = "remote"
required = true
udp_idle_timeout = "30s"
max_datagram_size = 1200
max_packets_per_second = 5000

[[profiles.forwards]]
name = "remote-dns"
type = "remote"
transport = "udp"
bind = "127.0.0.1:1053"
target = "127.0.0.1:53"
target_resolve = "local"
required = true
```

## 9. Config Schema

### 9.1 Runtime Table

```toml
[runtime]
state_dir = ""
required_profiles = []
shutdown_grace = "20s"
profile_start_parallelism = 8
file_lock = true

[runtime.threads]
model = "multi_thread"
orchestrator_threads = 1
service_threads = 2
logging_threads = 1
dns_threads = 1
observability_threads = 1
blocking_worker_threads = 4
idle_tick = "1s"

[runtime.reload]
mode = "watch"
debounce = "2s"
require_valid_config = true
restart_changed_profiles = true

[runtime.remote_config]
enabled = false
url = ""
fingerprint_sha256 = ""
cache_file = ""
allow_cached_on_failure = false
poll_interval = "5m"
```

Fields:

- `state_dir`: directory for status, locks, counters, and local event history.
- `required_profiles`: profiles that make the process unhealthy if they cannot start.
- `shutdown_grace`: time allowed for listeners and sessions to drain before forced close.
- `profile_start_parallelism`: maximum profiles started at once.
- `file_lock`: prevents multiple processes from supervising the same config and state directory.
- `runtime.threads.model`: runtime threading model. Allowed values are `multi_thread` and `single_thread_for_tests`.
- `runtime.threads.orchestrator_threads`: main monitor and orchestration thread count. Production configs MUST use exactly one orchestrator unless a future design documents sharding.
- `runtime.threads.service_threads`: worker threads for profile supervision and listener lifecycle.
- `runtime.threads.logging_threads`: dedicated logging and rotation workers.
- `runtime.threads.dns_threads`: transparent DNS and hosts-file worker threads.
- `runtime.threads.observability_threads`: metrics, SNMP, event sink, and Windows Event Log workers.
- `runtime.threads.blocking_worker_threads`: dedicated blocking workers for libssh2, filesystem, keychain, and OS service operations.
- `runtime.threads.idle_tick`: slow periodic tick used to avoid busy loops while idle.
- `runtime.reload.mode`: reload policy. Allowed values are `none`, `signal`, `watch`, and `service`.
- `runtime.reload.debounce`: file watch debounce interval.
- `runtime.reload.require_valid_config`: invalid new config is rejected while the previous config keeps running.
- `runtime.reload.restart_changed_profiles`: profile changes reconcile with minimal restart.
- `runtime.remote_config.enabled`: enables secure remote config retrieval.
- `runtime.remote_config.url`: HTTPS-only remote config URL.
- `runtime.remote_config.fingerprint_sha256`: required fingerprint for unattended remote config.
- `runtime.remote_config.cache_file`: local cache used atomically after successful fetch.
- `runtime.remote_config.allow_cached_on_failure`: allows last-known-good cache when fetch fails.
- `runtime.remote_config.poll_interval`: remote config refresh interval for services.

### 9.2 Logging Table

```toml
[logging]
level = "info"
format = "json"
destinations = ["stderr"]
file = ""
rotate = "size"
max_size = "100MiB"
max_files = 10
max_age = "30d"
compress_rotated = true
rotation_check_interval = "1m"
redact = ["secrets"]

[[logging.remote]]
name = "central-jsonl"
type = "https_jsonl"
endpoint = "https://logs.example.com/spt"
auth = "secret://logging/token"
timeout = "5s"
batch_size = 100
```

Allowed `format` values:

- `compact`
- `pretty`
- `json`

Allowed `destinations` values:

- `stderr`
- `stdout`
- `file`
- `journald`
- `syslog`
- `windows_event_log`
- `native`
- `remote-syslog`
- `remote-https`
- `otlp`

`native` means journald on systemd Linux, unified logging or log files on macOS depending service mode, and Windows Event Log on Windows.

Remote logging requirements:

- Remote syslog over TLS MUST be supported.
- HTTPS JSON Lines log shipping MUST be supported.
- OTLP log export MUST be supported.
- Remote log sinks MUST batch, retry with backoff, and drop only according to explicit queue policy.
- Remote log authentication MUST use `secret://` references or OS keychain references.
- Remote sink failures MUST not block active forwarding unless the sink is configured as `required = true`.

### 9.3 Secret Store

```toml
[secrets]
backend = "auto"
vault_file = ""
encrypt_at_rest = true
memory_protection = "best_effort"
keychain_namespace = "ssh-perma-tunnel"
```

Allowed `backend` values:

- `auto`
- `keychain`
- `vault`
- `env`

Secret store requirements:

- OS keychain integration MUST be available on Linux, macOS, and Windows.
- Linux MUST support Secret Service/libsecret where available and a documented fallback for headless systems.
- macOS MUST support Keychain Services.
- Windows MUST support Credential Manager or DPAPI-backed storage.
- The local vault backend MUST encrypt all credentials at rest using an authenticated encryption mode.
- The vault master key MUST be stored in the OS keychain when available.
- Secret values MUST be referenced as `secret://namespace/name` in config.
- Environment variables are allowed for automation but MUST be treated as less secure by `doctor`.

### 9.4 Internal DNS

```toml
[dns]
enabled = false
mode = "transparent_forwarder"
bind = "127.0.0.1:5353"
zone = "spt.local"
ttl = "30s"
auto_records = true
upstream = ["1.1.1.1:53"]
hosts_file = ""
hosts_file_mode = "render_only"

[[dns.records]]
name = "smtp.relay.spt.local"
type = "A"
value = "127.0.0.1"
ttl = "30s"
```

Internal DNS requirements:

- The transparent DNS resolver MUST be disabled by default.
- When enabled, the resolver MUST transparently forward all non-local names to the configured upstream DNS servers.
- The internal resolver MUST support A, AAAA, SRV, and TXT records.
- The resolver MUST support UDP and TCP DNS queries.
- The resolver MUST generate synthetic records for forwards that set `dns_names`.
- The resolver MUST support split-horizon behavior by answering configured names locally and forwarding other names to upstream resolvers.
- The resolver MUST support hosts-file rendering, apply, and restore for environments where running a DNS listener is not practical.
- Hosts-file manipulation MUST create backups, preserve unrelated entries, mark managed blocks, and require explicit confirmation or `--dry-run` preview.
- Users MUST be able to choose resolver mode per deployment: `disabled`, `transparent_forwarder`, `synthetic_only`, or `hosts_file`.
- DNS answers for tunnel names MUST be reflected in `spt dns query` and `spt forward explain`.
- DNS names used for TLS SNI MUST be preserved by having clients connect to the configured DNS name rather than raw `127.0.0.1` when possible.

### 9.5 Firewall And Bind Policy

```toml
[firewall]
enabled = true
manager = "auto"
apply_rules = false
bind_policy = "explicit"
default_interface = ""
allow_all_interfaces = false

[firewall.platform]
linux = "auto"
macos = "pf"
windows = "windows_firewall"
```

Firewall and bind requirements:

- Local forwards MUST support binding to a specific loopback IP, a specific non-loopback IP, a named interface, or all interfaces.
- Binding all interfaces MUST require `expose = true` and either explicit firewall policy or a documented `firewall.apply_rules = false` decision.
- Interface binding MUST support user preferences: `loopback`, `specific_ip`, `specific_interface`, `all_interfaces`, and `auto_interface`.
- `auto_interface` MUST select a bind address from a configured interface name, interface prefix, CIDR, route to target, or platform default.
- Firewall planning MUST show the exact ports, protocols, addresses, interfaces, and OS rules that would be applied.
- Firewall application MUST be idempotent and reversible where the platform supports managed rule identifiers.
- Rootless mode MUST degrade gracefully when firewall changes require privileges.
- Validation MUST warn when a bind address does not exist, an interface is down, a wildcard bind is exposed without firewall rules, or IPv4/IPv6 behavior is ambiguous.

### 9.6 Observability

```toml
[observability.metrics]
enabled = true
format = "prometheus"
state_file = ""

[observability.snmp]
enabled = true
version = "v3"
bind = "127.0.0.1:1161"
engine_id = ""
trap_sinks = []

[observability.windows_event]
enabled = true
source = "ssh-perma-tunnel"
channel = "Application"
install_source = true
```

Observability requirements:

- Metrics MUST be available as a state file and CLI output.
- Prometheus text format and JSON metrics output MUST be supported.
- SNMPv3 agent support MUST be available for secure polling.
- SNMP traps or informs MUST be supported for high-value events.
- A project MIB MUST define profiles, forwards, counters, states, reconnects, errors, bytes, drops, and failover state.
- Windows Event Log writing MUST support event source registration, structured event IDs, severity mapping, and local testing.
- Observability settings MUST never expose secrets.

### 9.7 Event Bindings

```toml
[[events.bindings]]
name = "profile-failed"
on = ["profile.failed"]
min_level = "warn"
actions = ["remote-log", "snmp-trap", "windows-event", "email-ops", "sms-oncall", "push-ops", "webhook-ops"]
throttle = "1m"

[[events.sinks]]
name = "email-ops"
type = "email"
smtp = "smtp.relay.spt.local:2525"
from = "spt@example.com"
to = ["ops@example.com"]
auth = "secret://events/email"

[[events.sinks]]
name = "sms-oncall"
type = "sms"
provider = "https_json"
url = "https://sms.example.com/send"
auth = "secret://events/sms-token"
to = ["secret://events/oncall-phone"]

[[events.sinks]]
name = "push-ops"
type = "push"
provider = "webpush"
endpoint = "https://push.example.com/spt"
auth = "secret://events/push-token"

[[events.sinks]]
name = "webhook-ops"
type = "http"
method = "POST"
url = "https://hooks.example.com/spt"
auth = "secret://events/webhook-token"
content_type = "application/json"

[[events.commands]]
name = "notify-local"
command = "C:\\Tools\\notify-spt.ps1"
args = ["--event", "{event}", "--profile", "{profile}"]
allow_exec = true
timeout = "10s"
```

Event binding requirements:

- Event bindings MUST support log emission, remote log emission, SNMP trap/inform, Windows Event Log writing, email, push notification, REST API call, HTTP request, POST request, SMS, local command execution, and MCP notification.
- HTTP-style event sinks MUST support configurable method, headers, body template, TLS trust, authentication, timeout, retry policy, and response-code success criteria.
- REST API and POST event sinks MUST be modeled as HTTP sinks with structured JSON templates.
- Email sinks MUST support SMTP with TLS, authentication through the secret store, configurable recipients, and rate limiting.
- SMS sinks MUST support provider adapters through HTTPS APIs and MUST keep phone numbers and provider credentials in the secret store when configured as sensitive.
- Push sinks MUST support provider-specific HTTPS payloads and secret-backed credentials.
- Local command execution MUST be disabled unless the binding sets `allow_exec = true`.
- Custom commands MUST use an allow-listed executable path, fixed argument templates, timeout, environment allow-list, and redacted event payloads.
- Event bindings MUST support throttling, retries, and dead-letter logging.
- Event payload templates MUST be redacted before dispatch.

### 9.8 MCP

```toml
[mcp]
enabled = false
default_mode = "read_only"
stdio = true
listen = ""
allow_secret_reveal = false
allow_write_tools = []
audit_events = true
```

MCP config requirements:

- MCP MUST be disabled by default.
- MCP MUST default to stdio and read-only behavior.
- `spt mcp serve` MUST require `[mcp].enabled = true` or the explicit `--enable` CLI override.
- Loopback TCP MUST require an explicit `listen` value.
- Non-loopback MCP binds MUST require `expose = true`, authentication policy, and `config validate --strict` approval.
- Write tools MUST be allow-listed.
- Secret reveal MUST be disabled by default and MUST remain disabled for MCP unless a future policy explicitly allows a narrow diagnostic flow.
- MCP policy MUST be inspectable with `spt mcp policy show`.

### 9.9 Diagnostics

```toml
[diagnostics]
bundle_dir = ""
include_recent_logs = true
include_status = true
include_stats = true
include_sessions = true
include_service_definitions = true
redact = true
max_bundle_size = "100MiB"
```

Diagnostic config requirements:

- Diagnostic bundles MUST be redacted by default.
- Session details included in diagnostic bundles MUST omit secrets and obey hostname/user redaction settings.
- Diagnostic bundles MUST have configurable size limits and time windows.
- `diagnose run --offline` MUST avoid network probes.
- `diagnose run --online` MUST clearly identify probes that contact remote endpoints.

### 9.10 Benchmarking

```toml
[benchmark]
enabled = true
default_duration = "30s"
max_duration = "5m"
max_connections = 256
max_bytes_per_second = "100MiB"
max_packets_per_second = 10000
require_explicit_target = true
allow_production_impact = false
results_dir = ""
```

Benchmark config requirements:

- Benchmarking MUST be enabled as a CLI capability by default but MUST require an explicit target profile and forward for live tunnel tests.
- Production-impacting benchmark options MUST be disabled by default.
- Benchmarks MUST honor profile and forward limits even when benchmark-level limits are higher.
- Benchmark results MUST be stored only when `results_dir` is configured or an output path is provided.
- Benchmark result files MUST not include secrets or raw tunneled payload data.

### 9.11 Profile Fields

Required profile fields:

```toml
name = "profile-name"
enabled = true
protocol = "ssh2"
user = "username"
```

SSH2 connection fields:

```toml
host = "example.com"
port = 22
```

SSH3 connection fields:

```toml
endpoint = "https://example.com:443/ssh3?user={username}"
acknowledge_experimental = true
```

Common configurable fields:

```toml
connect_timeout = "10s"
dns_resolution = "per_attempt"
network_change_reconnect = true
startup = "eager"
failure_policy = "retry"
tags = ["prod", "smtp"]

[profiles.connection]
connect_timeout = "10s"
auth_timeout = "20s"
handshake_timeout = "15s"
channel_open_timeout = "10s"
channel_window_size = "2MiB"
channel_max_packet_size = "32KiB"
tcp_nodelay = true
socket_keepalive = true
keepalive_idle = "60s"
keepalive_interval = "30s"
keepalive_retries = 3
read_timeout = "0s"
write_timeout = "0s"

[profiles.crypto]
policy = "modern"
allow_deprecated = false
warn_on_deprecated = true
ciphers = []
kex_algorithms = []
macs = []
host_key_algorithms = []

[profiles.instability]
enabled = true
window = "10m"
max_disconnects = 3
max_keepalive_misses = 6
max_latency_p95 = "2s"
min_successful_uptime = "5m"
action = "mark_degraded"

[[profiles.endpoints]]
name = "primary"
host = "bastion.example.com"
port = 22
priority = 10
weight = 100

[profiles.failover]
mode = "priority"
health_check = "tcp_connect"
fail_after = 3
restore_after = "5m"

[profiles.limits]
max_active_connections = 512
max_new_connections_per_second = 100
max_bytes_per_second_in = "20MiB"
max_bytes_per_second_out = "20MiB"
max_bits_per_second_in = ""
max_bits_per_second_out = ""
throttle_algorithm = "token_bucket"
max_connection_lifetime = "24h"
```

Allowed `startup` values:

- `eager`: connect immediately when the profile starts.
- `lazy`: bind local listeners immediately, connect on first inbound connection.

Allowed `failure_policy` values:

- `retry`: keep retrying according to reconnect policy.
- `fail_profile`: stop the profile after a terminal failure.
- `fail_process`: exit the whole process if this profile fails.

Connection capability requirements:

- Every transport, authentication, channel, keepalive, timeout, socket, retry, DNS, crypto, and forwarding capability exposed by the application MUST be configurable through TOML and CLI mutation commands.
- Connection timings MUST be independently configurable for TCP connect, SSH/QUIC handshake, trust verification, authentication, channel open, idle timeout, read timeout, write timeout, keepalive interval, keepalive timeout, reconnect delay, and graceful shutdown.
- Socket behavior MUST be configurable where the platform supports it, including TCP_NODELAY, keepalive, bind address, interface selection, dual-stack IPv4/IPv6 behavior, and listener backlog.
- SSH2 algorithm lists MUST be configurable for ciphers, key exchange, MACs, compression, and host key algorithms.
- SSH3 TLS and QUIC transport parameters MUST be configurable, including server name, ALPN/protocol token, idle timeout, keepalive, datagrams, stream limits, and certificate trust.

Crypto compatibility requirements:

- Modern cryptography MUST be the default policy.
- Deprecated or older ciphers, key exchange algorithms, MACs, host key algorithms, or TLS settings MAY be enabled only by explicit config.
- Enabling deprecated cryptography MUST emit warnings in `config validate`, `diagnose run`, startup logs, status, and diagnostic bundles.
- Deprecated cryptography warnings MUST identify the exact algorithm, profile, and safer replacement where known.
- Strict mode MUST be able to reject deprecated cryptography unless `allow_deprecated = true`.

Unstable connection detection requirements:

- Unstable connection detection MUST be configurable per profile.
- Instability signals MUST include disconnect frequency, keepalive miss frequency, reconnect churn, latency percentiles, packet loss for UDP, authentication churn, endpoint failovers, and short successful uptime.
- Instability actions MUST support `mark_degraded`, `failover`, `increase_keepalive`, `increase_backoff`, `emit_event`, and `restart_session`.
- Instability state MUST be visible in status, stats, diagnostics, metrics, SNMP, logs, and MCP resources.

Failover requirements:

- Profiles MUST support multiple endpoints with priority and weight.
- Failover MUST support ordered priority, weighted choice, and manual override.
- Health checks MUST support TCP connect, SSH transport handshake, SSH auth preflight, and SSH3 HTTP/3 endpoint preflight.
- Failover state MUST be visible in status, metrics, SNMP, logs, and MCP resources.
- Manual failover through `spt tunnel failover` MUST be recorded as an audit event.

Limit requirements:

- Profile and forward limits MUST be independently configurable.
- Bandwidth throttles MUST support inbound and outbound byte rates.
- Connection limits MUST support active connection count, new connection rate, queued accepts, and per-source limits where the listener can identify the source.
- UDP limits MUST support packets per second, bytes per second, active flow count, and datagram size.
- Exceeding limits MUST produce metrics and rate-limited logs.

### 9.12 Authentication

SSH2 public key:

```toml
[profiles.auth]
method = "public_key"
identity_file = "~/.ssh/id_ed25519"
certificate_file = "~/.ssh/id_ed25519-cert.pub"
passphrase = "secret://ssh/profile/passphrase"
agent = false
```

SSH2 agent:

```toml
[profiles.auth]
method = "agent"
identity_hint = "ssh-ed25519 AAAA..."
```

SSH2 password:

```toml
[profiles.auth]
method = "password"
password = "secret://ssh/profile/password"
keyboard_interactive = true
```

SSH3 bearer token:

```toml
[profiles.auth]
method = "bearer_token"
token = "secret://ssh3/profile/token"
```

SSH3 HTTP Basic:

```toml
[profiles.auth]
method = "http_basic"
password = "secret://ssh3/profile/password"
```

Requirements:

- Secret values MUST NOT be written directly in generated examples.
- Inline secrets in config MUST be rejected in strict mode and MUST produce warnings outside strict mode.
- All secret-bearing fields MUST support environment variable references.
- All secret-bearing fields MUST support `secret://` references.
- Secret file references MUST be supported with permission and ownership checks.
- OS keychain references MUST be fully supported on Linux, macOS, and Windows.
- SSH2 public key, SSH2 password, SSH2 keyboard-interactive, SSH agent, OpenSSH certificate, SSH3 bearer token, SSH3 HTTP Basic, SSH3 OIDC token, and SSH3 public-key style auth MUST all be modeled in config.
- Generated private keys MUST support encrypted-at-rest output.
- OpenSSH user certificate usage MUST be supported for SSH2.
- User certificate signing and verification commands MUST be available for deployments that manage their own SSH CA.
- Passphrase changes MUST never rewrite keys without a validated backup or atomic replacement.

### 9.13 Trust

SSH2 trust:

```toml
[profiles.trust]
mode = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict = true
accept_new = false
pin_sha256 = []
```

SSH3 TLS trust:

```toml
[profiles.tls]
server_name = "example.com"
system_roots = true
ca_file = ""
pin_sha256 = []
allow_self_signed = false
```

Requirements:

- SSH2 host key verification MUST be strict by default.
- SSH3 TLS certificate verification MUST be strict by default.
- `accept_new = true` MUST be supported for SSH2 and MUST log an audit event when a new host key is stored.
- `allow_self_signed = true` MUST require an explicit certificate pin or private CA file in strict mode.
- Trust bypass flags such as `insecure = true` MUST NOT exist as shortcuts.

### 9.14 Forward Fields

Common forward fields:

```toml
name = "forward-name"
type = "local"
transport = "tcp"
bind = "127.0.0.1:8080"
bind_mode = "specific_ip"
bind_interface = "loopback"
bind_interface_preference = []
bind_ipv6 = "auto"
expose = false
target = "service.internal:80"
listen = "127.0.0.1:8080"
connect = "service.internal:80"
dns_names = ["service.spt.local"]
sni_name = "service.spt.local"
target_resolve = "remote"
required = true
idle_timeout = "10m"
max_connections = 256
on_bind_conflict = "fail"
max_bytes_per_second_in = "10MiB"
max_bytes_per_second_out = "10MiB"
max_new_connections_per_second = 50
max_burst_bytes_in = "20MiB"
max_burst_bytes_out = "20MiB"
```

Allowed `type` values:

- `local`
- `remote`

Allowed `transport` values:

- `tcp`
- `udp`

Allowed `target_resolve` values:

- `local`
- `remote`
- `previous-hop`

Allowed `on_bind_conflict` values:

- `fail`
- `retry`
- `next_port`

Requirements:

- Local forwards MUST default to loopback binds.
- Non-loopback binds such as `0.0.0.0`, `::`, or public interface addresses MUST require `expose = true`.
- Local forwards MUST support binding to a specific localhost IP, a specific non-loopback IP, a named interface, automatically selected interfaces, or all interfaces.
- All-interface binds MUST support both `0.0.0.0` and `::` where the platform supports them and MUST make IPv4/IPv6 behavior explicit.
- Interface auto-binding MUST support preferences by interface name, interface alias, CIDR, route to target, interface type, or explicit priority list.
- Remote forwards MUST require an explicit `bind`.
- UDP forwards MUST require `protocol = "ssh3"` and negotiated datagram support.
- Dynamic forwards MUST require `protocol = "ssh2"`, `transport = "tcp"`, and
  `[capabilities].allow_dynamic_proxy = true`.
- Dynamic forwards MUST accept a configurable subset of `socks4`, `socks4a`,
  `socks5`, and `http_connect`; omitting the subset means all supported
  protocols are accepted.
- Privileged local ports MUST produce a clear permission error and remediation hint.
- `listen` and `connect` are user-friendly aliases for `bind` and `target`; rendered config MUST normalize to canonical fields.
- `dns_names` MUST create internal DNS records when `[dns].auto_records = true`.
- `sni_name` documents the name clients should use for TLS SNI and MUST be shown by `spt forward explain`.
- Forward-level throttles MUST override profile-level throttles when stricter.
- Bandwidth limits MUST support bytes-per-second, bits-per-second display, burst sizes, per-connection limits, per-forward aggregate limits, per-profile aggregate limits, and UDP packet-rate limits.

## 10. Forwarding Semantics

### 10.1 Local TCP Forward

Local TCP forwarding listens on the local machine and opens a channel through the SSH session for each inbound connection.

Example:

```text
local 127.0.0.1:2525 -> SSH session -> smtp.internal:25
```

Behavior:

- For SSH2, the implementation uses `direct-tcpip`.
- For SSH3, the implementation uses the draft-compatible TCP forwarding channel over HTTP/3 streams.
- Backpressure MUST propagate in both directions.
- TCP half-closes MUST be preserved where the platform and protocol backend expose the required socket/channel state.
- Connection-level errors MUST be logged with forward name and error category.

### 10.2 Remote TCP Forward

Remote TCP forwarding asks the SSH server to listen on the remote side and forward accepted connections back through the session.

Example:

```text
remote 127.0.0.1:18080 -> SSH session -> local 127.0.0.1:8080
```

Behavior:

- For SSH2, the implementation uses `tcpip-forward` and receives `forwarded-tcpip`.
- For SSH3, remote TCP forwarding MUST be implemented by the client and negotiated with the peer. If the peer lacks support, startup MUST fail with `unsupported_feature` for required forwards.
- If a server assigns a remote port from `bind` port `0`, the assigned port MUST be stored in state and shown by `spt tunnel status`.

### 10.3 User-Friendly Forward Model

Forwarding must be understandable without knowing SSH protocol channel names.

The CLI and rendered config MUST describe each forward using this shape:

```text
name: smtp
direction: local
listen here: 127.0.0.1:2525
connect there: smtp.internal:25
resolve target: on remote side
dns names: smtp.relay.spt.local
tls sni name: smtp.relay.spt.local
```

Requirements:

- `spt forward explain` MUST show plain-language direction, listener, target, DNS behavior, SNI guidance, limits, and failover behavior.
- `spt forward add` MUST accept friendly flags such as `--listen`, `--to`, `--tcp`, `--udp`, `--dns-name`, and `--sni-name`.
- Validation errors MUST name the exact forward and explain whether the problem is a local bind, remote bind, DNS, protocol, limit, or trust issue.
- Dynamic proxy forwarding MUST reject unsupported proxy protocols with a clear
  message and MUST continue to reject UDP dynamic forwards.

### 10.4 UDP Forwarding

UDP forwarding is required for SSH3 profiles with datagram support enabled and negotiated. SSH2 UDP forwarding is not supported because it is not part of standard SSH2 forwarding.

Behavior:

- UDP packets are mapped to logical flows by local socket, source address, target address, and profile.
- Each flow has an idle timeout.
- Oversized datagrams MUST be dropped with rate-limited warnings unless fragmentation support is explicitly implemented.
- The implementation MUST track dropped datagram counts.
- DNS-style request/response workloads MUST be supported.
- Long-lived media or QUIC workloads MUST be supported when peer behavior and datagram sizes allow it.
- Local UDP and remote UDP forwards MUST both be supported for SSH3.
- UDP failover MUST preserve listener sockets where possible and expire in-flight flow mappings according to configured idle timeout.

### 10.5 Transparent DNS And Hosts-File Assisted Forwarding

Transparent DNS exists to make forwarded services feel like named services instead of raw ports while forwarding all unrelated DNS queries to the configured upstream DNS servers. It is disabled by default.

Example:

```text
smtp.relay.spt.local -> 127.0.0.1
client connects to smtp.relay.spt.local:2525
TLS client can send SNI smtp.relay.spt.local
SPT forwards traffic to smtp.internal:25 over SSH
```

Requirements:

- Internal DNS MUST support per-forward names through `dns_names`.
- Transparent DNS MUST forward non-managed names to the chosen upstream DNS servers.
- Transparent DNS MUST be disabled by default and enabled only by config or explicit CLI command.
- DNS records MUST be removed or marked unhealthy when their required forward is unavailable, according to policy.
- DNS health policy MUST be configurable as `always_answer`, `answer_when_listening`, or `answer_when_healthy`.
- SRV records MUST be supported so a service name can discover the local port.
- `spt dns hosts render` MUST provide a fallback for environments that cannot point clients at the built-in resolver.
- `spt dns hosts apply` and `spt dns hosts restore` MUST support managed hosts-file updates with backup and dry-run behavior.

### 10.6 Bind and Target Parsing

Address syntax MUST support:

```text
127.0.0.1:8080
0.0.0.0:8080
[::1]:8080
example.com:443
```

Unix domain sockets MUST be supported on Unix platforms using:

```text
unix:///path/to/socket
```

Windows named pipes are out of scope for the MVP.

## 11. Permanent Operation

### 11.1 State Machine

Each profile MUST expose one of these states:

```text
disabled
starting
resolving
connecting
authenticating
verifying_trust
connected
binding
forwarding
degraded
retry_wait
stopping
stopped
failed
```

Each forward MUST expose one of these states:

```text
disabled
binding
listening
remote_requested
active
degraded
retry_wait
stopped
failed
```

### 11.2 Reconnect Policy

Reconnect behavior:

- DNS MUST be re-resolved on each connection attempt when `dns_resolution = "per_attempt"`.
- Backoff MUST support jitter.
- Backoff MUST reset after a stable connected duration.
- Authentication failures MUST stop retries unless `retry_auth_failures = true`.
- Trust failures MUST stop retries until config or trust material changes.
- Bind conflicts follow each forward's `on_bind_conflict` policy.

Example:

```toml
[profiles.reconnect]
initial_delay = "1s"
max_delay = "5m"
jitter = "20%"
reset_after = "10m"
max_attempts = 0
retry_auth_failures = false
```

### 11.3 Keepalive

Keepalive behavior:

- SSH2 MUST use protocol-level keepalive or global requests when supported.
- SSH3 MUST rely on QUIC transport liveness plus application-level probes where useful.
- Missed keepalives beyond policy MUST trigger session replacement.
- Keepalive failures MUST preserve listener sockets where possible while the session reconnects.

Example:

```toml
[profiles.keepalive]
interval = "30s"
timeout = "10s"
max_missed = 3
```

### 11.4 Reload

The supervisor MUST support configurable config reload without full process restart.

Reload behavior:

- Added profiles are started.
- Removed profiles are stopped.
- Changed forwards are reconciled with minimal interruption.
- Changed authentication or trust settings require session replacement.
- Changed logging settings apply immediately where possible.
- Invalid new config MUST be rejected while the old config continues running.
- Reload mode MUST obey `[runtime.reload].mode`.
- File-watch reload MUST debounce changes and ignore partial writes.
- Signal reload MUST use SIGHUP on Unix and a platform-appropriate service control event on Windows.
- Reload disabled by config MUST make `spt config reload` exit with a clear policy error.

### 11.5 Failover

Failover behavior:

- Profiles MUST support multiple connection endpoints.
- Failover MUST be triggered by connection failure, keepalive failure, health check failure, explicit CLI command, or configured event binding.
- Failover MUST honor endpoint priority, weight, cooldown, and maximum attempts.
- Failback MUST be configurable as disabled, manual, or automatic after a healthy duration.
- Failover decisions MUST be logged, exported as metrics, emitted through SNMP, written to Windows Event Log when configured, and visible through MCP.

## 12. Service Management

The CLI MUST manage native service definitions where supported. A service definition MUST always correspond to exactly one config file. Services MUST NOT be installed per profile or per profile group.

Rootless operation:

- User-level services MUST be supported where the operating system service manager allows them.
- Linux systemd user services MUST not require root.
- macOS LaunchAgents MUST not require root.
- Windows Service Control Manager services normally require administrative rights; unprivileged Windows operation MUST be available through foreground mode and a documented Task Scheduler fallback when service installation is denied.
- Rootless installs MUST use user config, state, log, keychain, and DNS settings by default.

### 12.1 Linux

Required Linux support:

- systemd system service.
- systemd user service.
- journald logging when configured.
- `sd_notify` readiness where available.
- rootless systemd user install, start, stop, restart, status, and uninstall.
- OpenRC service generation.
- SysV init script generation.

Generated unit behavior:

- `ExecStart` runs `spt tunnel run --foreground --config <path>`.
- Restart policy is `on-failure`.
- The internal supervisor handles per-profile reconnects; systemd handles process-level failure.
- Service hardening MUST be applied when it does not block configured key and state paths.

### 12.2 macOS

Required macOS support:

- launchd LaunchAgent for user services.
- launchd LaunchDaemon for system services.
- Log file destination by default because launchd log inspection is less uniform than journald.
- rootless LaunchAgent install, start, stop, restart, status, and uninstall.

Generated plist behavior:

- Runs `spt tunnel run --foreground --config <path>`.
- Uses `KeepAlive` for process-level restart.
- Uses configured working directory and state directory.

### 12.3 Windows

Required Windows support:

- Windows Service Control Manager integration.
- Event Log logging when configured.
- Service installation with explicit config path.
- Event source registration through `spt observe windows-event install-source`.
- Task Scheduler fallback for user-level unprivileged startup when SCM service installation is unavailable.

Generated service behavior:

- Runs `spt tunnel run --foreground --config <path>`.
- Uses recovery actions for process-level restart.
- Stores runtime state under `%ProgramData%\ssh-perma-tunnel` by default for system services.
- User-level fallback tasks store runtime state under `%APPDATA%\ssh-perma-tunnel` by default.

### 12.4 Service Commands

Service commands MUST be idempotent where safe:

- Installing an already installed service with the same definition MUST report no change.
- Starting an already running service MUST return success.
- Stopping an already stopped service MUST return success.
- Uninstalling a missing service MUST return success with a warning unless `--strict` is provided.
- Every service command MUST require or resolve a config file.
- A service name MUST be derived from the config path and fingerprint when `--name` is omitted.
- Changing the config path for an installed service MUST require reinstall or an explicit update command in a future schema.

## 13. Logging and Observability

### 13.1 Log Events

Logs MUST be structured internally and MAY be rendered as compact text.

Required event fields:

```text
timestamp
level
event
message
profile
forward
protocol
session_id
attempt
local_addr
remote_addr
target_addr
bind_interface
detected_service
connection_id
error.kind
error.message
duration_ms
bytes_in
bytes_out
packets_in
packets_out
packets_dropped
rate_limit.applied
failover.from
failover.to
dns.name
crypto.deprecated_algorithm
secret.ref
mcp.client_id
```

Fields that are unavailable SHOULD be omitted instead of logged as empty strings.

### 13.2 Event Categories

Required event categories:

```text
config.loaded
config.invalid
config.remote_fetch_started
config.remote_fetch_succeeded
config.remote_fetch_failed
config.remote_cache_used
service.install
service.start
service.stop
profile.start
profile.connected
profile.disconnected
profile.retry_scheduled
profile.failed
trust.verified
trust.failed
auth.started
auth.succeeded
auth.failed
crypto.deprecated_enabled
crypto.policy_rejected
forward.bind_started
forward.listening
forward.bind_failed
forward.remote_requested
forward.remote_active
forward.connection_opened
forward.connection_closed
forward.connection_failed
forward.throttled
forward.limit_reached
firewall.plan_created
firewall.rule_applied
firewall.rule_removed
firewall.rule_failed
session.opened
session.closed
session.force_closed
session.drain_started
session.drain_completed
stats.snapshot_written
diagnose.started
diagnose.completed
diagnose.failed
benchmark.started
benchmark.completed
benchmark.failed
dns.query
dns.record_generated
dns.unhealthy_answer_suppressed
secret.accessed
secret.rotated
key.generated
key.passphrase_changed
remote_log.delivered
remote_log.failed
event.email_sent
event.email_failed
event.push_sent
event.push_failed
event.http_sent
event.http_failed
event.sms_sent
event.sms_failed
event.command_started
event.command_completed
event.command_failed
snmp.poll
snmp.trap_sent
snmp.trap_failed
windows_event.written
windows_event.failed
mcp.session_started
mcp.tool_called
mcp.policy_denied
mcp.disabled
failover.started
failover.completed
failover.exhausted
ssh3.experimental_warning
shutdown.started
shutdown.completed
```

### 13.3 Redaction

The logger MUST redact:

- Passwords.
- Passphrases.
- Bearer tokens.
- Authorization headers.
- Private key material.
- Environment variable values that provide secrets.

The logger MUST support configurable redaction of:

- Usernames.
- Hostnames.
- Target addresses.

Redaction MUST apply before logs are written to files, native logs, stdout, or stderr.
Redaction MUST also apply before event bindings, SNMP traps, remote logs, Windows Event Log entries, metrics labels, and MCP responses.

### 13.4 Rotation

File logging MUST support:

- Size-based rotation.
- Time-based rotation.
- Maximum retained files.
- Maximum retained age.
- Best-effort compression.
- Rotation checks on a configurable interval.
- Explicit naming for active and rotated files.

Log rotation MUST not block active forwarding for long periods. If rotation fails, the tool MUST continue running and emit a rate-limited error.

### 13.5 Status Snapshots

The supervisor MUST write status snapshots to the state directory.

Required snapshot content:

- Process ID.
- Binary version.
- Config fingerprint.
- Start time.
- Profile states.
- Forward states.
- Current SSH/SSH3 session table.
- Current forwarded connection table.
- Active connection counts.
- Per-session age, endpoint, protocol, state, bytes, packet counts, and last activity.
- Per-forward current and rolling throughput.
- Last successful connection time.
- Last error per profile and forward.
- Byte counters.
- Assigned remote ports.
- Benchmark run summaries.
- Diagnostic run summaries.

Status files MUST be written atomically.

### 13.6 Stats And Sessions

The supervisor MUST maintain current session and forwarded connection state for inspection.

Session data MUST include:

- Stable session ID.
- Profile name.
- Protocol.
- Active endpoint.
- Authenticated user, redacted when configured.
- Session state.
- Connection start time.
- Last activity time.
- Keepalive state.
- Reconnect attempt number.
- Active forwards and forwarded connection counts.
- Bytes and packets in each direction.

Forwarded connection data MUST include:

- Stable connection ID.
- Profile and forward name.
- Direction and transport.
- Local peer address.
- Remote target address, redacted when configured.
- Start time and age.
- Last activity time.
- Bytes, packets, current rate, and applied throttle.
- Close reason when known.

Stats command requirements:

- `spt stats live` MUST provide a continuously updating terminal view.
- `spt stats export` MUST support automation-friendly export formats.
- `spt session close` MUST close only the selected forwarded connection or SSH/SSH3 session and MUST log an audit event.
- `spt session drain` MUST stop accepting new forwarded connections for the selected scope and wait for active connections to finish.
- Session and stats output MUST never include plaintext secrets.

### 13.7 Remote Logging

Remote logging MUST support:

- Syslog over TCP with TLS.
- HTTPS JSON Lines ingestion.
- OTLP logs over HTTP or gRPC.
- Configurable batching, backoff, retry budget, disk spool limit, and drop policy.
- Per-sink `required = true` to make startup fail when a critical remote log sink is unavailable.
- `spt log test --sink <name>` to validate credentials, trust, and reachability.

Remote logging MUST NOT:

- Block tunnel data forwarding on normal sink latency.
- Send unredacted secrets.
- Retry forever without bounded disk or memory queues.

### 13.8 Metrics

Metrics MUST include:

- Process uptime, version, and config fingerprint.
- Profile state, reconnect count, failover count, active endpoint, and last error category.
- Current SSH/SSH3 session count, session ages, reconnect state, and current endpoint.
- Current forwarded connection count and connection age distribution.
- Forward listener state, active connections, connection opens, connection closes, failures, bytes, packets, drops, throttled bytes, and limit rejects.
- Internal DNS query counts, response codes, cache hits, and unhealthy suppressions.
- Secret store lock state and access failures without exposing secret names unless redaction allows them.
- Remote logging queue depth, delivered events, failed events, and dropped events.
- MCP session count, tool calls, and policy denials.
- Benchmark run count, last benchmark result, and benchmark failure count.
- Diagnostic run count, last diagnostic result, and diagnostic failure count.

Metrics MUST be available through `spt observe metrics` and state files. A local HTTP metrics exporter MAY be added only as an observability endpoint, not as a management API.

### 13.9 SNMP

SNMP requirements:

- SNMPv3 authPriv MUST be supported.
- SNMPv2c read-only polling MAY be supported only when explicitly configured and bound to loopback by default.
- A project enterprise MIB MUST be provided.
- Pollable objects MUST cover process, profile, forward, DNS, failover, rate-limit, and remote-log status.
- Traps or informs MUST be emitted for profile failure, forward failure, failover start/completion/exhaustion, authentication failure, trust failure, rate-limit exhaustion, DNS failure, and remote logging failure.
- SNMP secrets MUST use the secret store.

### 13.10 Windows Event Log

Windows Event Log requirements:

- The CLI MUST install and remove an event source.
- Events MUST map levels to Windows event severities.
- Event IDs MUST be stable and documented.
- Event payloads MUST include profile, forward, protocol, event category, error category, and redacted message.
- `spt observe windows-event test` MUST write a test event.
- If Event Log writing fails, the failure MUST be logged through other available sinks.

### 13.11 Event Bindings

Event bindings MUST be evaluated after redaction and before sink dispatch.

Required actions:

- `log`: write to configured local logs.
- `remote-log`: send to configured remote log sinks.
- `snmp-trap`: emit SNMP trap or inform.
- `windows-event`: write Windows Event Log entry.
- `email`: send an email through a configured SMTP sink.
- `push`: send a push notification through a configured push sink.
- `http`: send an HTTP request with configurable method, headers, body, TLS, and authentication.
- `rest`: call a REST API using a structured HTTP sink.
- `post`: send an HTTP POST request using a structured HTTP sink.
- `sms`: send an SMS through a configured provider adapter.
- `command`: execute an explicitly allowed local command.
- `mcp-notify`: make the event available to MCP subscribers.

Bindings MUST support filters by event category, level, profile, forward, protocol, error category, and tag.
Bindings MUST support per-action throttles, retries, circuit breakers, and dead-letter records so failing notification sinks do not block tunnel forwarding.

### 13.12 Diagnostics

Diagnostics are structured checks that explain whether a configured tunnel can run and why it is failing.

Diagnostic toolsets MUST include:

- Config schema and migration readiness.
- File permissions and state directory writability.
- Secret store unlock, keychain access, and vault encryption health.
- SSH2 key parsing, public key derivation, OpenSSH certificate parsing, and passphrase validation.
- SSH2 host key trust and SSH3 TLS trust.
- DNS resolution, internal DNS records, upstream DNS forwarding, and SNI-name guidance.
- Local bind availability, remote bind negotiation, privileged port checks, and listener ACL checks.
- Port probes that attempt to auto-detect the endpoint service exposed on the port.
- Network reachability, endpoint failover readiness, keepalive health, and reconnect policy.
- Service installation, rootless service support, and native service status.
- Remote logging, SNMP, Windows Event Log, metrics, and event binding delivery.
- MCP disabled/enabled state, policy, transport, and write-tool exposure.

Diagnostic output requirements:

- Every check MUST have an ID, severity, status, explanation, evidence, and remediation hint.
- Diagnostic bundles MUST be redacted by default.
- Diagnostic bundles MUST include effective config, status snapshots, recent logs, recent events, stats summaries, session summaries, platform details, service definitions, and selected benchmark summaries.
- Diagnostic commands MUST avoid mutating system state unless a subcommand explicitly documents the mutation, such as Windows Event Log test writes.

Port auto-detection requirements:

- `spt diagnose port --autodetect-service` MUST attempt safe protocol identification for common services including SSH, SMTP, HTTP, HTTPS, PostgreSQL, MySQL, Redis, DNS, LDAP, IMAP, POP3, AMQP, MQTT, and generic TLS.
- Auto-detection MUST prefer passive banner reads and safe handshakes over intrusive probes.
- TLS probes MUST report certificate subject, SANs, issuer, expiry, protocol version, ALPN, and whether the configured SNI name appears valid.
- Probes MUST be timeout-bounded, rate-limited, and clearly marked as network-touching diagnostics.
- Unknown services MUST be reported as `unknown` with observed evidence rather than guessed aggressively.

### 13.13 Benchmarking

Benchmarking measures tunnel behavior under controlled load and MUST be safe for production-like systems by default.

Benchmark types:

- Startup time.
- SSH2 and SSH3 connect latency.
- Authentication latency.
- Local TCP forward latency and throughput.
- Remote TCP forward latency and throughput.
- SSH3 local UDP packet rate, loss, jitter, and throughput.
- SSH3 remote UDP packet rate, loss, jitter, and throughput.
- Internal DNS query latency and cache behavior.
- Reconnect and failover recovery time.
- Throttle accuracy and limit enforcement.
- Logging and event sink overhead.

Benchmark safety requirements:

- Benchmarks MUST require an explicit profile and forward unless using an offline synthetic benchmark.
- Benchmarks MUST honor configured connection, bandwidth, packet, and safety limits.
- Benchmarks MUST refuse destructive or excessive load unless `--unsafe-allow-production-impact` is provided.
- Benchmark payloads MUST be synthetic and MUST NOT include secrets or sampled user traffic.
- Benchmark results MUST include environment metadata, config fingerprint, protocol, endpoint, forward, duration, concurrency, payload size, errors, percentiles, throughput, packet loss where applicable, and applied throttles.
- Benchmark reports MUST be exportable as JSON, JSON Lines, CSV, and Markdown.
- Benchmark runs MUST be logged as audit events.

## 14. Security Requirements

### 14.1 Threat Model

The tool should assume:

- The network can be observed, interrupted, delayed, or redirected.
- DNS responses can change between retries.
- Remote hosts can be misconfigured.
- Local unprivileged users may read world-readable files.
- Logs may be collected by centralized systems.
- Services may run unattended after boot.

### 14.2 Trust Verification

Requirements:

- SSH2 host key verification is mandatory by default.
- SSH3 TLS verification is mandatory by default.
- Pinning SHOULD support SHA-256 public key or certificate pins.
- Trust failures MUST be clear, terminal errors.
- Trust-on-first-use behavior, if supported, MUST be explicit and audited.

### 14.3 Remote Config Security

Requirements:

- Remote config URLs MUST use HTTPS with strict TLS verification.
- Remote config for unattended service mode MUST require a SHA-256 fingerprint, signature policy, pinned public key, or private CA trust policy.
- Redirects MUST be limited and MUST never downgrade to HTTP.
- Remote config content MUST be size-limited, schema-validated, and written to a local cache atomically.
- Remote config authentication MUST use the secret store.
- Remote config fetch failures MUST never replace a known-good local config with partial or invalid content.

### 14.4 Local Exposure

Requirements:

- Local binds default to `127.0.0.1`.
- Wildcard binds require `expose = true`.
- Specific loopback binds such as `127.0.0.2` MUST be supported where the OS allows them.
- Specific non-loopback IP binds MUST verify that the address belongs to a local interface unless explicitly configured to allow late interface availability.
- Interface-aware binds MUST support named interfaces, automatic interface selection, and all-interface binding.
- Remote binds require explicit bind address and port.
- Local listener ACLs MUST support CIDR allow and deny lists.
- Firewall rules MUST be configurable separately from listener binds and MUST support preview before applying.

Example:

```toml
[[profiles.forwards]]
name = "admin"
type = "local"
transport = "tcp"
bind = "0.0.0.0:8443"
target = "admin.internal:443"
expose = true
allow_cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
```

### 14.5 File Permissions

The tool MUST warn when sensitive files are too permissive:

- Private keys.
- Secret files.
- Config files containing secret references.
- State files containing operational details.
- Log files when redaction settings are weakened.

On Unix, private key and secret files SHOULD be owner-readable only. On Windows, ACL checks SHOULD verify the current user, Administrators, and SYSTEM are the only principals with read access for sensitive files.

### 14.6 Secret Management

Secrets include passwords, key passphrases, bearer tokens, OIDC refresh tokens, SNMP auth and privacy secrets, remote logging tokens, MCP credentials, and vault master keys.

Requirements:

- Credentials MUST be encrypted at rest.
- OS keychain storage MUST be fully supported on Linux, macOS, and Windows.
- A local encrypted vault MUST be available for headless or portable deployments.
- The vault MUST use authenticated encryption and per-record nonces.
- Secrets MUST be loaded just in time, held in zeroizing buffers, and cleared immediately after use.
- Secrets MUST NOT be stored in long-lived `String` values or written into status snapshots.
- Memory locking MUST be attempted on platforms that support it, with clear diagnostics when unavailable.
- Crash reports and panic hooks MUST avoid secret material.
- Commands that reveal secrets MUST require an explicit `--reveal` flag and MUST not be used by generated examples.
- Secret rotation MUST support updating config references without exposing old or new values in logs.

Plaintext in memory cannot be eliminated completely when an SSH, TLS, HTTP, or SNMP library requires credential bytes. The requirement is to minimize lifetime, avoid avoidable copies, zero memory after use, and prevent persistence in logs, state, swap where possible, or crash output.

### 14.7 SSH3 Experimental Safety

SSH3 profiles MUST:

- Be usable in default builds without feature gates.
- Require explicit profile selection with `protocol = "ssh3"`.
- Report draft/prototype version in logs and status.
- Fail closed if required protocol features are not negotiated.
- Avoid claiming production security parity with SSH2 while the draft remains experimental or expired.

## 15. Cross-Platform Requirements

Required platforms:

- Linux x86_64 and aarch64.
- macOS aarch64 and x86_64.
- Windows x86_64.

Additional supported platforms:

- FreeBSD x86_64.
- Linux musl static builds.

Platform-specific behavior:

- Path expansion MUST handle `~`, environment variables, and platform separators.
- Signals MUST map to equivalent shutdown/reload behavior where available.
- File locks MUST work across processes.
- Socket options MUST be applied through cross-platform abstractions with platform-specific fallbacks.
- IPv6 support MUST be tested on all required platforms.

## 16. MCP Capability

MCP support MUST be a first-class capability for local automation and agent-assisted operations. It MUST NOT expose a public remote management plane by default.

MCP server behavior:

- MCP MUST be disabled by default in generated config.
- `spt mcp serve` MUST fail closed unless config enables MCP or the operator passes `--enable`.
- Starting MCP with `--enable` MUST emit an audit event.
- MCP MUST still default to read-only after it is enabled.

Required transports:

- `stdio` for local editor and agent integrations.
- Loopback TCP only when explicitly requested with `--listen 127.0.0.1:<port>`.
- No wildcard bind for MCP unless config explicitly sets `expose = true` and an authentication policy.

MCP resources:

```text
spt://config/effective
spt://config/redacted
spt://profiles
spt://forwards
spt://status
spt://stats/summary
spt://sessions/current
spt://events/recent
spt://logs/recent
spt://metrics
spt://diagnostics/recent
spt://benchmarks/recent
spt://dns/records
spt://snmp/mib
spt://service/definition
spt://policy/mcp
```

MCP tools:

```text
config_validate
config_doctor
config_render
profile_list
profile_show
profile_set
forward_list
forward_explain
forward_add
forward_remove
tunnel_status
tunnel_reload
tunnel_failover
stats_summary
stats_export
session_list
session_show
diagnose_run
diagnose_bundle
benchmark_run
benchmark_report_export
dns_query
dns_record_add
dns_record_remove
log_tail
observe_metrics
event_test
service_render
secret_list
secret_set_ref
key_inspect
```

MCP security requirements:

- MCP MUST be disabled by default.
- MCP MUST default to read-only unless started with write permissions or policy allows specific tools.
- MCP MUST never return plaintext secrets.
- Secret-setting tools MUST accept references or trigger CLI-side prompting, not expose values through MCP logs.
- Mutating tools MUST use the same validation, dry-run, backup, and atomic-write path as CLI commands.
- MCP sessions MUST be logged with client identity when available.
- MCP policy denials MUST be visible in logs, metrics, and status.
- Long-running operations MUST stream progress where the MCP transport supports it.
- MCP must be documented as a local automation interface, not a replacement for config files.

Example MCP policy:

```toml
[mcp]
enabled = false
default_mode = "read_only"
allow_write_tools = ["forward_add", "forward_remove", "config_validate", "config_doctor"]
allow_secret_reveal = false
listen = ""
stdio = true
```

## 17. Architecture

### 17.1 Modules

Suggested Rust module layout:

```text
src/
  main.rs
  cli/
  tui/
  config/
  remote_config/
  logging/
  observability/
  service/
  supervisor/
  state/
  stats/
  dns/
  firewall/
  events/
  secrets/
  diagnostics/
  benchmark/
  mcp/
  protocol/
    mod.rs
    ssh2.rs
    ssh3.rs
  forward/
    local_tcp.rs
    remote_tcp.rs
    udp.rs
    limits.rs
    failover.rs
  auth/
  key/
  trust/
  net/
  error.rs
```

### 17.2 Runtime Model

The implementation MUST use Tokio for async networking and task supervision.

Runtime shape:

- One main monitor orchestrator thread owns global shutdown, reload, lifecycle decisions, health aggregation, and failover decisions.
- Service worker threads own profile supervision, listener lifecycle, session replacement, and forward reconciliation.
- Logging worker threads own structured log formatting, redaction, file writes, rotation, and remote log queue draining.
- DNS worker threads own transparent DNS forwarding and hosts-file rendering/apply operations.
- Observability worker threads own metrics snapshots, SNMP, Windows Event Log writes, event sink delivery, diagnostics, and benchmark reporting.
- Blocking worker threads isolate libssh2, filesystem, keychain, service-manager, hosts-file, and firewall operations from async reactor threads.
- Each profile runs as an isolated task tree.
- Each forward owns listener lifecycle.
- Each accepted connection runs in its own bounded task.
- Shared session objects are reference-counted and replaced on reconnect.
- Backpressure is enforced with bounded channels and direct socket copying where possible.
- The internal DNS resolver runs as its own supervised task when enabled.
- Remote logging, SNMP traps, Windows Event Log writes, and event bindings use bounded queues.
- SSH2 libssh2 operations that block MUST run on dedicated blocking workers so Tokio reactor threads are not stalled.

Low idle CPU requirements:

- Idle services MUST be event-driven and MUST NOT poll tight loops.
- Periodic work MUST use configurable ticks with jitter and backoff.
- File watchers, socket readiness, service status, DNS, metrics, and log rotation MUST sleep when idle.
- Idle CPU usage with no active connections SHOULD remain near zero on supported platforms.
- Diagnostics, benchmarks, and event sinks MUST run only on demand or when explicitly configured.

### 17.3 Protocol Adapter Trait

Protocol implementations MUST conform to a common adapter boundary similar to:

```rust
trait TunnelProtocol {
    async fn connect(&self, profile: &ProfileConfig) -> Result<Box<dyn TunnelSession>>;
    fn capabilities(&self) -> ProtocolCapabilities;
}

trait TunnelSession {
    async fn open_tcp(&self, target: TargetAddr) -> Result<TcpChannel>;
    async fn request_remote_tcp(&self, bind: BindAddr, target: TargetAddr) -> Result<RemoteListener>;
    async fn open_udp(&self, target: TargetAddr) -> Result<UdpAssociation>;
    async fn request_remote_udp(&self, bind: BindAddr, target: TargetAddr) -> Result<RemoteUdpAssociation>;
    async fn keepalive(&self) -> Result<()>;
    async fn close(&self) -> Result<()>;
}
```

The actual code should avoid unnecessary dynamic dispatch if static dispatch is cleaner, but the design boundary should remain explicit.

### 17.4 Candidate Crates

Candidate core crates:

- `tokio` for async runtime.
- `clap` for CLI parsing.
- `ratatui` and `crossterm` for the interactive profile configurator TUI.
- `serde`, `toml`, and `serde_json` for config and status.
- `tracing`, `tracing-subscriber`, and `tracing-appender` for logging.
- `thiserror` for typed errors.
- `miette` or `color-eyre` for human diagnostics.
- `directories` for platform config paths.
- `notify` for config reload watching if needed.
- `zeroize` and `secrecy` for secret handling.
- `keyring` or platform-specific bindings for OS keychains.

Required SSH2 backend:

- The production SSH2 backend MUST use libssh2 through the Rust `ssh2` crate for mature SSH2 interoperability and forwarding behavior.
- The protocol adapter MUST isolate libssh2-specific blocking and lifecycle behavior from the rest of the supervisor.
- A pure Rust backend such as `russh` may be added later, but it MUST pass the same forwarding, auth, host-key, and reconnect test suite before becoming default.

Candidate SSH3 crates and building blocks:

- `quinn` for QUIC.
- `rustls` for TLS.
- `h3` for HTTP/3.
- Draft-specific SSH3/RTH3 code implemented in the default build while the adapter keeps protocol-version details isolated.

Candidate service crates:

- `windows-service` for Windows service integration.
- Generated unit/plist files for systemd and launchd.

Candidate observability and MCP crates:

- SNMP crate selection MUST be validated for SNMPv3 authPriv support.
- OpenTelemetry crates for OTLP logs and metrics.
- A Rust MCP SDK or minimal MCP implementation for stdio-first local integration.

The final crate choices MUST be validated against forwarding support, maintenance status, license compatibility, and cross-platform build behavior.

## 18. Error Model

Errors MUST be typed internally and rendered clearly externally.

Required error categories:

```text
config
remote_config
filesystem
dns
internal_dns
network
bind
firewall
ssh_transport
ssh_auth
ssh_trust
ssh_channel
crypto_policy
ssh3_tls
ssh3_http3
ssh3_quic
secret_store
secret_crypto
key_management
rate_limit
failover
instability
stats
session
diagnostics
benchmark
remote_logging
event_sink
metrics
snmp
windows_event_log
mcp
unsupported_feature
service_manager
shutdown
oom
internal
```

Error messages MUST include:

- Profile name where applicable.
- Forward name where applicable.
- Operation that failed.
- Underlying cause.
- Whether the error is retryable.
- Next retry time when applicable.

Error messages MUST NOT include secrets.

## 19. Performance Requirements

Baseline targets for SSH2 local TCP forwarding on a typical developer laptop:

- 100 simultaneous TCP connections per profile without instability.
- 1,000 configured profiles or forwards can be parsed and validated within two seconds.
- Idle profile memory overhead should remain small enough for dozens of profiles in one service process.
- Idle CPU usage with no active connections should remain near zero and MUST not be driven by tight polling loops.
- Tunnel throughput should primarily be limited by SSH library, cipher choice, and network path rather than avoidable buffering.

Backpressure requirements:

- The tool MUST avoid unbounded per-connection buffers.
- Slow receivers MUST not cause global memory growth.
- Per-forward and per-profile connection limits MUST be enforceable.
- Connection copy loops MUST shut down both directions cleanly on error.
- Token-bucket throttles MUST support per-forward and per-profile rates.
- UDP flow tables MUST enforce maximum active flows and idle cleanup.
- Remote logging and event binding queues MUST have bounded memory and disk spool limits.
- Out-of-memory or resource exhaustion conditions MUST fail closed for new connections while preserving existing tunnels when possible.

## 20. Testing Requirements

### 20.1 Unit Tests

Required unit test areas:

- Config parsing and validation.
- Secure remote config URL validation and cache policy.
- Duration and size parsing.
- Address parsing, including IPv6.
- Redaction.
- Secret reference parsing, encryption metadata, and zeroization boundaries.
- Reconnect backoff.
- Failover selection.
- Rate limiting and throttling.
- State machine transitions.
- Error classification.
- Internal DNS record generation.
- Hosts-file managed block rendering and restore planning.
- Firewall bind policy and interface selection.
- Event binding filters.
- Event sink templating for email, HTTP, REST, POST, SMS, push, and command actions.
- Crypto policy warnings for deprecated algorithms.
- Unstable connection detection state transitions.
- Stats aggregation windows.
- Session table lifecycle.
- Diagnostic check result classification.
- Benchmark result calculation and safety policy.
- MCP policy decisions.

### 20.2 Integration Tests

Required integration tests:

- SSH2 local TCP forward against an OpenSSH server.
- SSH2 remote TCP forward against an OpenSSH server.
- SSH2 auth failure.
- SSH2 host key mismatch.
- Local bind conflict.
- Reconnect after server restart.
- Config reload adding and removing a forward.
- Secure remote config pull and cache fallback.
- Service file generation for Linux, macOS, and Windows.
- Service-per-config behavior.
- Rootless systemd user service and macOS LaunchAgent generation.
- Windows Event Log source registration and test event writing.
- Internal DNS UDP and TCP query handling.
- Transparent DNS forwarding to configured upstream resolvers.
- Hosts-file apply and restore using a temporary test hosts file.
- DNS-assisted SNI-friendly forwarding workflow.
- Firewall plan/apply/remove behavior where CI permissions allow it, plus dry-run everywhere.
- Bind to specific loopback IP, specific interface IP, auto-selected interface, and all interfaces.
- Secret store operations on Linux, macOS, and Windows where CI support exists.
- Key generation, public key export, passphrase change, and key inspection.
- Remote logging sink retry and redaction behavior.
- SNMPv3 polling and trap emission.
- Current session listing, session close, and drain behavior.
- Stats live/export behavior.
- Diagnostic bundle generation with redaction.
- Diagnostic port service auto-detection for common protocols.
- Benchmark latency, throughput, UDP, reconnect, DNS, and limit checks.
- MCP stdio server resources, tools, write policy, and secret redaction.
- Bandwidth throttling, connection limits, UDP flow limits, and failover exhaustion.

SSH3 integration tests:

- MUST be marked experimental.
- SHOULD run only when an SSH3/RTH3 test server is available.
- MUST test protocol feature negotiation failure paths.
- MUST test local TCP, remote TCP, local UDP, and remote UDP when the peer supports the required capabilities.

### 20.3 Manual Acceptance Tests

SMTP relay:

1. Configure local `127.0.0.1:2525` to remote `smtp.internal:25`.
2. Start `spt tunnel run`.
3. Send SMTP traffic through the local port.
4. Restart the remote SSH server.
5. Confirm the local listener remains and forwarding resumes.

Jump host:

1. Configure local `127.0.0.1:15432` to remote `db.internal:5432` through a bastion.
2. Verify database connectivity.
3. Drop the network interface.
4. Restore connectivity.
5. Confirm reconnect and status accuracy.

Service restart:

1. Install a system service.
2. Start the service.
3. Reboot the machine.
4. Confirm tunnels return without manual action.

## 21. Packaging

Required deliverables:

- Static or mostly self-contained CLI binaries where practical.
- Linux `.deb` and `.rpm` packages.
- macOS signed universal binary or package.
- Windows MSI or ZIP with service support.
- Rootless archive install for each required platform.
- Shell completions.
- Man page or generated CLI reference.
- SNMP MIB file.
- MCP integration guide and machine-readable tool descriptions.

Package behavior:

- Packages MUST NOT install or start a tunnel service without explicit user action.
- Packages MAY install example config files.
- Service installation MUST be performed by `spt service install`.
- User-level package installation MUST be documented where supported.

## 22. Documentation Requirements

Required docs:

- Quickstart for local SSH2 tunnel.
- SMTP relay example.
- Jump host example.
- Reverse tunnel example.
- SSH3 experimental example.
- Service installation guide for Linux, macOS, and Windows.
- Config reference.
- Logging and troubleshooting guide.
- Remote logging guide.
- Internal DNS and SNI guide.
- Transparent DNS forwarding and hosts-file management guide.
- Firewall, interface binding, and exposed listener guide.
- Remote config URL and trust policy guide.
- Secret store and key management guide.
- SNMP, metrics, and Windows Event Log guide.
- Stats and current sessions guide.
- Diagnostics and support bundle guide.
- Benchmarking guide.
- Event notifications guide covering email, push, HTTP, REST, POST, SMS, and command actions.
- Interactive TUI profile configurator guide.
- Crypto compatibility and deprecated algorithm warning guide.
- Unstable connection detection guide.
- MCP integration guide.
- Throttling, limits, and failover guide.
- Security guide covering trust, bind exposure, secret handling, and SSH3 status.

The docs MUST consistently state that SSH3 support is experimental while the relevant draft remains expired or otherwise non-final.

## 23. Milestones

### M0: Specification and Project Skeleton

- Create this specification.
- Add Rust workspace.
- Add CLI skeleton.
- Add global option handling for the Docker-style command schema.
- Add config parser and validation.
- Add structured logging foundation.
- Add command group help framework.

### M1: SSH2 Local Forwarding

- libssh2-backed SSH2 adapter.
- Public key auth.
- Password and keyboard-interactive auth.
- Known hosts verification.
- Local TCP forwarding.
- Reconnect and keepalive.
- Status snapshots.
- Secret references and OS keychain integration foundation.
- Basic tests with OpenSSH.

### M2: Key, Secret, DNS, and CLI Management

- Key generation, inspection, public export, and passphrase change.
- Encrypted secret vault and OS keychain backends.
- CLI config mutation commands.
- Interactive TUI profile configurator.
- Internal DNS resolver and hosts rendering.
- Transparent DNS forwarding disabled by default.
- Hosts-file apply and restore.
- Forward explain and user-friendly add commands.
- Secure remote config pull and cache.

### M3: Service Management and Observability

- systemd service install/start/stop/status.
- launchd service generation.
- Windows service integration.
- File logging with rotation.
- Native logging integrations.
- Remote logging.
- Windows Event Log writing.
- Metrics output.
- SNMPv3 polling and traps.
- Email, push, HTTP, REST, POST, SMS, and command event sinks.
- Stats snapshots and live stats.
- Current session inspection.
- Log rotation hardening.

### M4: SSH2 Advanced Forwarding

- Remote TCP forwarding.
- Multi-forward profiles.
- Multi-hop SSH2 jump chains.
- Config reload.
- Failover endpoints.
- Throttling and limits.
- Firewall planning and interface-aware bind policy.
- Deprecated crypto compatibility warnings.
- Unstable connection detection.
- Session close and drain.

### M5: Diagnostics And Benchmarking

- `spt diagnose` toolsets.
- Redacted diagnostic bundles.
- `spt benchmark` latency, throughput, UDP, reconnect, DNS, and limits tests.
- Benchmark report export and comparison.

### M6: SSH3 Experimental But Default Enabled

- Default-build SSH3 adapter.
- TLS trust configuration.
- HTTP/3 Extended CONNECT session establishment.
- Local TCP forwarding.
- Remote TCP forwarding.
- UDP forwarding when datagrams are negotiated.
- Remote UDP forwarding.
- Experimental integration tests.

### M7: MCP and Hardening

- MCP stdio server.
- MCP resources and guarded tools.
- MCP policy and audit logging.
- Extended event bindings.

### M8: Release

- Cross-platform packaging.
- Extended integration test matrix.
- Security review.
- Performance tuning.
- Documentation completion.

## 24. Open Questions

1. Which SSH3/RTH3 implementation should be treated as the compatibility target for experimental integration tests?
2. Which SNMP crate or implementation strategy provides reliable SNMPv3 authPriv support across required platforms?
3. Should Linux headless secret storage prefer Secret Service, kernel keyring, age-encrypted vault files, or another fallback when no user keychain is available?
4. Should MCP loopback TCP transport be included in the first release or limited to stdio until the policy model is hardened?
5. Which enterprise OID should be used for the project MIB?

## 25. References

- SSH Transport Layer Protocol, RFC 4253: https://www.rfc-editor.org/rfc/rfc4253
- SSH Connection Protocol, RFC 4254: https://www.rfc-editor.org/rfc/rfc4254
- Remote terminal over HTTP/3 connections, draft-michel-remote-terminal-http3-00: https://datatracker.ietf.org/doc/html/draft-michel-remote-terminal-http3
- SSH3 prototype repository: https://github.com/francoismichel/ssh3
- Towards SSH3: how HTTP/3 improves secure shells: https://arxiv.org/abs/2312.08396
- libssh2 project: https://www.libssh2.org/
- Model Context Protocol: https://modelcontextprotocol.io/
- SNMP architecture, RFC 3411: https://www.rfc-editor.org/rfc/rfc3411
- SNMP user-based security model, RFC 3414: https://www.rfc-editor.org/rfc/rfc3414
- Syslog protocol, RFC 5424: https://www.rfc-editor.org/rfc/rfc5424
- TLS transport mapping for syslog, RFC 5425: https://www.rfc-editor.org/rfc/rfc5425
- OpenTelemetry protocol specification: https://opentelemetry.io/docs/specs/otlp/
