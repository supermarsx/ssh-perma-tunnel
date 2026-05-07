# Configuration

`spt` is config-file-driven. The schema is TOML and versioned
(`version = 1`). Spec §8/§9 is the canonical reference; this guide is the
operator companion.

## Where the config lives

The CLI accepts `--config PATH` or the `SPT_CONFIG` environment variable.
Service installs default to:

| OS      | Path                                             |
|---------|--------------------------------------------------|
| Linux   | `/etc/spt/spt.toml`                              |
| macOS   | `/usr/local/etc/spt/spt.toml`                    |
| Windows | `%PROGRAMDATA%\spt\spt.toml`                     |

## Top-level shape

    version = 1
    [runtime]                 # state dir, threading, reload mode
    [logging]                 # level, format, destinations, redaction
    [secrets]                 # backend selection
    [dns]                     # built-in resolver, hosts file
    [firewall]                # planner platform + ruleset hooks
    [observability.metrics]   # Prometheus exporter
    [observability.snmp]      # SNMPv3 agent + traps
    [events]                  # bindings + sinks
    [mcp]                     # Model Context Protocol server
    [diagnostics]             # `spt diagnose` defaults
    [benchmark]               # `spt benchmark` defaults
    [[profiles]]              # one or more tunnel profiles

## Validating a config

    spt config validate --config /etc/spt/spt.toml --strict

`--strict` rejects unknown fields and friendly aliases. In non-strict
mode unknown fields surface as warnings.

`spt config render` re-emits the canonical TOML; pass `--redacted` to
mask secret references.

## `[runtime]`

State directory, threading, reload mode. See spec §9.1, §17.2.

    [runtime]
    state_dir = "/var/lib/spt"
    shutdown_grace = "10s"
    file_lock = true

    [runtime.threads]
    model = "multi_thread"
    orchestrator_threads = 1
    service_threads = 4
    blocking_worker_threads = 32

    [runtime.reload]
    mode = "signal"
    debounce = "1s"
    require_valid_config = true

## `[logging]`

    [logging]
    level = "info"
    format = "compact"
    destinations = ["stderr", "file"]
    file = "/var/log/spt/spt.log"
    rotate = "daily"
    max_files = 14
    redact = ["secrets", "auth"]

Remote sinks are declared as `[[logging.remote]]` and may be `syslog_tls`,
`https_jsonl`, or `otlp`.

## `[secrets]`

    [secrets]
    backend = "auto"             # auto | keychain | vault | env
    vault_file = "/var/lib/spt/vault.spt"
    keychain_namespace = "spt"

See [Secrets](secrets.md) for the resolver-priority rules.

## `[dns]`

    [dns]
    enabled = false
    mode = "transparent_forwarder" # disabled | transparent_forwarder | synthetic_only | hosts_file
    bind = "127.0.0.1:5353"
    upstream = ["1.1.1.1:53"]

`[[dns.records]]` blocks declare A/AAAA/SRV/TXT records served from the
managed zone.

## Profile basics

A minimal profile (see [`examples/minimal.toml`](../examples/minimal.toml)):

    [[profiles]]
    name = "minimal"
    enabled = true
    protocol = "ssh2"
    host = "bastion.example.com"
    user = "alice"

    [profiles.auth]
    method = "agent"

    [profiles.trust]
    mode = "known_hosts"
    strict = true

    [[profiles.forwards]]
    name = "web"
    type = "local"
    transport = "tcp"
    bind = "127.0.0.1:8080"
    target = "service.internal:80"

See [Profiles](profiles.md), [Forwards](forwards.md), and
[Authentication](auth.md) for the per-profile sub-tables.

## Reload semantics

`[runtime.reload]` controls hot reload. Modes:

- `signal` — SIGHUP triggers reload (Unix only).
- `watch` — file-watch with debounce.
- `service` — service-manager-driven (systemd `ExecReload`, SCM
  `ParamChange`).
- `none` — no reload; restart the service to apply changes.

## Examples

The repo ships several examples under [`/examples/`](../examples/):

- `minimal.toml`     — single profile, single local forward.
- `jump-host.toml`   — multi-hop chain.
- `reverse.toml`     — remote forward.
- `smtp-relay.toml`  — SMTP relayed via a local bind.
- `dns-split-horizon.toml` — split-horizon DNS resolver.
- `mcp.toml`         — MCP server with read-only policy.
- `ssh3.toml`        — experimental SSH3 backend.
- `zero-trust-https.toml` — internal HTTPS via vault-resolved pubkey + pin.
- `ha-failover.toml` — two endpoints with priority/weight.
- `multi-profile-fleet.toml` — five-bastion fleet, per-profile crypto.
- `observability-otel.toml` — OTLP + Prometheus + remote syslog-TLS.
- `headless-ci.toml` — env-only secrets for CI/CD pipelines.

## See also

- [CLI Reference](cli-reference.md)
- [Remote Config](remote-config.md)
- [Security](security.md)
