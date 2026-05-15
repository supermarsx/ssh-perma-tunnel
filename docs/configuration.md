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
    [network]                 # interface, gateway, offload, load balancing
    [observability.metrics]   # Prometheus exporter
    [observability.snmp]      # SNMPv3 agent + traps (feature-gated)
    [observability.windows_event] # Windows Event Log integration
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

Remote sinks are declared as `[[logging.remote]]` and may be `syslog_udp`,
`syslog_tcp`, `syslog_tls`, `https_jsonl`, or `otlp`. Syslog defaults are
port `514` for UDP/TCP and `6514` for TLS. Reliable transports support
`spool_dir`, `spool_max_bytes`, `queue_max_records`, `timeout`, and
`reconnect_backoff`; TLS additionally supports `ca_file`, `server_name`,
`client_cert`, `client_key`, and `allow_invalid_certs`.

## `[secrets]`

    [secrets]
    backend = "auto"             # auto | keychain | vault | env
    vault_file = "/var/lib/spt/vault.spt"
    keychain_namespace = "spt"

See [Secrets](secrets.md) for the resolver-priority rules.

## `[observability]`

Metrics, SNMP, Windows Event Log, and OTLP/syslog details are covered in
[Observability](observability.md). Production SNMP is build-gated and requires
an operator-owned IANA Private Enterprise Number:

    [observability.snmp]
    enabled = true
    version = "v3"
    bind = "127.0.0.1:10161"
    enterprise_id = 12345 # replace with your registered PEN

## `[dns]`

    [dns]
    enabled = false
    mode = "transparent_forwarder" # disabled | transparent_forwarder | synthetic_only | hosts_file
    bind = "127.0.0.1:5353"
    upstream = ["1.1.1.1:53"]

`[[dns.records]]` blocks declare A/AAAA/SRV/TXT records served from the
managed zone.

## `[network]`

Use `[network]` for host-level routing policy that applies across profiles:
interface selection, gateway checks, kernel/socket offload choices, and
load-balancing defaults.

    [network.interface]
    default_interface = "eth0"
    allowed_interfaces = ["eth0", "wg0"]
    require_explicit_interface = true
    allow_all_interfaces = false
    bind_ipv6 = "auto" # auto | prefer | disable

    [network.gateway]
    default_gateway = "192.0.2.1"
    interface = "eth0"
    route_check_target = "198.51.100.10"
    require_gateway_match = true
    policy = "route_to_target" # disabled | default_route | interface_only | route_to_target

    [network.offload]
    tcp_nodelay = true
    socket_keepalive = true
    zerocopy = false
    io_uring = false

    [network.load_balance]
    strategy = "weighted" # priority | weighted | round_robin | least_connections | manual
    sticky_sessions = true
    fail_after = 3
    restore_after = "30s"

`spt firewall gateway show|set` manages the interface/gateway fields without
hand-editing TOML. `spt firewall policy list|show|set|unset` manages the
corresponding GPO-style policy values under `Software\Policies\spt`.

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
