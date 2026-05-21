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
    [capabilities]            # fleet/admin feature gates
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

`spt firewall gateway show|set` manages these network policy fields without
hand-editing TOML, including `--allowed-interface`, `--denied-interface`,
`--tcp-nodelay`, `--zerocopy`, `--load-balance-strategy`,
`--load-balance-fail-after`, and gateway route checks. The
`spt firewall policy list|show|set|unset` commands manage the corresponding
GPO-style policy values under `Software\Policies\spt`.

## `[capabilities]`

`[capabilities]` is the operator policy table for optional, higher-impact
feature families. It can be set in config or enforced through Windows GPO
bindings.

    [capabilities]
    ssh2_backend = "russh"          # russh | libssh2 (legacy)
    allow_libssh2 = false
    allow_gssapi = true
    allow_sspi = true
    allow_gssapi_delegation = false
    allow_ntlm_fallback = false
    allow_post_quantum_kex = true
    allow_ml_kem = true
    require_post_quantum_kex = false
    allow_dynamic_proxy = true      # SOCKS / HTTP CONNECT listeners
    allow_sftp = true
    allow_filesystem_mounts = true
    allow_windows_drive_mounts = true
    allow_writeback_cache = false
    allow_windows_event_log = true
    allow_gpo_policy_writes = true

The production SSH2 target is the pure-Rust `russh` backend. `libssh2` is kept
as a legacy migration value only and validation warns when it is selected.
The current `russh` runtime supports password, public-key, certificate, and
keyboard-interactive auth plus local TCP, remote TCP, and dynamic SOCKS5/HTTP
CONNECT proxy forwarding. SSH agent auth and multi-hop chains still return
explicit unsupported-feature diagnostics on the `russh` path; select
`ssh2_backend = "libssh2"` only for those migration cases and keep
`allow_libssh2 = true`.
`require_post_quantum_kex` requires `allow_post_quantum_kex = true`; Windows
drive-letter mounts and writeback caching require filesystem mounts to be
enabled explicitly.

## `[[profiles.sftp_mounts]]`

SFTP file operations use `spt sftp ...` against SSH2 profiles. Mount and drive
entries are stored under the owning profile and are managed by
`spt sftp mount ...` and `spt sftp drive ...`.

    [capabilities]
    ssh2_backend = "russh"
    allow_sftp = true
    allow_filesystem_mounts = true
    allow_windows_drive_mounts = true

    [[profiles.sftp_mounts]]
    name = "data"
    remote_path = "/srv/data"
    mount_point = "/mnt/spt-data"
    read_only = true
    cache = "metadata"              # none | metadata | writeback

    [[profiles.sftp_mounts]]
    name = "data-drive"
    remote_path = "/srv/data"
    drive_letter = "S:"
    read_only = true
    cache = "none"

`mount_point` and `drive_letter` are mutually exclusive. Drive-letter entries
require `allow_windows_drive_mounts = true`. `cache = "writeback"` also
requires `allow_writeback_cache = true`. The current CLI stores and validates
mount plans and reports the platform helper needed (`FUSE`, `macFUSE`, or
`WinFsp` family); it does not silently install or run an OS filesystem driver.

## `[profiles.crypto]` And PQ KEX

`[profiles.crypto]` is an allow-list. Empty lists defer to the selected SSH2
backend defaults. Deprecated algorithms are allowed only with warnings; see
`config validate` and `diagnose run`.

    [capabilities]
    allow_post_quantum_kex = true
    allow_ml_kem = true

    [profiles.crypto]
    kex_algorithms = [
      "mlkem768x25519-sha256",
      "sntrup761x25519-sha512@openssh.com",
      "curve25519-sha256",
    ]

Recognized post-quantum SSH KEX names are validated behind
`allow_post_quantum_kex`; ML-KEM names additionally require `allow_ml_kem`.
`require_post_quantum_kex = true` rejects explicit classical-only KEX lists and
warns when a profile relies on backend defaults. Runtime support is still
bounded by the SSH backend: the current russh/libssh2 paths return an explicit
unsupported-feature diagnostic for requested ML-KEM/SNTRUP KEX until those KEX
engines are implemented in the transport.

## `[profiles.auth]` GSSAPI And SSPI

GSSAPI/Kerberos and Windows SSPI/Negotiate auth are explicit config surfaces:

    [capabilities]
    allow_gssapi = true
    allow_sspi = true

    [profiles.auth]
    method = "kerberos"       # aliases: gssapi, gssapi-with-mic
    gssapi_service = "host/edge.example.com"
    gssapi_principal = "alice@EXAMPLE.COM"
    gssapi_delegate = false

Or on Windows:

    [capabilities]
    allow_sspi = true

    [profiles.auth]
    method = "sspi"           # alias: negotiate
    sspi_service = "host/edge.example.com"
    sspi_principal = "alice@example.com"
    sspi_delegate = false
    sspi_allow_ntlm_fallback = false

Validation enforces the capability gates, delegation policy, and NTLM fallback
policy. Runtime support is still bounded by backend implementation and returns
an explicit unsupported-feature diagnostic until Kerberos/SSPI negotiation is
implemented.

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

Dynamic proxy listener:

    [capabilities]
    allow_dynamic_proxy = true

    [[profiles.forwards]]
    name = "proxy"
    type = "dynamic"
    transport = "tcp"
    bind = "127.0.0.1:1080"
    max_connections = 128

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

## Sealed configs (`SPTENC1`)

`spt-config-crypt` ships an authenticated-encryption envelope so a config
file can live on disk without exposing its secrets in plaintext. The
file format is `SPTENC1` (8-byte magic `b"SPTENC1\n"`), an AEAD-protected
body (`AES-256-GCM`) with one of three key sources:

- **Passphrase** — Argon2id (m=64 MiB, t=3, p=4 by default).
- **Vault master** — 32-byte vault master key resolved from the configured
  vault, unlocked through the OS keychain or `--vault-passphrase-from`.
- **X25519 recipients** — one or more recipient public keys; any holder
  of a matching private scalar can unseal.

### Commands

```text
spt config encrypt <in> [--out <PATH>]
                        [--passphrase-from <REF>]   # e.g. env:NAME, file:///path
                        [--recipient <PUBKEY_B64>]
                        [--use-vault-master]
                        [--vault-path <PATH>]
                        [--vault-passphrase-from <SOURCE>]
                        [--force]
spt config decrypt <in> [--out <PATH>]
                        [--passphrase-from <REF>]
                        [--recipient-key <PATH>]
                        [--vault-path <PATH>]
                        [--vault-passphrase-from <SOURCE>]
spt config edit    <sealed>  [--passphrase-from <REF>]
                        [--vault-path <PATH>]
                        [--vault-passphrase-from <SOURCE>]
spt config crypt rotate <sealed> [--new-passphrase-from <REF>]
                                 [--new-recipient <PUBKEY_B64>]
                                 [--vault-path <PATH>]
                                 [--vault-passphrase-from <SOURCE>]
```

`--passphrase-from` accepts the same `env:` / `file://` / `secret://`
forms as the rest of the CLI. When it points at `secret://ns/name`, the
config command opens the configured vault and resolves that record without
printing the secret. `--vault-path` accepts either a vault directory or a
path ending in `vault.spt`; `--vault-passphrase-from` accepts `stdin`,
`env:NAME`, `file:<path>`, or `file:///path` for passphrase-only vaults.

### Loader auto-detection

`spt_config::load` and `load_with_key` peek the on-disk magic bytes
through `spt_config_crypt::is_sealed`. If sealed and no
`KeySource` is supplied, the loader prompts for a passphrase on the
controlling TTY (via `spt_secrets::read_passphrase`, which echo-
suppresses and restores terminal state on every exit including panic).
For non-interactive callers (tests, supervised reloads, headless CI)
use `load_with_key(path, strict, Some(&key))`.

### `edit` flow

1. Unseal into a `secrecy::SecretBox<Zeroizing<Vec<u8>>>` (zero-on-drop).
2. Write the cleartext to an OS runtime tmpfile (`$XDG_RUNTIME_DIR` on
   Linux, `$TMPDIR` on macOS, `%LOCALAPPDATA%\Temp` on Windows) created
   with mode `0600` on Unix; an `EditSession` RAII guard owns it.
3. Spawn `$EDITOR` (override via `SPT_EDITOR_OVERRIDE`, then `$VISUAL`,
   then `$EDITOR`, then `vi`/`nano` on Unix or `notepad` on Windows).
4. On save, re-validate via `spt_config::load_str`. Any parse error
   aborts the operation without touching the original sealed file.
5. Re-seal under the **same** `KeySource` (use `crypt rotate` to
   change keys) and atomic-write back to the original path.
6. The `Drop` impl on `EditSession` best-effort zeros the tmpfile's
   contents and unlinks it on every exit path including panic.

### Security notes

- The plaintext **only** lives on disk during the `edit` window;
  outside of that, every cleartext exposure stays in zeroize-on-drop
  buffers wrapped by `secrecy::SecretBox`.
- `spt config decrypt` to stdout is honoured but should be piped — the
  cleartext is by definition not redacted.
- `--use-vault-master` seals the config under the vault master key. Use
  `--vault-passphrase-from` for headless passphrase-only vaults; otherwise
  the CLI tries the OS keychain first and prompts for the vault passphrase
  if keychain unlock is unavailable.

## See also

- [CLI Reference](cli-reference.md)
- [Remote Config](remote-config.md)
- [Security](security.md)
