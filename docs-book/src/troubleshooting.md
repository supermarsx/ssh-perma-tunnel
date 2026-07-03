# Troubleshooting

A practical guide to diagnosing and resolving common `spt` problems, with a complete exit-code reference and instructions for generating diagnostic bundles.

## Quick diagnostic

When in doubt, generate a redacted bundle before doing anything else. It captures logs, config (redacted), status, events, and metrics in a single archive:

```sh
spt diagnose run --report report.json
spt diagnose bundle --out support.tgz --redacted --since 24h
```

The bundle is strictly redacted by default. Review `manifest.txt` inside the archive before sharing it externally. See [Security](security.md) for the redaction model.

## Using `spt diagnose`

`spt diagnose` runs structured checks against the local environment and any loaded config. Each check has an identifier, severity, status, an evidence list, and an optional remediation hint.

### Available subcommands

```sh
spt diagnose run                                    # batch: all checks
spt diagnose run --report report.json               # write structured JSON report
spt diagnose network                                # network reachability probes
spt diagnose auth                                   # authentication pre-flight
spt diagnose trust                                  # host-key and TLS pin checks
spt diagnose dns                                    # resolver connectivity
spt diagnose bind                                   # local port availability
spt diagnose port --host db --port 5432 --tcp --autodetect-service
spt diagnose service                                # service manager state
spt diagnose secrets                                # secret backend health
spt diagnose observability                          # metrics and logging sinks
spt diagnose mcp                                    # MCP server tool and resource count
spt diagnose bundle --out support.tgz --redacted --since 24h
```

`diagnose run` executes the real check set (it is not a stub) and exits non-zero when any check fails. The `mcp` check spawns `mcp serve --stdio --enable` and asserts the live tool and resource counts. The `network`, `dns`/`bind`, `service`, and `time` (NTP drift) checks run real probes.

`diagnose port --autodetect-service` performs a banner-then-probe sweep: it reads the server's first bytes for known patterns (SSH, SMTP, IMAP, POP3, FTP), or sends a TLS ClientHello or HTTP probe when the peer is silent.

### Bundle contents

`spt diagnose bundle` produces a `tar.gz` containing:

| File | Contents |
|---|---|
| `manifest.txt` | Generation metadata, timestamps, spt version. |
| `version.txt` | Output of `spt --version`. |
| `effective-config.toml` | Strict-redacted merged config. |
| `status.json` | Last status snapshot. |
| `events.jsonl` | Recent event stream (redacted). |
| `logs.txt` | Tail of the log file. |
| `stats.txt` | Prometheus metrics exposition from the state-dir metrics file. |
| `report.json` | Structured diagnostic report from `diagnose run`. |

Every text entry is passed through `spt_core::redact(.., RedactionMode::Strict)` as a defence-in-depth measure even after each producer has already applied its own redaction.

## Where logs and state live

Default paths (override via `[runtime].state_dir`):

| Path | Contents |
|---|---|
| `/var/lib/spt/` | State directory: lock, PID file, status snapshot, event spool, benchmark results, metrics file. |
| `/var/lib/spt/status.json` | Last supervisor status snapshot. |
| `/var/lib/spt/spt.lock` | `fs4` exclusive lock (held while supervisor is running). |
| `/var/lib/spt/spt.pid` | Supervisor PID file. |
| `/var/lib/spt/benchmarks/` | Benchmark result files (`<run-id>.json` and `<run-id>.md`). |
| `/var/lib/spt/metrics.prom` | Prometheus metrics file (written when metrics exporter is enabled). |
| Log file | Path set by `[logging].file`; defaults to stderr when not configured. |

## Enabling verbose logs

For interactive troubleshooting, set `RUST_LOG` before starting `spt`:

```sh
RUST_LOG=spt=debug spt tunnel run --foreground --config /etc/spt/spt.toml
```

To restrict to a specific module:

```sh
RUST_LOG=spt_ssh2=trace,spt=info spt tunnel run --foreground ...
```

For structured JSON logs redirect stderr and parse with `jq`:

```sh
RUST_LOG=spt=debug spt tunnel run --foreground 2>&1 | jq .
```

Persistent verbose logging via config:

```toml
[logging]
level = "debug"
format = "json"
destinations = ["stderr", "file"]
file = "/var/log/spt/spt.log"
```

See [Observability](observability.md) for the full logging and metrics reference.

## Common failures and fixes

### "another spt instance is already running" (exit 16, `StateLockFailed`)

The state directory has an active `fs4` lock. Either another `spt tunnel run` is live (check `<state_dir>/spt.pid`) or a previous process exited without releasing its file handle.

```sh
spt tunnel stop --state-dir /var/lib/spt
# If no process exists (last resort after confirming no supervisor is running):
rm /var/lib/spt/spt.pid /var/lib/spt/spt.lock
```

Set `[runtime].file_lock = false` in ephemeral environments such as CI containers where stale locks cannot accumulate.

### "no config path supplied" (exit 1, `InvalidArgs`)

Pass `--config PATH` or set the `SPT_CONFIG` environment variable. There is no per-OS auto-discovery.

### "validation failed" (exit 2, `InvalidConfig`)

Run `spt config validate --config <path>` for the specific field path. Common causes:

- `version` must be `1`.
- `protocol` must be `ssh2` or `ssh3`.
- `bind` not parseable; use `host:port` or `[::1]:port`.
- Inline plaintext secret value; use `secret://namespace/name` instead.
- `auth.method` typo; see [Authentication](authentication.md) for canonical names.
- Unknown field; run with `--strict` to promote unknown-field warnings to errors.

### "auth failed" (exit 5, `AuthFailed`)

- Confirm the configured method matches what the server allows (`AuthenticationMethods` in `sshd_config`).
- For `agent`: verify `SSH_AUTH_SOCK` exists in the supervisor's environment. Service units typically need `Environment=SSH_AUTH_SOCK=...` added to the unit file.
- For `public_key`: check the file mode is owner-only (`chmod 0600`).
- For `password` or `bearer_token`: run `spt secret get <ref>` to confirm the backend can resolve the reference. Run `spt diagnose secrets` for a backend health summary.

### "trust verification failed" (exit 6, `TrustFailed`)

The remote host key did not match `known_hosts` or the configured SHA-256 pin. Possible causes:

- Legitimate host-key rotation: add the new pin alongside the old one, reload, then remove the old pin after the rollout completes. See [Trust](trust.md).
- MITM or incorrect host: do not weaken the trust policy; investigate the mismatch.
- `trust.mode = "tofu"` accepted a key on first connection that has now changed.

### "local bind failed" (exit 7, `LocalBindFailed`)

The local listening port is already in use or the process lacks privilege to bind a port below 1024.

```sh
ss -tlnp | grep <port>    # find what holds the port
```

Mitigations:

- Use a high port (`> 1024`) and `bind_mode = "loopback"`.
- Grant `CAP_NET_BIND_SERVICE` via the systemd unit `AmbientCapabilities=` if a low port is required. See [Service](service.md).

### "remote bind failed" (exit 8, `RemoteBindFailed`)

The remote SSH server refused the `tcpip-forward` request. Check:

- `AllowTcpForwarding` in `sshd_config` (must be `yes` or `local`/`remote` as appropriate).
- `GatewayPorts` when binding on non-loopback addresses at the remote side.
- The user's shell or forced-command restrictions.

### "secret unavailable" (exit 17, `SecretUnavailable`)

Run `spt secret doctor` for a backend health summary. Typical causes by backend:

- **macOS Keychain**: `spt` was launched without a GUI session (LaunchAgent vs LaunchDaemon distinction). The Keychain prompt has no TTY to present to.
- **Linux Secret Service**: `dbus-daemon` is not running in the unit's environment. Add `Environment=DBUS_SESSION_BUS_ADDRESS=...` to the unit.
- **File backend**: path or permission mismatch. Confirm `<state_dir>/secrets/<namespace>/<name>` exists and is readable by the `spt` user.
- **Vault backend**: vault is sealed, the passphrase changed, or the vault file path is wrong.

### "DNS resolution failed" (exit 11, `DnsFailed`)

- `spt diagnose dns` will probe the configured upstream resolvers.
- Check the `[dns]` config section; verify `upstream` addresses are reachable.
- If `auto_records = true`, confirm the forward `dns_names` fields are valid.
- For transient DNS drift (short-TTL records that change while the tunnel is up), configure `target_resolve = "remote"` on the forward to re-resolve at reconnect time. See [DNS](dns.md).

### "network unreachable" (exit 12, `NetworkUnreachable`)

The TCP connection to the SSH endpoint was refused or could not be routed.

- `spt diagnose port --host <endpoint> --port <port> --tcp` tests reachability directly.
- Confirm firewall rules permit outbound connections on the SSH port. See [Firewall](firewall.md).
- For failover configurations, check all `[[profiles.endpoints]]` are reachable.

### "all failover targets exhausted" (exit 23, `FailoverExhausted`)

Every endpoint in `[[profiles.endpoints]]` failed its health check. Run:

```sh
spt diagnose port --host <endpoint> --port <port> --tcp
```

against each endpoint. Inspect the `profile.failover` events in the status snapshot for individual failure reasons. Check endpoint health checks (`[profiles.load_balance].health_check`) and `fail_after` settings.

### "rate limited" (exit 22, `RateLimited`)

A throttle policy denied the operation. Review `[profiles.limits]` and per-forward `max_new_connections_per_second`. If the rate limit is legitimately too low, raise it in config.

### SSH3 "unsupported platform" (exit 10, `UnsupportedPlatform`)

SSH3 is over QUIC/HTTP3 and requires the `ssh3` protocol in the profile. If `spt` was built without the `ssh3` feature or the platform does not support QUIC, this error is returned. Check `spt about` for compiled-in features.

When running `spt benchmark udp` against a live tunnel, `UnsupportedPlatform` is also returned because there is no live datagram seam in the `TunnelSession` API; run it against the synthetic connector instead. See [Benchmarking](benchmarking.md).

### High CPU or memory at idle

The runtime is designed for near-zero idle overhead. If you observe high CPU or memory:

- Start with `RUST_LOG=spt=debug spt tunnel run --foreground ...` and capture a few seconds of output.
- Check the status snapshot (`spt tunnel stats`) for any profile stuck in the `Reconnecting` state. A profile that cannot connect keeps the supervisor scheduling reconnect attempts; inspect the reconnect delay and backoff settings under `[profiles.reconnect]`.
- If memory grows over time, enable the RSS monitor in config:

```toml
[mem_hygiene]
enabled          = true
interval         = "60s"
window_samples   = 30
growth_threshold = "64MiB"
```

The monitor emits a `memory.leak_suspected` event when it detects sustained growth. See [Observability](observability.md).

### Reconnect storms

A reconnect storm occurs when a profile continuously reconnects due to repeated short-lived failures. Symptoms: high reconnect event rate in the event stream, CPU spikes, log flood.

Mitigations:

- Increase `[profiles.reconnect].initial_delay` and `max_delay`.
- Set `[profiles.reconnect].jitter` to spread reconnect attempts across a window.
- Set `max_attempts` to limit the total attempt count; the profile will then fail rather than retry indefinitely.
- Check whether the remote endpoint has an aggressive connection rate limit or auth throttle.
- If the cause is keepalive timeout, increase `[profiles.keepalive].interval` or `timeout`, or increase `max_missed`.

## Filing a bug report

```sh
spt --version
spt diagnose run --report report.json
spt diagnose bundle --out support.tgz --redacted --since 24h
```

Attach `support.tgz`, `report.json`, and the `--version` string. The bundle is strictly redacted by default — see [Security](security.md) for the redaction model — but review it before sharing.

## Complete exit-code table

All 38 stable exit codes from `crates/spt-core/src/exit_code.rs` (spec §7.4). Numeric values are contractually fixed and will never be reused.

| Code | Name | Meaning |
|---|---|---|
| 0 | `Success` | Successful completion. |
| 1 | `InvalidArgs` | Invalid command-line arguments. |
| 2 | `InvalidConfig` | Configuration file failed to load or validate. |
| 3 | `RuntimeFailure` | Generic runtime failure (including unimplemented stubs). |
| 4 | `RequiredProfileFailed` | A profile marked `required` failed to start or stay up. |
| 5 | `AuthFailed` | Authentication to a remote endpoint failed. |
| 6 | `TrustFailed` | Host-key, TLS certificate, or pin verification failed. |
| 7 | `LocalBindFailed` | A local listening bind failed. |
| 8 | `RemoteBindFailed` | A remote/forwarded bind failed. |
| 9 | `ServiceManagerFailed` | A service-manager operation (install, start, stop) failed. |
| 10 | `UnsupportedPlatform` | Platform or feature is not supported. |
| 11 | `DnsFailed` | DNS resolution or the internal resolver failed. |
| 12 | `NetworkUnreachable` | Network unreachable or connection refused. |
| 13 | `KeepaliveTimeout` | Keepalive timed out. |
| 14 | `ReloadFailed` | `config reload` failed. |
| 15 | `LoggingSinkUnavailable` | A required logging sink is unavailable. |
| 16 | `StateLockFailed` | State-directory lock acquisition failed (another instance running). |
| 17 | `SecretUnavailable` | A referenced secret is unavailable, locked, or denied. |
| 18 | `SecretCryptoFailed` | Secret encryption or decryption failed. |
| 19 | `KeyFailure` | Key generation, parsing, or file-permission check failed. |
| 20 | `PermissionDenied` | OS-level permission denied. |
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
| 31 | `InternalError` | Internal assertion, invariant, or `unreachable`. |
| 32 | `DiagnosticFailed` | A diagnostic check reported failure. |
| 33 | `DiagnosticBundleFailed` | Diagnostic bundle generation failed. |
| 34 | `BenchmarkFailed` | A benchmark run failed. |
| 35 | `BenchmarkRefused` | Benchmark refused by safety policy (missing two-key gate). |
| 36 | `SessionNotFound` | Session ID not found. |
| 37 | `SessionCloseFailed` | Session close or drain failed. |

Source of truth: `crates/spt-core/src/exit_code.rs`. For the security implications of each code category see [Security](security.md).
