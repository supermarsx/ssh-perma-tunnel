# Troubleshooting

A symptom-keyed reference for common `spt` issues, plus the full exit-code
table from spec §7.4.

## Quick diagnostic

When in doubt, generate a redacted bundle for support:

```bash
spt diagnose run --report report.json
spt diagnose bundle --out support.tgz --redacted --since 24h
```

The bundle is strictly redacted by default — review `manifest.txt` before
sharing externally.

## Symptoms → fixes

### "another spt instance is already running" — exit 16 (`StateLockFailed`)

The state directory has an active `fs4` lock (`<state_dir>/spt.lock`). Either
another `spt tunnel run` is live (check `<state_dir>/spt.pid`) or a previous
process didn't release its file handle. Fix:

```bash
spt tunnel stop --state-dir /var/lib/spt
# or, if no process exists (last resort):
rm /var/lib/spt/spt.pid /var/lib/spt/spt.lock
```

### "no config path supplied" — exit 1 (`InvalidArgs`)

Pass `--config PATH` or set `SPT_CONFIG`. There is no per-OS auto-discovery
in M0.

### "validation failed" — exit 2 (`InvalidConfig`)

`spt config validate` shows the offending field path. Common causes:

- Wrong `version` (must be `1`).
- `protocol` outside `{ssh2, ssh3}`.
- `bind` not parseable (use `host:port` or `[v6]:port`).
- Inline plaintext secret (use `secret://…`).
- `auth.method` typo — see [Authentication](auth.md) for canonical names.

Re-run with `--strict` once warnings are clean to catch unknown fields.

### "auth failed" — exit 5 (`AuthFailed`)

- Confirm the configured method matches what the server allows (server
  `AuthenticationMethods` setting).
- For `agent`, verify `$SSH_AUTH_SOCK` exists in the supervisor's
  environment. Service units typically need `Environment=SSH_AUTH_SOCK=…`.
- For `public_key`, check the file mode is owner-only (`0600` on Unix).
- For `password` / `bearer_token`, run `spt secret get <ref>` to confirm the
  backend can resolve the secret.

### "trust verification failed" — exit 6 (`TrustFailed`)

The remote host key didn't match `known_hosts` or the SHA-256 pin. If this is
a legitimate rotation, list both old and new pins simultaneously, reload, then
remove the old after the rollout.

### "local bind failed" — exit 7 (`LocalBindFailed`)

Port already in use, or insufficient privilege to bind a low port. Use
`bind_mode = "loopback"` and a high port, or grant `CAP_NET_BIND_SERVICE` (see
[Service Integration](service-integration.md)).

### "remote bind failed" — exit 8 (`RemoteBindFailed`)

The remote SSH server refused the `tcpip-forward` request. Check
`AllowTcpForwarding`, `GatewayPorts`, and the user's permissions on the
remote.

### "secret unavailable" — exit 17 (`SecretUnavailable`)

Run `spt secret doctor` for a backend health summary. Typical causes:

- macOS Keychain: spt was launched without GUI session (LaunchAgent vs
  LaunchDaemon).
- Linux Secret Service: `dbus-daemon` not running in the unit's environment.
- File backend: permission or path mismatch.

### "rate limited" — exit 22 (`RateLimited`)

A throttle policy denied the operation. See `[profiles.limits]` and per-forward
`max_new_connections_per_second`.

### "all failover targets exhausted" — exit 23 (`FailoverExhausted`)

Every endpoint in `[[profiles.endpoints]]` failed its health check. Check
`spt diagnose port` against each endpoint and inspect the `profile.failover`
events.

### High CPU or memory at idle

The runtime is designed for near-zero idle. If you see otherwise:

- `RUST_LOG=spt=debug spt tunnel run --foreground …` and capture a few seconds.
- Check the status snapshot for any profile stuck in `Reconnecting` —
  reconnect failures keep the supervisor scheduling.

## Full exit-code table (spec §7.4)

The binary uses 38 stable exit codes. The numeric value of every code is
contractually fixed.

| Code | Name                         | Meaning                                                   |
|------|------------------------------|-----------------------------------------------------------|
| 0    | `Success`                    | Successful completion.                                    |
| 1    | `InvalidArgs`                | Invalid command-line arguments.                           |
| 2    | `InvalidConfig`              | Configuration file failed to load or validate.            |
| 3    | `RuntimeFailure`             | Generic runtime failure (incl. M0 stubs).                 |
| 4    | `RequiredProfileFailed`      | A `required` profile failed to start or stay up.          |
| 5    | `AuthFailed`                 | Authentication to a remote endpoint failed.               |
| 6    | `TrustFailed`                | Host-key / TLS / pin verification failed.                 |
| 7    | `LocalBindFailed`            | A local listening bind failed.                            |
| 8    | `RemoteBindFailed`           | A remote/forwarded bind failed.                           |
| 9    | `ServiceManagerFailed`       | A service-manager operation failed.                       |
| 10   | `UnsupportedPlatform`        | Platform or feature is not supported.                     |
| 11   | `DnsFailed`                  | DNS resolution or the internal resolver failed.           |
| 12   | `NetworkUnreachable`         | Network unreachable / connection refused.                 |
| 13   | `KeepaliveTimeout`           | Keepalive timed out.                                      |
| 14   | `ReloadFailed`               | `config reload` failed.                                   |
| 15   | `LoggingSinkUnavailable`     | A required logging sink is unavailable.                   |
| 16   | `StateLockFailed`            | State-directory lock acquisition failed.                  |
| 17   | `SecretUnavailable`          | A referenced secret is unavailable / locked / denied.     |
| 18   | `SecretCryptoFailed`         | Secret encryption / decryption failed.                    |
| 19   | `KeyFailure`                 | Key generation, parsing, or file-permission check failed. |
| 20   | `PermissionDenied`           | OS-level permission denied.                               |
| 21   | `ResourceExhausted`          | Resource exhausted / out-of-memory.                       |
| 22   | `RateLimited`                | A rate limit or throttle rejected the operation.          |
| 23   | `FailoverExhausted`          | All failover targets exhausted.                           |
| 24   | `SnmpOrMetricsFailed`        | SNMP agent or metrics exporter failed.                    |
| 25   | `WindowsEventLogFailed`      | A Windows Event Log operation failed.                     |
| 26   | `McpFailed`                  | MCP server policy or operation failed.                    |
| 27   | `RemoteSinkRejected`         | A remote observability sink rejected delivered data.      |
| 28   | `PartialDegraded`            | Partial success with degraded non-required profiles.      |
| 29   | `HealthCheckFailed`          | A health check failed.                                    |
| 30   | `VersionOrMigrationFailed`   | Schema version / migration failure.                       |
| 31   | `InternalError`              | Internal assertion / invariant / `unreachable`.           |
| 32   | `DiagnosticFailed`           | A diagnostic check reported failure.                      |
| 33   | `DiagnosticBundleFailed`     | Diagnostic bundle generation failed.                      |
| 34   | `BenchmarkFailed`            | A benchmark run failed.                                   |
| 35   | `BenchmarkRefused`           | Benchmark refused by safety policy.                       |
| 36   | `SessionNotFound`            | Session id not found.                                     |
| 37   | `SessionCloseFailed`         | Session close / drain failed.                             |

Source of truth: [`crates/spt-core/src/exit_code.rs`](../crates/spt-core/src/exit_code.rs).

## Filing a bug report

```bash
spt --version
spt diagnose run --report report.json
spt diagnose bundle --out support.tgz --redacted --since 24h
```

Attach `support.tgz`, `report.json`, and the version string. The bundle is
strictly redacted by default — see [Diagnostics](diagnostics.md) and
[Security](security.md) for the redaction model.
