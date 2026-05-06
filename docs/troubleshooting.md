# Troubleshooting

A symptom-keyed reference for common `spt` issues. For a full exit-code
table see [CLI Reference](cli-reference.md).

## "another spt instance is already running" (exit 16)

The state directory has an active `fs4` lock (`<state_dir>/spt.lock`). Either
another `spt tunnel run` is live (check `<state_dir>/spt.pid`) or a previous
process didn't release its file handle. Fix:

    spt tunnel stop --state-dir /var/lib/spt
    # or, if no process exists:
    rm /var/lib/spt/spt.pid /var/lib/spt/spt.lock   # last resort

## "no config path supplied" (exit 1)

Pass `--config PATH` or set `SPT_CONFIG`. There is no per-OS auto-discovery
in M0.

## "unsupported platform" (exit 10)

A subsystem is not implemented for the current OS — typical for firewall
applies on a host without nftables/pf/netsh. Use `--dry-run` to preview the
plan.

## "validation failed" (exit 2)

`spt config validate` shows the offending field path. Common causes:
- Wrong `version` (must be `1`).
- `protocol` outside `{ssh2, ssh3}`.
- `bind` not parseable (use `host:port` or `[v6]:port`).

## "auth failed" (exit 5)

- Confirm the configured method matches what the server allows.
- For agent auth, verify `$SSH_AUTH_SOCK` exists in the supervisor's
  environment.
- For pubkey, check the file mode is owner-only (`0600`).

## "trust verification failed" (exit 6)

The remote host key didn't match `known_hosts` or the SHA-256 pin. If this
is a legitimate rotation, update the trust material in config and reload.

## High CPU or memory at idle

The runtime is designed for near-zero idle. If you see otherwise:
- Set `RUST_LOG=spt=debug` and capture a few seconds of logs.
- Check status snapshot for any profile stuck in `Reconnecting` —
  reconnect failures keep the supervisor scheduling.

## Filing a bug report

    spt diagnose bundle --out support.tgz --redacted --since 24h

Attach `support.tgz`. The bundle is strictly redacted by default — review
the `manifest.txt` to confirm.
