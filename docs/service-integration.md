# Service Integration

`spt service install --config /etc/spt/spt.toml --system` installs `spt` as a
managed service using the right backend for the host OS. **One service per
config file** — profile filters are runtime-only; do not split a config to
get separate services.

## systemd (Linux)

The shipped unit lives at [/packaging/systemd/spt.service](../packaging/systemd/spt.service).
The service uses `Type=notify` + `sd_notify` for clean state reporting, runs
as `spt:spt`, and applies `NoNewPrivileges`, `ProtectSystem=strict`, and
`PrivateTmp=true`.

User-scope services (`--user`) install under
`~/.config/systemd/user/spt-<config-stem>.service`.

## launchd (macOS)

A LaunchDaemon plist ships at
[/packaging/pkg/com.mariana.spt.plist](../packaging/pkg/com.mariana.spt.plist).
For per-user installs, choose `--user` to write a LaunchAgent under
`~/Library/LaunchAgents/`.

## Windows SCM

`spt service install --system` registers via the Service Control Manager
using the `windows-service` crate. Service start type is `Automatic` and
recovery is configured for restart-on-failure.

## OpenRC / SysV

Templates live under `/packaging/openrc/` and `/packaging/sysv/`. These are
fallbacks for systems without systemd; not exercised in CI.

## Reload semantics

| Backend  | Reload trigger                                |
|----------|-----------------------------------------------|
| systemd  | `systemctl reload spt.service` (SIGHUP).      |
| launchd  | `launchctl kill -HUP system/com.mariana.spt`. |
| SCM      | Service "Pause" event (`ParamChange` flag).   |

## Render without installing

    spt service render --config /etc/spt/spt.toml --system --format unit

## Status & control

    spt service status  --config /etc/spt/spt.toml --system --json
    spt service start   --config /etc/spt/spt.toml --system
    spt service stop    --config /etc/spt/spt.toml --system
    spt service uninstall --config /etc/spt/spt.toml --system
