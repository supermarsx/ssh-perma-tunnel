# Platform Acceptance Criteria

`spt` is release-ready only when the same production matrix is exercised for
rootless and privileged installs. A row passes when install, upgrade, start,
reload, stop, status, logs, uninstall, config preservation, and state
preservation all pass on the named platform.

| Platform | Service mode | Rootless | Privileged | Firewall/hosts path | Policy path |
|----------|--------------|----------|------------|---------------------|-------------|
| Linux systemd | system service | required | required | nftables/iptables + hosts-file | config + remote config |
| Linux systemd | user service | required | n/a | rootless preview only | config + remote config |
| Linux OpenRC | system service | n/a | required | nftables/iptables + hosts-file | config + remote config |
| Linux SysV | system service | n/a | required | iptables + hosts-file | config + remote config |
| macOS launchd | user agent | required | n/a | pf preview + user config | config + remote config |
| macOS launchd | daemon | n/a | required | pf + hosts-file | config + remote config |
| Windows SCM | service | n/a | required | Windows Firewall + hosts-file | HKLM GPO + config |
| Windows Task Scheduler | user task | required | optional | preview unless elevated | HKCU GPO + config |

Required checks:

- `spt service install|start|status|logs|restart|stop|uninstall` returns the
  documented exit code and JSON shape where supported.
- `spt tunnel reload` preserves running profiles when a reload is rejected by
  `require_valid_config = true`.
- Interface-specific binds, gateway policy, offload policy, weighted failover,
  and manual failover are covered by config validation plus at least one live
  or fixture-backed test on each OS family.
- `spt firewall bind-preview` resolves loopback, explicit IP, specific
  interface, auto-interface, and all-interface modes.
- `spt firewall policy list|show` works everywhere; `set|unset` writes HKCU/HKLM
  on Windows and returns `UnsupportedPlatform` elsewhere.
- Default builds do not expose SNMP CLI. `--features snmp` builds expose SNMP
  agent/trap diagnostics, and enabled SNMP configs must set
  `[observability.snmp].enterprise_id` to a registered production PEN.
- Packages include signed checksums and preserve config/state across upgrade.
