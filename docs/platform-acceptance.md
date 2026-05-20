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
  on Windows, returns `UnsupportedPlatform` elsewhere, and honors
  `Capabilities.AllowGpoPolicyWrites` / `[capabilities].allow_gpo_policy_writes`.
- Windows Event Log acceptance covers source registration, source removal, and
  test event writes through `spt observe windows-event install-source`,
  `uninstall-source`, and `test`; non-Windows hosts must return clean
  `UnsupportedPlatform` diagnostics.
- SSH2 acceptance uses the pure-Rust `russh` backend as the production target.
  Any `libssh2` run is a legacy migration lane and must be marked separately
  in reports.
- GSSAPI/Kerberos/SSPI, ML-KEM/PQ KEX, SOCKS/HTTP CONNECT, SFTP, filesystem
  mounts, and Windows drive-letter mounts must each have positive, negative,
  policy-denied, and platform-denied tests before GA.
- CLI documentation acceptance requires generated man pages for every
  top-level command group and generated completions for bash, zsh, fish,
  PowerShell, and Elvish. Linux/macOS packages must install POSIX-shell
  completions to their standard share paths, Windows package flows must expose
  the PowerShell module, and release tarballs/zips must carry all completion
  artifacts under `share/`.
- Default builds do not expose SNMP CLI. `--features snmp` builds expose SNMP
  agent/trap diagnostics, and enabled SNMP configs must set
  `[observability.snmp].enterprise_id` to a registered production PEN. Runtime
  agent startup must reject `32473` and `99999` unless the caller is using an
  explicit documentation/test fixture.
- Packages include signed checksums and preserve config/state across upgrade.
