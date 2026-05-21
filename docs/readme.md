# spt Documentation

Index of user-facing documentation for `spt` (SSH Permanent Tunnel).

## Guides

- [Getting Started](getting-started.md) — install and run your first tunnel
- [Installation](installation.md) — per-OS install, packages, signatures
- [Configuration](configuration.md) — TOML reference
- [CLI Reference](cli-reference.md) — every command and flag
- [Profiles](profiles.md) — profile concepts, state machine, examples
- [Forwards](forwards.md) — local/remote/UDP forwards, limits, ACLs
- [Authentication](auth.md) — pubkey, agent, password, kbi, cert, bearer, basic, OIDC
- [Secrets](secrets.md) — vault, keychain, env, and file backends
- [Trust](trust.md) — known_hosts, SHA-256 pinning, TLS pinning
- [Service Integration](service-integration.md) — systemd, launchd, SCM, Task Scheduler
- [DNS](dns.md) — transparent resolver and hosts-file integration
- [Firewall](firewall.md) — nft, pf, and Windows Firewall integration
- [Observability](observability.md) — logs, metrics, OTLP, SNMP
- [Events](events.md) — bindings, sinks, templating
- [Diagnostics](diagnostics.md) — `spt diagnose`, bundles, redaction
- [Benchmarking](benchmarking.md) — drivers, safety, comparing runs
- [Test Coverage](test-coverage.md) — feature coverage and acceptance gaps
- [MCP](mcp.md) — MCP server, resources, tools, policy
- [TUI](tui.md) — interactive profile configurator
- [SSH3](ssh3.md) — experimental SSH3 support and limitations
- [Remote Config](remote-config.md) — HTTPS config, fingerprint pinning
- [Security](security.md) — threat model, redaction, secret handling
- [Troubleshooting](troubleshooting.md) — common issues and exit codes

## Migration guides

- [Migration guides](migration/index.md) — move existing tunnel setups
  onto `spt` from autossh, sshuttle, OpenSSH `~/.ssh/config`,
  systemd-resolved, or corkscrew.

For implementation status of individual subcommands, see
[CLI Reference](cli-reference.md).
