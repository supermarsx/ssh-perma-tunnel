# spt Documentation

Index of user-facing documentation for `spt` (SSH Permanent Tunnel).

## Guides

- [Getting Started](getting-started.md) — install and run your first tunnel
- [Installation](installation.md) — per-OS install, packages, signatures
- [Configuration](configuration.md) — TOML reference
- [CLI Reference](cli-reference.md) — every command and flag
- [Profiles](profiles.md) — profile concepts, state machine, examples
- [Forwards](forwards.md) — local/remote/UDP/UDS forwards, jump chains, limits, ACLs
- [Authentication](auth.md) — pubkey, agent, password, kbi, cert, SSPI/GSSAPI, bearer, basic, OIDC
- [Secrets](secrets.md) — vault, keychain, env, and file backends
- [Trust](trust.md) — known_hosts, SHA-256 pinning, TLS pinning
- [SFTP](sftp.md) — SFTP client + mount surfaces (FUSE/Dokany2/sshfs)
- [Obfuscation](obfuscation.md) — obfs4, meek-http, ssh-over-websocket, shadowsocks
- [Scripting](scripting.md) — rhai-based hook engine (`pre_connect`, `post_connect`, ...)
- [Service Integration](service-integration.md) — systemd, launchd, SCM, Task Scheduler
- [Docker](docker.md) — hardened distroless container, compose security profile, secrets at runtime
- [DNS](dns.md) — transparent resolver and hosts-file integration
- [Firewall](firewall.md) — nft, pf, and Windows Firewall integration
- [Observability](observability.md) — logs, metrics, OTLP, SNMP
- [Events](events.md) — bindings, sinks, templating
- [Memory Hygiene](mem-hygiene.md) — opt-in RSS growth monitor, `memory.leak_suspected`
- [Diagnostics](diagnostics.md) — `spt diagnose`, bundles, redaction
- [Benchmarking](benchmarking.md) — drivers, safety, comparing runs
- [MCP](mcp.md) — MCP server, resources, tools, policy
- [TUI](tui.md) — interactive profile configurator
- [SSH3](ssh3.md) — experimental SSH3 support and limitations
- [Remote Config](remote-config.md) — HTTPS config, fingerprint pinning
- [Security](security.md) — threat model, redaction, secret handling
- [Troubleshooting](troubleshooting.md) — common issues and exit codes
- [Versioning](versioning.md) — the rolling `YY.N` scheme and Cargo encoding

For implementation status of individual subcommands, see
[CLI Reference](cli-reference.md).
