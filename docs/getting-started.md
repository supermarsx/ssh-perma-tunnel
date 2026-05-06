# Getting Started

This guide takes you from a clean machine to a running SSH tunnel in under
five minutes.

## Prerequisites

- Linux, macOS, or Windows host. SSH access (key, password, or agent) to the
  remote endpoint you want to tunnel through.
- For systemd / launchd / SCM service installation: administrative
  privileges on the local host.

## Install spt

### From a release artifact

Pre-built binaries are published to GitHub Releases for Linux (deb, rpm,
musl-static), macOS (pkg), and Windows (msi). See [Installation](installation.md)
for signatures and verification.

### From source

Requires Rust 1.83 or later. From the workspace root:

    cargo build --release -p spt-bin
    sudo install -m 0755 target/release/spt /usr/local/bin/spt

## Create your first profile

The simplest config: a single profile with a single local TCP forward.
The bundled example matches this shape one-for-one:

    # examples/minimal.toml
    version = 1
    [[profiles]]
    name = "minimal"
    enabled = true
    protocol = "ssh2"
    host = "bastion.example.com"
    port = 22
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
    target_resolve = "remote"
    required = true

Validate it before running:

    spt config validate --config examples/minimal.toml

A successful validation prints `ok: <path> (1 profile(s))` and exits 0.
Errors and warnings include the field path so you can jump straight to
the offending line.

## Start the tunnel

In the foreground:

    spt tunnel run --foreground --config examples/minimal.toml

In another terminal, check status:

    spt tunnel status --config examples/minimal.toml

The status snapshot is also written to `<state_dir>/status.json` (see
[Configuration](configuration.md) for state-directory paths).

## Verify connectivity

For the local forward above, connect to the bind address:

    curl http://127.0.0.1:8080/

## Stop and uninstall

To stop a foreground run, send `Ctrl-C` (SIGINT) or:

    spt tunnel stop --config examples/minimal.toml

To uninstall a service:

    sudo spt service uninstall --config /etc/spt/spt.toml --system

## Where next

- [Configuration](configuration.md) — full TOML reference.
- [Profiles](profiles.md) — failover, reconnect, instability detection.
- [Forwards](forwards.md) — local, remote, UDP, multi-hop chains.
- [Service Integration](service-integration.md) — install spt as a
  long-running service.
- [Troubleshooting](troubleshooting.md) — exit codes and common failures.
