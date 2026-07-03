# Quick Start

This chapter takes you from a bare installation to a running SSH tunnel in
under five minutes, then shows a second pattern — a reverse (remote) forward —
to demonstrate the main config shape variations.

## Prerequisites

- `spt` installed (see [Installation](installation.md)).
- SSH access to a remote host. The examples use key-based auth via an agent
  (`ssh-agent` running and `ssh-add`ed); substitute `method = "public_key"`
  with an explicit `identity_file` if you have no agent.
- For the reverse-forward example: a service running locally that you want to
  expose at the remote end.

## Example 1 — local TCP forward

A local forward makes a service on the remote side reachable as a local
port. This is the simplest tunnel shape.

### Write the config

Save the following as `~/spt-minimal.toml` (or copy from
`examples/minimal.toml` in the repository root and update the host/user):

```toml
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
# Standard OpenSSH known_hosts file. On Windows: %USERPROFILE%\.ssh\known_hosts
known_hosts_file = "~/.ssh/known_hosts"
strict = true

[[profiles.forwards]]
name = "web"
type = "local"
transport = "tcp"
bind = "127.0.0.1:8080"
target = "service.internal:80"
target_resolve = "remote"
required = true
```

**Key fields:**

- `type = "local"` — listen locally (`bind`), forward to `target` via the SSH
  server's network.
- `target_resolve = "remote"` — the target hostname is resolved by the SSH
  server, not by `spt`'s local DNS. This is what you want for names that only
  exist on the remote side.
- `required = true` — `spt` treats a failure to establish this forward as a
  fatal error rather than continuing with a degraded set.

### Validate the config

Before running, check that the config parses and passes all validation rules:

```sh
spt config validate --config ~/spt-minimal.toml
```

On success you see:

```
ok: /home/alice/spt-minimal.toml (1 profile(s))
```

Errors and warnings include the dotted field path so you can jump straight to
the offending line.

### Run in the foreground

```sh
spt tunnel run --foreground --config ~/spt-minimal.toml
```

`spt` connects to `bastion.example.com:22`, authenticates via the agent,
establishes the forward, and prints structured log lines to stderr. It stays
in the foreground; press `Ctrl-C` to stop gracefully.

### Verify connectivity

In a second terminal:

```sh
curl http://127.0.0.1:8080/
```

If `service.internal:80` is reachable from `bastion.example.com`, you will
get its response. The local port `8080` is bound on the loopback interface
only (`127.0.0.1`), so it is not world-reachable.

### Inspect live status

```sh
spt tunnel status --config ~/spt-minimal.toml
```

This reads the status snapshot from the state directory and prints a
human-readable (or `--json`) summary of every profile and forward: connection
state, last connect/disconnect time, forward health, and error counts.

### Stop the tunnel

Send `Ctrl-C` in the foreground terminal, or from another shell:

```sh
spt tunnel stop --config ~/spt-minimal.toml
```

## Example 2 — reverse (remote) forward

A reverse forward has `spt` ask the SSH server to listen on a remote port and
forward connections back to a local service. This is how you expose a
service running on your machine through a server you can already reach.

### Write the config

```toml
version = 1

[[profiles]]
name = "reverse-web"
enabled = true
protocol = "ssh2"
host = "bastion.example.com"
port = 22
user = "alice"

[profiles.auth]
method = "agent"

[profiles.trust]
mode = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict = true

[profiles.reconnect]
# Reconnect automatically on drops; back off up to 2 minutes.
initial_delay = "2s"
max_delay = "2m"
jitter = "20%"

[[profiles.forwards]]
name = "expose-local-app"
type = "remote"
transport = "tcp"
# The server listens on this address/port.
bind = "0.0.0.0:9090"
# Connections are forwarded here, resolved from spt's (local) perspective.
target = "127.0.0.1:3000"
target_resolve = "local"
required = true
```

**Key differences from example 1:**

- `type = "remote"` — the SSH server (`bastion.example.com`) opens the
  listener. The remote kernel bind rule applies: `0.0.0.0:9090` makes the
  listener world-reachable from the server; restrict it to `127.0.0.1:9090`
  if you want it loopback-only on the server. Your SSH server's `GatewayPorts`
  directive must allow remote-bind addresses that are not loopback.
- `target_resolve = "local"` — `target` is resolved by `spt` itself, which is
  appropriate here because the target (`127.0.0.1:3000`) is on the local
  machine.
- The `[profiles.reconnect]` block ensures `spt` re-establishes the reverse
  forward automatically after any connection drop.

### Validate and run

```sh
spt config validate --config ~/spt-reverse.toml
spt tunnel run --foreground --config ~/spt-reverse.toml
```

A connection to `bastion.example.com:9090` will now arrive at `localhost:3000`
on the machine running `spt`.

## Running as a service

For long-lived tunnels, install `spt` as a managed service so it starts at
boot and recovers from crashes automatically. See [Service Management](service.md).

## Configuration validation in CI

For headless environments (CI pipelines, GitLab runners, GitHub Actions)
`spt config validate` exits 0 on success and non-zero on any error — usable
in a pre-deploy gate. The bundled `examples/headless-ci.toml` shows a
fully-annotated CI-oriented config: env-backend secrets, eager startup,
`failure_policy = "fail_process"` (the pipeline fails loudly instead of
retrying), and a Prometheus state-file exporter.

## Where next

- [Configuration Overview](configuration-overview.md) — top-level TOML
  structure, the `version` field, and config precedence.
- [Configuration Reference](configuration-reference.md) — every table and
  field, with defaults and validation rules.
- [CLI Reference](cli-reference.md) — every `spt` command, flag, and exit code.
- [Forwarding](forwarding.md) — local, remote, dynamic (SOCKS/HTTP CONNECT),
  UDP, UNIX-domain socket, and multi-hop chain forwards.
- [Service Management](service.md) — install `spt` as a systemd / launchd /
  SCM / OpenRC / SysV / Task Scheduler service.
