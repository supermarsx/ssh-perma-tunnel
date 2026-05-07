# Migrating from OpenSSH `~/.ssh/config`

## Audience

You currently drive long-lived tunnels through entries in
`~/.ssh/config` (or `/etc/ssh/ssh_config`), with options like
`LocalForward`, `RemoteForward`, `ServerAliveInterval`,
`ControlMaster`, and `ProxyJump`. Reconnect is typically handled by
either:

- A wrapper script that re-runs `ssh -N` on exit, or
- A systemd user unit with `Restart=always`, or
- Nothing at all — you reconnect manually after a drop.

You want first-class supervision without rewriting every script that
relies on `ssh` being on `$PATH`.

## What OpenSSH gives you

OpenSSH's `ssh_config(5)` is the canonical reference. The relevant
options for tunnel-style usage:

| Option                          | Effect                                                        |
|---------------------------------|---------------------------------------------------------------|
| `Host`                          | Pattern that scopes subsequent options                        |
| `HostName`                      | Real hostname for that alias                                  |
| `User`, `Port`                  | Endpoint user and port                                        |
| `IdentityFile`                  | Path to a private key                                         |
| `IdentitiesOnly`                | Don't fall through to the agent                               |
| `ProxyJump` (`-J`)              | One or more intermediate hops                                 |
| `ProxyCommand`                  | Custom command to bridge stdin/stdout to the remote           |
| `LocalForward`                  | Repeatable: `[bind:]port host:hostport`                       |
| `RemoteForward`                 | Repeatable: `[bind:]port host:hostport` (other direction)     |
| `DynamicForward`                | SOCKS proxy bind                                              |
| `ServerAliveInterval`           | Seconds between keepalive probes                              |
| `ServerAliveCountMax`           | Probes missed before declaring dead                           |
| `TCPKeepAlive`                  | OS-level keepalive on the SSH socket                          |
| `ExitOnForwardFailure`          | Exit if a forward listener can't bind                         |
| `ControlMaster`/`ControlPath`/`ControlPersist` | Connection multiplexing                  |
| `StrictHostKeyChecking`         | known_hosts policy                                            |
| `UserKnownHostsFile`            | Where to find known_hosts                                     |
| `KexAlgorithms`/`Ciphers`/`MACs`| Crypto negotiation                                            |
| `Match`                         | Conditional blocks                                            |
| `IdentityAgent`                 | Path to a specific agent socket                               |

## What spt gives you that's similar

| OpenSSH option                 | spt equivalent                                                  |
|--------------------------------|------------------------------------------------------------------|
| `Host alias`                   | `[[profiles]] name = "alias"`                                    |
| `HostName`/`Port`/`User`       | Profile-level `host`/`port`/`user`                               |
| `IdentityFile`                 | `[profiles.auth] method = "public_key" identity_file = …`        |
| `IdentityAgent`                | Set `SSH_AUTH_SOCK` in the service env; `[profiles.auth] method = "agent"` |
| `IdentitiesOnly = yes`         | Use `method = "public_key"` (no agent fallback)                 |
| `ProxyJump`                    | `[[profiles.hops]]` chain                                        |
| `ProxyCommand`                 | No direct equivalent — `spt` is the connector itself             |
| `LocalForward`                 | `[[profiles.forwards]] type = "local"`                           |
| `RemoteForward`                | `[[profiles.forwards]] type = "remote"`                          |
| `DynamicForward`               | Not yet — see "What OpenSSH does" below                          |
| `ServerAliveInterval`          | `[profiles.keepalive] interval`                                  |
| `ServerAliveCountMax`          | `[profiles.keepalive] max_missed`                                |
| `ExitOnForwardFailure = yes`   | `required = true` on the forward                                 |
| `ControlMaster`/`ControlPersist` | Always on — `spt` multiplexes channels per session             |
| `StrictHostKeyChecking yes`    | `[profiles.trust] mode = "known_hosts" strict = true`            |
| `UserKnownHostsFile`           | `[profiles.trust] known_hosts_file = …`                          |
| `KexAlgorithms`/`Ciphers`/`MACs` | `[profiles.crypto] kex = […] ciphers = […] macs = […]`        |

## Concrete config translation

### A typical `~/.ssh/config`

```ssh-config
Host bastion
    HostName bastion.example.com
    User tunnel
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    ServerAliveInterval 30
    ServerAliveCountMax 3
    ExitOnForwardFailure yes
    LocalForward 5432 db.internal:5432
    LocalForward 8443 admin.internal:443
    StrictHostKeyChecking yes
    UserKnownHostsFile ~/.ssh/known_hosts

Host inner
    HostName inner.internal
    User ops
    ProxyJump bastion
    LocalForward 9000 metrics.internal:9000
```

### The spt equivalent

```toml
version = 1

[runtime]
state_dir = "~/.local/state/spt"

[[profiles]]
name = "bastion"
enabled = true
protocol = "ssh2"
host = "bastion.example.com"
port = 22
user = "tunnel"

[profiles.auth]
method = "public_key"
identity_file = "~/.ssh/id_ed25519"

[profiles.trust]
mode = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict = true

[profiles.keepalive]
interval = "30s"
timeout = "10s"
max_missed = 3

[profiles.reconnect]
initial_delay = "1s"
max_delay = "60s"
jitter = "20%"
reset_after = "5m"

[[profiles.forwards]]
name = "db"
type = "local"
transport = "tcp"
bind = "127.0.0.1:5432"
target = "db.internal:5432"
target_resolve = "remote"
required = true

[[profiles.forwards]]
name = "admin"
type = "local"
transport = "tcp"
bind = "127.0.0.1:8443"
target = "admin.internal:443"
target_resolve = "remote"
required = true

# Second profile reaches "inner" via the same bastion as a hop.
[[profiles]]
name = "inner"
enabled = true
protocol = "ssh2"
host = "bastion.example.com"
port = 22
user = "tunnel"

[profiles.auth]
method = "public_key"
identity_file = "~/.ssh/id_ed25519"

[profiles.trust]
mode = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict = true

[[profiles.hops]]
name = "inner-hop"
protocol = "ssh2"
host = "inner.internal"
port = 22
user = "ops"
target_resolve = "previous-hop"

[[profiles.forwards]]
name = "metrics"
type = "local"
transport = "tcp"
bind = "127.0.0.1:9000"
target = "metrics.internal:9000"
target_resolve = "remote"
required = true
```

Two `Host` blocks in `~/.ssh/config` map to two `[[profiles]]` blocks
in `spt.toml`. Each profile owns its own session, keepalive, and
reconnect state.

### `Match` blocks

OpenSSH's `Match` is a conditional. `spt` doesn't have a conditional
profile language; instead, you express the same intent by:

- Splitting profiles by environment (`bastion-prod`, `bastion-staging`)
  and toggling `enabled`, or
- Using `[[profiles.endpoints]]` failover when the conditional is
  "if A unreachable, use B," or
- Templating the config from your config-management tool.

### `ControlMaster` / `ControlPath`

OpenSSH's connection multiplexing reuses an existing TCP+SSH session
for new sessions to the same host. `spt` is always-multiplexed: every
forward defined in a profile rides the same SSH session as a separate
SSH channel. You don't need to configure it. There is no socket file
to leak between runs.

## What changes for the operator

### Where the config lives

| Concern                  | OpenSSH                       | spt                                       |
|--------------------------|-------------------------------|-------------------------------------------|
| User config              | `~/.ssh/config`               | `~/.config/spt/spt.toml` or `--config`    |
| System config            | `/etc/ssh/ssh_config`         | `/etc/spt/spt.toml`                       |
| Per-host overrides       | Pattern matching on `Host`    | Multiple `[[profiles]]`                   |
| Include other files      | `Include ~/.ssh/config.d/*`   | Use config-management or pre-render TOML  |

`spt` does not currently support a multi-file `Include` directive.
For fleet management, generate the TOML from a template.

### Lifecycle

`ssh -N -L … host` runs in the foreground; you control its lifetime.
`spt tunnel run --foreground` is the same shape, but for long-running
operation use:

```sh
spt service install --config ~/.config/spt/spt.toml --user
systemctl --user enable --now spt.service
```

For system-wide installs, use `--system` and run the equivalent
`systemctl` commands as root.

### Logging

OpenSSH's verbosity comes from `-v`, `-vv`, `-vvv`, sending free-form
diagnostics to stderr. `spt`'s default is `info`-level structured
logging; raise it with `[logging] level = "debug"` or one-shot
`spt --verbose tunnel run …`.

### Signal handling

| Signal     | OpenSSH                      | spt                                          |
|------------|------------------------------|----------------------------------------------|
| `SIGINT`   | Graceful disconnect           | Graceful shutdown                            |
| `SIGTERM`  | Graceful disconnect           | Graceful shutdown with `shutdown_grace`      |
| `SIGHUP`   | Disconnects                   | Reload config (when `[runtime.reload].mode = "signal"`) |
| `~.` escape sequence | Disconnect from a tty | Not applicable — `spt tunnel stop`           |

### Known-hosts

`spt` reads the same `known_hosts` file format OpenSSH uses (hashed
or plain). Pin `[profiles.trust].mode = "known_hosts"` and point
`known_hosts_file` at the file you already trust. Hostname-keyed
SHA-256 pins are also supported via `[profiles.trust]` — see
[Trust](../trust.md).

## What spt does that OpenSSH config doesn't

- **Supervisor-level reconnect with backoff and jitter.** OpenSSH
  exits on disconnect; you build the loop. `spt` ships the loop.
- **Per-profile failover.** `[[profiles.endpoints]]` with priority,
  weight, and health checks; OpenSSH has no native failover.
- **Hot reload.** Edit the TOML; SIGHUP or `systemctl reload spt`
  applies changes without dropping unaffected forwards.
- **Built-in DNS resolver** for naming forwarded services.
- **Structured observability** — JSON logs, Prometheus, OTLP, SNMPv3,
  events, MCP.
- **Secret resolution.** Identity passphrases through keychain or
  vault, never plaintext in the config.
- **SSH3 backend.** Optional QUIC/HTTP-3 transport for environments
  that block raw TCP/22.

## What OpenSSH does that spt doesn't

- **`DynamicForward` (SOCKS).** OpenSSH's `-D` opens a SOCKS proxy
  in the SSH client. `spt` does not currently expose a SOCKS proxy
  forward. If you need one, run OpenSSH's `ssh -ND 1080` alongside
  `spt`.
- **`ProxyCommand` arbitrary executable.** `spt` reaches the remote
  via `direct-tcpip` channels through declared hops; it does not
  shell out to an arbitrary `ProxyCommand`. (Bridges like
  corkscrew are addressed in [from-corkscrew](from-corkscrew.md).)
- **Interactive shell sessions.** `spt` is tunnels-only; if you need
  `ssh user@host` for a shell, keep using OpenSSH alongside.
- **`Match exec` and other dynamic config.** No conditional config
  in `spt`; template the file.
- **PKCS#11 `SecurityKeyProvider` flows for FIDO2.** See upstream
  [Authentication](../auth.md) docs for what is supported today.
- **Agent forwarding (`-A` / `ForwardAgent`).** Not exposed.
- **X11 forwarding.** Not exposed.
- **`SendEnv`/`AcceptEnv` of arbitrary client env to the server.**
  Not exposed.

When in doubt about an OpenSSH option not listed in this guide:
**see upstream `ssh_config(5)`** rather than guessing whether `spt`
honors it.

## Side-by-side runtime comparison

| Dimension                          | OpenSSH `ssh -N`                            | spt                                              |
|------------------------------------|---------------------------------------------|--------------------------------------------------|
| Cold-start                         | One handshake                                | One handshake (same `libssh2` path)             |
| Memory (single tunnel)             | ~5–8 MiB                                     | ~6–10 MiB (one supervisor for many profiles)    |
| Reconnect on drop                  | Manual or via `Restart=always`               | Built-in, with backoff                          |
| Multi-tunnel cost                  | One ssh process per `Host`                   | One supervisor across all profiles              |
| Config file format                 | Plaintext, position-sensitive                | TOML, structured                                |
| Hot reload                         | Restart                                      | SIGHUP / `systemctl reload`                     |

## Step-by-step migration recipe

1. **Read your current `~/.ssh/config`.** Identify which `Host`
   blocks are tunnel-only (typically those used with `-N`) and
   which are interactive shells. Only the former are migration
   candidates.

2. **Install `spt`** and pick a config path (e.g.
   `~/.config/spt/spt.toml` for a personal setup).

3. **Translate one tunnel-only `Host` block** using the table
   above. Keep the OpenSSH entry in place for now — your existing
   shell aliases (`ssh bastion`) continue to work.

4. **Validate.**

   ```sh
   spt config validate --config ~/.config/spt/spt.toml --strict
   ```

5. **Trial-run in the foreground.**

   ```sh
   spt tunnel run --foreground --config ~/.config/spt/spt.toml
   ```

6. **Compare behavior.** Stop the OpenSSH tunnel; verify the
   `spt` one serves your application. Then bounce the network
   and confirm `spt` reconnects without intervention.

7. **Install as a user service.**

   ```sh
   spt service install --config ~/.config/spt/spt.toml --user
   systemctl --user enable --now spt.service
   ```

8. **Trim `~/.ssh/config`.** Remove tunnel-specific options
   (`LocalForward`, `RemoteForward`, `ServerAliveInterval`) from
   the `Host` blocks `spt` now manages, but leave the basic
   `Host`/`HostName`/`User`/`IdentityFile` entries — you'll still
   want them for interactive `ssh` use.

9. **Repeat** for additional `Host` blocks. Each becomes another
   `[[profiles]]` in the same `spt.toml`.

## See also

- [Configuration](../configuration.md)
- [Profiles](../profiles.md)
- [Authentication](../auth.md)
- [Trust](../trust.md)
- [`examples/jump-host.toml`](../../examples/jump-host.toml)
