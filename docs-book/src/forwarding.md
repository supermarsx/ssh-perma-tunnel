# Forwarding

A forward is a single accept-and-relay rule attached to a profile. `spt` supports local TCP, remote TCP, UDP, UNIX-domain-socket, and dynamic SOCKS/HTTP CONNECT forwards, as well as multi-hop chains through intermediate SSH peers. Every forward kind runs on the pure-Rust `russh` SSH2 backend. The experimental SSH3 backend (see [transports.md](transports.md)) natively supports local TCP, remote TCP, and UDP datagram forwards over QUIC.

Forwards are declared as entries in `[[profiles.forwards]]`. Each entry has a direction (`type`), a transport (`transport`), and a wire flavour (`kind`). The supervisor drives each forward through an eight-state machine:

```
Disabled -> Initialising -> Binding -> Ready
         -> Reconciling -> RemovingForward -> Stopped -> Disposed
```

Failures during `Binding` map to exit code 7 (`LocalBindFailed`) for local forwards and exit code 8 (`RemoteBindFailed`) for remote forwards.

---

## Local TCP forwarding

`type = "local"`, `transport = "tcp"` — the client binds a local TCP port and tunnels accepted connections to a remote target via SSH `direct-tcpip` channels.

```toml
[[profiles.forwards]]
name           = "db"
type           = "local"
transport      = "tcp"
bind           = "127.0.0.1:5432"
target         = "db.internal:5432"
target_resolve = "remote"     # resolve the target hostname on the SSH server side
required       = true
```

`target_resolve = "remote"` (default) sends the hostname string to the SSH server and lets the server perform DNS. `target_resolve = "local"` resolves the hostname on the client before opening the channel, sending the resulting IP to the server. Use `"remote"` for names that only exist in the server's DNS zone.

A full production example with rate limits:

```toml
[[profiles.forwards]]
name                   = "smtp"
type                   = "local"
transport              = "tcp"
bind                   = "127.0.0.1:2525"
target                 = "smtp.internal:25"
target_resolve         = "remote"
required               = true
idle_timeout           = "10m"
max_connections        = 256
max_bytes_per_second_in  = "5MiB"
max_bytes_per_second_out = "5MiB"
```

---

## Remote (reverse) TCP forwarding

`type = "remote"`, `transport = "tcp"` — the client sends a `tcpip-forward` request asking the SSH server to bind a port on its side. Each incoming connection to that remote port is delivered to the client via `forwarded-tcpip` and connected to the local `target`.

```toml
[[profiles.forwards]]
name           = "callback"
type           = "remote"
transport      = "tcp"
bind           = "127.0.0.1:18080"   # address the SSH server binds
target         = "127.0.0.1:8080"    # local service to connect to
target_resolve = "local"
required       = true
```

The full example from `examples/reverse.toml`:

```toml
[[profiles]]
name     = "reverse-admin"
enabled  = true
protocol = "ssh2"
host     = "edge.example.com"
port     = 22
user     = "edge"

[profiles.auth]
method        = "public_key"
identity_file = "~/.ssh/id_ed25519"

[[profiles.forwards]]
name           = "callback"
type           = "remote"
transport      = "tcp"
bind           = "127.0.0.1:18080"
target         = "127.0.0.1:8080"
target_resolve = "local"
required       = true
```

When `bind` uses `0.0.0.0` to expose the port on all server interfaces, the server's firewall must allow inbound connections on that port. See [firewall.md](firewall.md) and [security.md](security.md).

---

## UDP forwarding

`transport = "udp"` — forwards UDP datagrams. Over SSH2/russh, UDP is carried over standard SSH channels because SSH has no native datagram primitive. Over SSH3, datagrams map natively onto QUIC datagrams when `[profiles.ssh3] enable_datagrams = true`.

### SSH2 UDP modes

Two modes are available via `udp_mode`:

**`tcp-framed`** (default, all platforms)

Each datagram is length-prefixed and shipped over a single `direct-tcpip` channel. Datagrams larger than 64 KiB are dropped and counted in the `udp_oversize_drops` status counter. Works on Linux, macOS, and Windows.

```toml
[[profiles.forwards]]
name           = "syslog"
type           = "local"
transport      = "udp"
bind           = "127.0.0.1:5514"
target         = "logger.internal:514"
target_resolve = "remote"
udp_mode       = "tcp-framed"    # default; can be omitted
```

**`uds-bridge`** (Linux and macOS only)

Opens a `direct-streamlocal@openssh.com` channel to a remote UNIX socket that already speaks the spt UDP framing protocol. Useful with an operator-run UDP-to-UDS relay daemon on the server side. Both client and server must be Unix hosts.

```toml
[[profiles.forwards]]
name                = "metrics-udp"
type                = "local"
transport           = "udp"
bind                = "127.0.0.1:9125"
remote_socket_path  = "/run/spt-udp-bridge.sock"
udp_mode            = "uds-bridge"
```

### SSH3 UDP

Over SSH3 with `enable_datagrams = true`, UDP datagrams are mapped directly onto QUIC datagrams. No framing overhead is added:

```toml
[profiles.ssh3]
enable_datagrams = true

[[profiles.forwards]]
name                   = "dns"
type                   = "local"
transport              = "udp"
bind                   = "127.0.0.1:1053"
target                 = "dns.internal:53"
target_resolve         = "remote"
required               = true
udp_idle_timeout       = "30s"
max_datagram_size      = 1200
max_packets_per_second = 5000
```

### UDP flow table

A NAT-style flow table maps each `(local_addr, remote_addr)` pair to an SSH channel. The table is bounded by a hard cap of **65 536** concurrent flows by default; set `max_connections = 0` on the forward to remove the cap (idle eviction becomes the only bound). Idle flows are reclaimed after `udp_idle_timeout` (default 30 s). The `udp_oversize_drops` counter in `spt tunnel stats` tracks frames dropped for exceeding `max_datagram_size`.

---

## UNIX-domain socket forwarding

spt forwards UNIX-domain sockets in both directions using the OpenSSH `direct-streamlocal@openssh.com` and `streamlocal-forward@openssh.com` non-standard channel types. Set `kind` to `"local_uds"` or `"remote_uds"` on a forward entry. UDS forwards are validated at config-load time; they are rejected on Windows and on SSH3 profiles (russh on Unix supports them).

### local_uds — client to remote socket

The client binds `local_socket_path` as a local UNIX socket. Each accepted connection opens a `direct-streamlocal` channel to `remote_socket_path` on the server.

```toml
[[profiles.forwards]]
name               = "docker"
type               = "local"
transport          = "tcp"
kind               = "local_uds"
local_socket_path  = "/run/user/1000/spt-docker.sock"
remote_socket_path = "/var/run/docker.sock"
```

This exposes the server's Docker socket at `/run/user/1000/spt-docker.sock` on the client. Applications can then set `DOCKER_HOST=unix:///run/user/1000/spt-docker.sock` to use it.

### remote_uds — remote socket to local target

The client sends a `streamlocal-forward@openssh.com` global request asking the server to listen on `remote_socket_path`. Each connection to that server-side socket is tunnelled back to the client's `local_socket_path`.

```toml
[[profiles.forwards]]
name               = "expose-prom"
type               = "remote"
transport          = "tcp"
kind               = "remote_uds"
remote_socket_path = "/run/user/1000/prom.sock"   # server binds this path
local_socket_path  = "127.0.0.1:9090"             # local service to connect to (TCP or UDS)
```

---

## Dynamic SOCKS and HTTP CONNECT proxy

`type = "dynamic"`, `transport = "tcp"` — the client binds a local listener that accepts SOCKS4, SOCKS4A, SOCKS5 CONNECT, and HTTP CONNECT requests. Each request names its own remote target; spt opens a `direct-tcpip` channel to that target.

Dynamic proxy requires `allow_dynamic_proxy = true` in `[capabilities]`:

```toml
[capabilities]
allow_dynamic_proxy = true
```

Basic configuration:

```toml
[[profiles.forwards]]
name            = "proxy"
type            = "dynamic"
transport       = "tcp"
bind            = "127.0.0.1:1080"
max_connections = 128
```

When `proxy_protocols` is omitted, all four protocols are accepted. To restrict accepted protocols:

```toml
proxy_protocols = ["socks5", "http_connect"]
```

Valid values: `socks4`, `socks4a`, `socks5`, `http_connect`.

### Target ACLs

`allow_targets` and `deny_targets` restrict which destinations a dynamic proxy listener will reach. Each entry is either a host glob (`*` wildcard, case-insensitive) or a CIDR/IP rule (matched against IP-literal targets). Deny rules always win over allow rules.

```toml
[[profiles.forwards]]
name            = "restricted-proxy"
type            = "dynamic"
transport       = "tcp"
bind            = "127.0.0.1:1080"
allow_targets   = ["*.internal", "10.0.0.0/8"]
deny_targets    = ["10.99.0.0/24", "169.254.0.0/16"]
```

When `allow_targets` is non-empty, a proxied target must match an allow rule and not match any deny rule, or the SOCKS/HTTP CONNECT request is rejected before any SSH channel is opened. An empty `allow_targets` (the default) allows all targets, subject to deny rules.

SOCKS4A and SOCKS5 domain-name requests forward the hostname string to the SSH server for resolution. SOCKS4 sends a raw IP, so `target_resolve` is not meaningful for pure-IP requests.

CLI convenience:

```
spt forward add dynamic --profile edge --listen 127.0.0.1:1080 --connections 128
spt forward add dynamic --profile edge --listen 127.0.0.1:1080 \
    --proxy-protocol socks5 --proxy-protocol http-connect
```

See [cli-reference.md](cli-reference.md) for the full `spt forward` reference.

---

## Multi-hop and jump-host chains

Multi-hop chains stack SSH sessions (or proxy hops) through one or more intermediate peers. The russh path opens nested `direct-tcpip` channels end-to-end without a loopback socketpair.

### CLI shorthand

```
spt tunnel run -J alice@bastion1.example.com,bob@bastion2.example.com ...
```

`-J` accepts comma-separated `[user@]host[:port]` entries. `~/.ssh/config` host aliases are honoured unless `--portable` is active.

### Configuration hops

Hops are declared in `[[profiles.hops]]`. The final session (the one that carries forwards) is the profile's own `host`/`port`; hops describe intermediate steps to reach it.

```toml
[[profiles]]
name     = "two-hop-admin"
enabled  = true
protocol = "ssh2"
host     = "jump1.example.com"
port     = 22
user     = "ops"

[profiles.auth]
method = "agent"

[[profiles.hops]]
name             = "jump2"
protocol         = "ssh2"
host             = "jump2.internal"
port             = 22
user             = "ops"
target_resolve   = "previous-hop"

[[profiles.forwards]]
name           = "admin-ui"
type           = "local"
transport      = "tcp"
bind           = "127.0.0.1:18443"
target         = "admin.internal:443"
target_resolve = "remote"
required       = true
```

### Hop fields

| Field | Description |
|---|---|
| `name` | Unique hop identifier within the profile. |
| `protocol` | `ssh2` (only SSH2 hops are supported today). |
| `host`, `port` | Address of this intermediate peer. |
| `user` | Remote user on this hop. |
| `auth` | Per-hop auth block. Falls back to the profile `[profiles.auth]` when absent. |
| `trust` | Per-hop trust block. Falls back to the profile `[profiles.trust]` when absent. |
| `target_resolve` | `local`, `remote`, or `previous-hop`. |
| `kind` | `ssh` (default), `socks5`, or `http-connect`. |
| `proxy_username` | Username for SOCKS5 / HTTP CONNECT proxy hops. |
| `proxy_password_ref` | `secret://` reference to the proxy password. |

### Hop kinds

`HopKind` controls how spt reaches the next peer through this hop:

- `ssh` (default) — opens a `direct-tcpip` channel through the current session and re-establishes an SSH session through it. The standard SSH ProxyJump behaviour.
- `socks5` — speaks RFC 1928 CONNECT (with optional RFC 1929 user/password auth) to an existing SOCKS5 proxy already reachable from the previous hop.
- `http-connect` — speaks HTTP `CONNECT host:port HTTP/1.1` (with optional `Proxy-Authorization: Basic`) through an HTTP proxy.

```toml
[[profiles.hops]]
name              = "corp-proxy"
protocol          = "ssh2"
host              = "proxy.corp.example.com"
port              = 1080
kind              = "socks5"
proxy_username    = "alice"
proxy_password_ref = "secret://proxies/alice"
```

Per-hop `auth` and `trust` blocks allow different credentials and host-key pins on each intermediate peer. See [authentication.md](authentication.md) and [trust.md](trust.md).

---

## Bind policy

The `bind_mode` field controls how the listener address is chosen for local and dynamic forwards:

| `bind_mode` | Behaviour |
|---|---|
| `loopback` | `127.0.0.1` or `[::1]`. Default for local forwards. |
| `specific_ip` | Exactly the address in `bind`. |
| `specific_interface` | First IP on `bind_interface`. |
| `auto_interface` | Try `bind_interface_preference` entries in order. |
| `all_interfaces` | `0.0.0.0` or `[::]`. |

Binding to `all_interfaces` or a non-loopback address requires `expose = true` on the forward to confirm the operator acknowledges the broader exposure:

```toml
[[profiles.forwards]]
name      = "public-relay"
type      = "local"
transport = "tcp"
bind_mode = "all_interfaces"
bind      = "0.0.0.0:8080"
target    = "internal.host:80"
expose    = true
```

When using `all_interfaces`, ensure the host firewall is configured to permit or restrict access as intended. See [security.md](security.md) and [firewall.md](firewall.md).

---

## required forwards

Setting `required = true` on a forward marks it as critical. If the forward cannot bind or activate, the profile is marked unhealthy rather than degraded:

```toml
[[profiles.forwards]]
name      = "primary-db"
type      = "local"
transport = "tcp"
bind      = "127.0.0.1:5432"
target    = "db.internal:5432"
required  = true
```

A profile with no `required` forwards will start even if all its forwards fail to bind. With `required = true` on any forward, failure of that forward causes the profile to enter the `Failed` state, triggering the reconnect/failover policy. See [resilience.md](resilience.md).

---

## Rate limits and connection caps

Rate limits are configured inline on each forward entry. Token-bucket throttles are enforced per-connection by the `spt-forward` crate.

```toml
[[profiles.forwards]]
name                        = "smtp"
type                        = "local"
transport                   = "tcp"
bind                        = "127.0.0.1:2525"
target                      = "smtp.internal:25"
max_connections             = 256          # concurrent accepted connections
max_new_connections_per_second = 50        # accept rate
max_bytes_per_second_in     = "5MiB"       # inbound throughput cap
max_bytes_per_second_out    = "5MiB"       # outbound throughput cap
max_burst_bytes_in          = "10MiB"      # burst allowance
max_burst_bytes_out         = "10MiB"
idle_timeout                = "10m"        # close idle connections
```

For UDP-specific limits:

```toml
udp_idle_timeout       = "30s"    # evict idle UDP flows
max_datagram_size      = 1500     # drop datagrams exceeding this size
max_packets_per_second = 5000     # per-flow packet rate cap
```

Profile-level limits (maximum across all forwards in a profile) are set in `[profiles.limits]`. See [configuration-reference.md](configuration-reference.md) for the full `Limits` table reference.

---

## Bind conflict policy

When the requested bind address is already in use, `on_bind_conflict` controls the response:

| Value | Behaviour |
|---|---|
| `fail` (default) | Return `LocalBindFailed` (exit 7). |
| `retry` | Retry the bind after a short delay. |
| `next_port` | Increment the port number and retry. |

---

## DNS name registration

Forwards can register DNS names with the spt DNS resolver so that tunnelled services are reachable by name when the embedded DNS is enabled:

```toml
[[profiles.forwards]]
name      = "api"
type      = "local"
transport = "tcp"
bind      = "127.0.0.1:8443"
target    = "api.internal:443"
dns_names = ["api.tunnel.local"]
sni_name  = "api.internal"
```

`dns_names` entries are registered as synthetic A records. `sni_name` provides a TLS SNI hint for clients connecting through the forward. See [dns.md](dns.md).

---

## SFTP and FTP translator

SFTP file transfer and filesystem mounting are configured via `[[profiles.sftp_mounts]]` on a profile that already uses the SSH2 backend. The `spt sftp` command group provides interactive transfer and mount/unmount operations. An FTP-to-SFTP translator surface allows legacy FTP clients to connect to a local listener that proxies their commands over the SSH channel.

For the full SFTP surface including platform support (Linux FUSE, Windows Dokany2, macOS sshfs shell-out), mount lifecycle, and exit codes, see the SFTP chapter. CLI commands are documented in [cli-reference.md](cli-reference.md).
