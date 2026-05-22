# Forwards

A forward is a single accept-and-relay rule attached to a profile. `spt`
supports local TCP, remote TCP, UDP, UNIX-domain-socket, and dynamic
proxy forwards. Every forward kind runs uniformly on the pure-Rust
`russh` backend — there is no longer a backend split (libssh2 was
removed in t7). SSH3 over QUIC is available as an experimental
alternative transport that natively supports UDP datagrams.

## Local TCP (`type = "local"`)

Listens locally; bytes are tunneled to a remote target.

    [[profiles.forwards]]
    name = "db"
    type = "local"
    transport = "tcp"
    bind = "127.0.0.1:5432"
    target = "db.internal:5432"
    target_resolve = "remote"   # remote | local

## Remote TCP (`type = "remote"`)

Asks the remote peer to listen on its side; incoming connections are
tunneled back through and connected to the local target.

    [[profiles.forwards]]
    name = "egress"
    type = "remote"
    transport = "tcp"
    bind = "0.0.0.0:9090"
    target = "127.0.0.1:9090"

## Dynamic TCP Proxy (`type = "dynamic"`)

Listens locally and accepts SOCKS4, SOCKS4A, SOCKS5 CONNECT, or HTTP CONNECT.
Each client request chooses its own remote target, and `spt` opens an SSH2
`direct-tcpip` channel to that target. This is controlled by
`allow_dynamic_proxy`.

    [capabilities]
    allow_dynamic_proxy = true

    [[profiles.forwards]]
    name = "proxy"
    type = "dynamic"
    transport = "tcp"
    bind = "127.0.0.1:1080"
    max_connections = 128
    proxy_protocols = ["socks4", "socks4a", "socks5", "http_connect"]

CLI:

    spt forward add dynamic --profile edge --listen 127.0.0.1:1080 --connections 128
    spt forward add dynamic --profile edge --listen 127.0.0.1:1080 --proxy-protocol socks5 --proxy-protocol http-connect

`proxy_protocols` is optional. When omitted, the listener accepts every
supported dynamic proxy protocol. Use a subset when compatibility policy
requires it. SOCKS4A and SOCKS5 domain-name requests are forwarded by hostname
so the SSH server side performs target DNS resolution.

## UDP forwarding

    [[profiles.forwards]]
    name = "syslog"
    type = "local"
    transport = "udp"
    bind = "127.0.0.1:5514"
    target = "logger.internal:514"
    udp_mode = "tcp-framed"     # tcp-framed (default) | uds-bridge

Over SSH2/russh, UDP is tunnelled by framing datagrams over a regular
`direct-tcpip` channel. Two modes are available:

- `tcp-framed` (default) — each datagram is length-prefixed (16-bit
  big-endian) and shipped over a single `direct-tcpip` channel. 64 KiB
  per-frame cap; oversized datagrams are dropped and counted in
  `udp_oversize_drops` (status snapshot). Works on every russh build,
  Linux / macOS / Windows.
- `uds-bridge` — opens a `direct-streamlocal@openssh.com` channel to a
  remote UNIX socket that already speaks the SSH-UDP framing protocol.
  Useful for OpenSSH 8.4+ servers configured with `StreamLocalBindUnlink`
  + a userspace UDP relay. Unix-only on both ends.

Over SSH3, UDP datagrams are mapped directly onto QUIC datagrams. The
same `udp_oversize_drops` counter applies.

## UNIX-domain-socket forwarding (`type = "local_uds"` / `"remote_uds"`)

`spt` supports forwarding UNIX-domain sockets in both directions via the
SSH `direct-streamlocal@openssh.com` channel type:

    [[profiles.forwards]]
    name = "docker"
    type = "local_uds"
    bind = "/run/user/1000/spt-docker.sock"
    target = "/var/run/docker.sock"

    [[profiles.forwards]]
    name = "expose-prom"
    type = "remote_uds"
    bind = "/run/user/1000/prom.sock"      # remote path on the server
    target = "127.0.0.1:9090"              # local TCP backend

UDS forwards are validated at config-load time against the configured
profile's backend capability. `Forward.link_kind` semantics: the
validator rejects UDS link kinds on Windows and on any SSH3 profile;
russh on Unix accepts them.

## Multi-hop / jump-proxy chains (`-J`)

Multi-hop chains stack `direct-tcpip` channels through one or more
intermediate SSH peers. The native russh path opens nested channels
end-to-end — there is no loopback socketpair indirection.

    spt tunnel run -J alice@bastion1.example.com,bob@bastion2.example.com ...

`-J` accepts comma-separated `[user@]host[:port]` entries; `~/.ssh/config`
host aliases are honoured (unless `--portable` is active, which skips
`~/.ssh/config` resolution).

## Bind modes

`bind_mode` controls how the listener address is chosen:

- `loopback` — `127.0.0.1` / `[::1]` (default for `local`).
- `specific_ip` — exactly the address in `bind`.
- `specific_interface` — pick the first IP on `bind_interface`.
- `auto_interface` — try `bind_interface_preference` in order.
- `all_interfaces` — `0.0.0.0` / `[::]`.

## ACLs

Per-forward CIDR allow/deny lists:

    [profiles.forwards.acl]
    allow = ["10.0.0.0/8"]
    deny  = ["10.99.0.0/24"]
    default = "deny"

## Limits

    [profiles.forwards.limits]
    max_connections = 64
    rate_in = "10MiB/s"
    rate_out = "10MiB/s"
    udp_idle = "30s"

Token-bucket throttles are applied per-connection, per-forward, and
per-profile (configurable in each scope).

## Forward state machine

8 states:

    Disabled -> Initialising -> Binding -> Ready
            -> Reconciling -> RemovingForward -> Stopped (-> Disposed)

Failures during `Binding` map to `LocalBindFailed` (exit code 7) for local
forwards or `RemoteBindFailed` (8) for remote forwards.

## See also

- [Profiles](profiles.md)
- [Firewall](firewall.md) — opening ports for `0.0.0.0` binds.
- [DNS](dns.md) — `target_resolve = "spt-dns"` for split-horizon resolution.
