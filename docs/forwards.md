# Forwards

A forward is a single accept-and-relay rule attached to a profile. `spt`
supports local TCP, remote TCP, and UDP forwards (UDP only via SSH3 since
SSH2 has no UDP channel type). SSH2/russh also supports dynamic TCP proxy
listeners for SOCKS5 and HTTP CONNECT.

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

Listens locally and accepts SOCKS5 CONNECT or HTTP CONNECT. Each client
request chooses its own remote target, and `spt` opens an SSH2 `direct-tcpip`
channel to that target. This is controlled by `allow_dynamic_proxy`.

    [capabilities]
    allow_dynamic_proxy = true

    [[profiles.forwards]]
    name = "proxy"
    type = "dynamic"
    transport = "tcp"
    bind = "127.0.0.1:1080"
    max_connections = 128

CLI:

    spt forward add dynamic --profile edge --listen 127.0.0.1:1080 --connections 128

## UDP (SSH3 only)

    [[profiles.forwards]]
    name = "syslog"
    type = "local"
    transport = "udp"
    bind = "127.0.0.1:5514"
    target = "logger.internal:514"

UDP datagrams are mapped onto QUIC datagrams. Oversized datagrams are
dropped and counted in `udp_oversize_drops` (status snapshot).

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
