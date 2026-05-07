# Migrating from corkscrew

## Audience

You currently tunnel SSH through an HTTP `CONNECT` proxy using
[corkscrew](https://github.com/bryanpkc/corkscrew) (or the closely
related `proxytunnel` / `httptunnel`) as a `ProxyCommand`. The classic
shape:

```ssh-config
Host bastion
    HostName bastion.example.com
    Port 443
    ProxyCommand corkscrew proxy.corp.example 8080 %h %p ~/.corkscrew-auth
```

You're investigating `spt` because you want a supervised tunneling
client *and* you'd prefer not to keep tunneling SSH-over-TCP-over-HTTP
forever. `spt`'s SSH3 backend (QUIC + HTTP/3) is the modern equivalent
for environments where raw SSH/22 is blocked.

## What corkscrew gives you

corkscrew is a tiny tool. From upstream:

- Reads stdin/stdout, opens a TCP socket to an HTTP proxy, issues
  `CONNECT host:port HTTP/1.1`, and on success bridges the socket.
- Optional HTTP basic auth from a credentials file (`user:password`).
- No TLS. No proxy-side authentication beyond Basic. No keepalive.
  No retry.

It exists to make `ssh` work through a proxy that allows the
`CONNECT` verb. Its operation is:

```
ssh client -> corkscrew (stdin/stdout) -> TCP to proxy:port
            -> proxy CONNECT to bastion:22 -> bastion sshd
```

## What spt gives you that's similar

`spt` ships an experimental SSH3 backend: SSH multiplexed over QUIC
inside HTTP/3. That fundamentally changes the picture:

- The "proxy traversal" problem disappears at the network level —
  HTTP/3 is what corporate proxies, CDN front doors, and
  load balancers natively understand.
- TLS termination, ALPN selection, and proxy-side authentication
  (bearer tokens, OIDC, HTTP Basic) become first-class.
- You no longer need a `ProxyCommand` at all; the SSH3 endpoint
  *is* an HTTPS URL.

| corkscrew concept                  | spt SSH3 counterpart                                   |
|------------------------------------|---------------------------------------------------------|
| `CONNECT host:port` over HTTP      | HTTP/3 request to `endpoint = "https://…"`             |
| Proxy host/port                    | Implicit — DNS / direct HTTPS                           |
| `~/.corkscrew-auth` (Basic)        | `[profiles.auth] method = "http_basic"` with `secret://` |
| (No keepalive)                     | `[profiles.keepalive]` against the SSH3 transport       |
| (Manual restart on drop)           | `[profiles.reconnect]` supervisor                       |
| (No TLS)                           | `[profiles.tls]` with `system_roots`/`ca_file`/pinning  |

## Concrete config translation

### Old setup

```ssh-config
# ~/.ssh/config
Host bastion
    HostName bastion.example.com
    Port 443
    User tunnel
    ProxyCommand corkscrew proxy.corp.example 8080 %h %p ~/.corkscrew-auth
    LocalForward 5432 db.internal:5432
    ServerAliveInterval 30
```

```ini
# ~/.corkscrew-auth
alice:s3cret
```

Wrapped with `autossh -M 0 -N bastion` for restart-on-drop.

### SSH3 spt config

If your bastion runs the [`francoismichel/ssh3`](https://github.com/francoismichel/ssh3)
reference server (or any other SSH3-compliant endpoint), the corkscrew
layer disappears entirely. Compare
[`examples/ssh3.toml`](../../examples/ssh3.toml):

```toml
version = 1

[[profiles]]
name = "ssh3-bastion"
enabled = true
protocol = "ssh3"
acknowledge_experimental = true
endpoint = "https://bastion.example.com:443/ssh3?user={username}"
user = "tunnel"
connect_timeout = "10s"

[profiles.auth]
method = "bearer_token"
token = "secret://ssh3/bastion/token"
# Or: method = "http_basic" with `username = "alice"`, `password = "secret://…"`

[profiles.tls]
server_name = "bastion.example.com"
system_roots = true
allow_self_signed = false

[profiles.ssh3]
draft = "michel-remote-terminal-http3-00"
protocol_token = "remote-terminal"
enable_datagrams = true

[profiles.keepalive]
interval = "30s"
timeout = "10s"
max_missed = 3

[profiles.reconnect]
initial_delay = "1s"
max_delay = "60s"
jitter = "20%"

[[profiles.forwards]]
name = "db"
type = "local"
transport = "tcp"
bind = "127.0.0.1:5432"
target = "db.internal:5432"
target_resolve = "remote"
required = true
```

The `acknowledge_experimental = true` line is required (per spec
§14.7) — SSH3 is experimental and `spt` refuses to start without
that explicit opt-in. See [SSH3](../ssh3.md) for limitations.

### Bridging period: SSH2 over an HTTPS proxy

If you cannot move the bastion to SSH3 yet, your options are:

1. **Keep corkscrew (or `ssh -o ProxyCommand=…`) and wrap with `spt`'s
   SSH2 profile.** `spt` does not currently embed an HTTP `CONNECT`
   client of its own. The cleanest bridge is an external `ssh`
   daemon-side approach (a TLS-terminating reverse proxy that exposes
   the bastion's SSH on port 443 directly). Once that's in place,
   `spt` connects with `protocol = "ssh2"` and `port = 443` like any
   normal endpoint.

2. **Move to SSH3** on the bastion as soon as you can. The SSH3
   reference implementation deploys behind nginx / Caddy with
   trivial config, so this is often easier than it sounds.

In both cases, the HTTP-CONNECT-via-corkscrew layer goes away.

## What changes for the operator

### No `ProxyCommand`

`spt` does not invoke arbitrary `ProxyCommand` executables. If you
absolutely depend on traversing an HTTP proxy *with no other
options*, you must keep that traversal at the network layer (a TLS
SNI gateway, an HTTPS forward proxy that supports tunneling, or
SSH3 — which uses the proxy verbs natively).

### TLS configuration

corkscrew is plaintext HTTP. SSH3 is HTTPS. You'll need:

- A trust path to the server certificate (`system_roots = true`,
  or a custom `ca_file = "…"`, or a certificate pin via
  `[profiles.trust]` — see [Trust](../trust.md)).
- The `server_name` your bastion presents in the certificate.

### Authentication

corkscrew handed `user:password` to the proxy, never to the SSH
server. SSH3 conflates the two: HTTP-style auth (`bearer_token`,
`http_basic`, `oidc`, `ssh3_public_key`) authenticates you against
the SSH3 endpoint directly. Pick `bearer_token` for most cases —
short-lived tokens scoped to the SSH3 endpoint are easier to
rotate than basic credentials.

### Logging

corkscrew logs nothing of operational use. `spt` emits structured
events for handshake, auth, forward bind, reconnect — all the
checkpoints you previously had no visibility into.

## What spt does that corkscrew doesn't

Just about everything corkscrew explicitly disclaims:

- Reconnect supervision.
- TLS with proper CA trust and certificate pinning.
- Token-based authentication and OIDC device flow.
- Multiple forwards multiplexed over one session (corkscrew has no
  awareness of forwards at all — it's a stdin/stdout pipe).
- UDP forwards (over SSH3's QUIC datagrams).
- DNS, observability, MCP — the same things every other migration
  guide in this directory lists.

## What corkscrew does that spt doesn't

- **Acts as a `ProxyCommand` for arbitrary `ssh` clients.** corkscrew
  is a building block for any tool that knows about
  `ProxyCommand`; `spt` is a complete client and is not invokable
  in that role.
- **Works with HTTP/1.1 `CONNECT` proxies.** `spt`'s SSH3 backend
  uses HTTP/3 (over QUIC). If your environment's proxy *only*
  speaks HTTP/1.1 `CONNECT` and explicitly blocks UDP/443, neither
  SSH3 nor `spt` can traverse it directly. Stay on corkscrew (or
  use a TLS-tunneling alternative) until the network policy
  changes.
- **Zero-config.** corkscrew is one binary and one credentials
  file. `spt` always wants a TOML.

## Side-by-side runtime comparison

| Dimension                       | corkscrew + ssh                              | spt SSH3                                              |
|---------------------------------|----------------------------------------------|--------------------------------------------------------|
| Wire protocol                   | TCP -> HTTP CONNECT -> SSH                   | UDP/443 -> QUIC -> HTTP/3 -> SSH3                      |
| TLS                             | None (proxy auth in cleartext basic)         | TLS 1.3 (QUIC native)                                  |
| Handshake round-trips           | 2 (CONNECT) + N (SSH KEX)                    | 1 (QUIC 0-RTT/1-RTT) + N (SSH3)                        |
| Reconnect on drop                | Manual / autossh                             | Built-in, with backoff                                 |
| UDP forwards                     | No                                           | Yes (QUIC datagrams)                                   |
| Auth methods                     | Basic to proxy + whatever ssh has            | bearer / basic / OIDC / ssh3_public_key                |

## Step-by-step migration recipe

1. **Confirm SSH3 is feasible.** Check whether your bastion can run
   the SSH3 reference server, and whether your network egress
   permits UDP/443 outbound. If UDP/443 is blocked, you may be stuck
   with corkscrew until network policy changes.

2. **Install `spt`** locally and the SSH3 server on your bastion
   (see upstream `francoismichel/ssh3` docs).

3. **Provision an auth credential.** A bearer token is simplest:
   generate one server-side and store it in your secret backend.

   ```sh
   spt secret put ssh3/bastion/token --from-stdin
   ```

4. **Write a minimal `spt.toml`** matching the template above.

5. **Validate** with the experimental flag:

   ```sh
   spt config validate --config ~/.config/spt/spt.toml --strict
   ```

   Without `acknowledge_experimental = true` in the profile, this
   fails — that's intentional.

6. **Foreground run.**

   ```sh
   spt tunnel run --foreground --config ~/.config/spt/spt.toml
   spt tunnel status --config ~/.config/spt/spt.toml
   ```

7. **Test the forward.** Connect to `127.0.0.1:5432` (or whatever
   you bound) and confirm the bastion-side service responds.

8. **Run alongside corkscrew briefly.** Both setups can coexist on
   different bind ports while you build confidence in the SSH3
   path.

9. **Cut over.** Disable the autossh / corkscrew wrapper, install
   `spt` as a user or system service, and remove the corkscrew
   credentials file (and the `Host bastion` block from
   `~/.ssh/config` if it was tunnel-only).

## See also

- [SSH3](../ssh3.md) — backend overview, draft tracking, limitations
- [Configuration](../configuration.md)
- [Trust](../trust.md) — TLS pinning for the SSH3 endpoint
- [`examples/ssh3.toml`](../../examples/ssh3.toml)
