# Migrating from sshuttle

## Audience

You currently use [sshuttle](https://github.com/sshuttle/sshuttle) — sometimes
described as "a poor man's VPN over SSH" — to route specific subnets
(or all of `0/0`) through an SSH server. You're considering `spt` because
you want a long-lived, supervised tunneling client with structured
observability.

This guide is a little different from the others in the series:
**sshuttle and `spt` solve overlapping but distinct problems**, and for
some workloads sshuttle is still the right tool. Read the "What
sshuttle does that spt doesn't" section before committing.

## What sshuttle gives you

sshuttle's upstream description is "where transparent proxy meets VPN
meets ssh" (see upstream docs and `man sshuttle`). Concretely:

- A single command that, given a remote SSH host and a list of subnets,
  routes those subnets through the SSH server transparently — no
  per-application proxy config.
- Implementation: install local firewall rules (Linux `nftables` or
  legacy `iptables` with `REDIRECT`/`TPROXY`; macOS `pf`) so traffic to
  configured subnets is captured and tunneled to a Python helper that
  sshuttle uploads to the remote host on connect.
- Optional `--dns` flag — captures DNS UDP/53 the same way and resolves
  via the remote.
- Connection-only state on the remote: nothing is installed; on
  disconnect, the remote helper exits.
- "Auto-hosts" — the remote helper scrapes `/etc/hosts` and shares
  names back to the client.

What it deliberately doesn't do: per-port forwards, reverse forwards,
service-manager integration, multi-endpoint failover.

## What spt gives you that's similar

| sshuttle concept                    | spt counterpart                                              |
|--------------------------------------|--------------------------------------------------------------|
| `-r user@host`                       | `[[profiles]]` block with `host`/`user`                      |
| Subnet captures (e.g. `10.0.0.0/8`) | **No direct equivalent** — see "What sshuttle does" below   |
| Specific port reroute                | `[[profiles.forwards]]` `type = "local"`                     |
| Reconnect on drop                    | `[profiles.reconnect]` with full-jitter backoff              |
| `--dns`                              | `[dns]` resolver with `mode = "transparent_forwarder"`       |
| `--auto-hosts`                      | `[dns]` `hosts_file_mode = "render_only"` + managed records |
| `-x exclude/24`                      | Resolve specific names through DNS upstream + per-forward bind |
| `--ssh-cmd`                          | `[profiles.auth]` and `[profiles.trust]` instead             |
| Python helper on remote              | None — `spt` is a pure SSH/SSH3 client                       |

## Concrete config translation

### Per-port reroute (the easy case)

If your sshuttle invocation is essentially "I want to reach a handful of
named services," that translates cleanly:

```bash
# Old: route DB and admin UI through bastion.
sshuttle -r tunnel@bastion.example.com 10.10.5.10/32 10.10.5.11/32
```

becomes a profile with explicit forwards:

```toml
version = 1

[[profiles]]
name = "internal-services"
enabled = true
protocol = "ssh2"
host = "bastion.example.com"
port = 22
user = "tunnel"

[profiles.auth]
method = "agent"

[profiles.trust]
mode = "known_hosts"
strict = true

[[profiles.forwards]]
name = "db"
type = "local"
transport = "tcp"
bind = "127.0.0.1:5432"
target = "10.10.5.10:5432"
target_resolve = "remote"
required = true

[[profiles.forwards]]
name = "admin"
type = "local"
transport = "tcp"
bind = "127.0.0.1:8443"
target = "10.10.5.11:443"
target_resolve = "remote"
required = true
```

Clients now reach the database at `127.0.0.1:5432` and admin UI at
`127.0.0.1:8443` — no firewall manipulation, no privileged subnet
capture. If your apps hard-code `10.10.5.10`, see the DNS section
below.

### DNS-based name reroute (the recommended pattern)

sshuttle's `--dns` flag plus auto-hosts gave you "internal names just
work" without per-app config. `spt` reaches the same end state with
managed DNS records (compare
[`examples/dns-split-horizon.toml`](../../examples/dns-split-horizon.toml)):

```bash
# Old:
sshuttle --dns -r tunnel@bastion 10.10.0.0/16
```

```toml
[dns]
enabled = true
mode = "transparent_forwarder"
bind = "127.0.0.1:5353"
zone = "spt.local"
upstream = ["1.1.1.1:53", "9.9.9.9:53"]
hosts_file_mode = "render_only"

[[dns.records]]
name = "db.internal.spt.local"
type = "A"
value = "127.0.0.1"
ttl = "30s"

[[profiles]]
name = "internal"
protocol = "ssh2"
host = "bastion.example.com"
user = "tunnel"

[profiles.auth]
method = "agent"

[profiles.trust]
mode = "known_hosts"
strict = true

[[profiles.forwards]]
name = "db"
type = "local"
transport = "tcp"
bind = "127.0.0.1:5432"
target = "db.internal.corp:5432"   # the real upstream name
target_resolve = "remote"
dns_names = ["db.internal.spt.local"]
required = true
```

Clients use `db.internal.spt.local:5432`, the local resolver returns
`127.0.0.1`, the forward delivers the bytes through the tunnel, and the
*remote side* resolves `db.internal.corp` against its own resolver. You
get the convenience of name-based access without the kernel-level
subnet capture.

To actually route lookups through the spt resolver, point your system
resolver at `127.0.0.1:5353` (or apply the managed hosts block with
`spt dns hosts apply`).

## What changes for the operator

### No firewall manipulation

This is the single biggest operational difference. sshuttle inserts
NAT/firewall rules every time it starts and removes them on a clean
exit (and *only* on a clean exit — a SIGKILL leaves rules behind that
break network access). `spt` never touches the kernel firewall by
default. There is a `[firewall]` section that emits *suggested* rules
for review, but it does not apply them autonomously.

### No remote-side helper

sshuttle uploads a Python helper on connect. If your remote bastion
has no Python interpreter (or you're using a hardened, locked-down
account), sshuttle won't work. `spt` uses the standard SSH `direct-tcpip`
channel — anything that runs `sshd` works.

### Privileges

sshuttle requires root locally (or `sudo`) because it touches the
firewall. `spt` runs unprivileged for ordinary local-bind forwards.
Privileges are only required if you bind below port 1024 or want
`spt` to install a system service.

### Log format

sshuttle prints free-form lines. `spt` produces structured key=value
or JSON events with stable field names. See
[Observability](../observability.md).

## What spt does that sshuttle doesn't

- **Reverse forwards** — `type = "remote"` on a forward exposes a
  local service on the remote side.
- **UDP forwards over SSH3.** sshuttle has UDP support over SSH but
  only via a complex tproxy mode; `spt`'s SSH3 backend supports UDP
  via QUIC datagrams natively.
- **Multi-hop chains** without ProxyJump tricks.
- **Endpoint failover.** Multiple endpoints with priority/weight and
  health checks.
- **Service installation** for systemd/launchd/SCM/OpenRC/SysV/Task
  Scheduler.
- **Secret resolution** through keychain/vault/env/file.
- **MCP, Prometheus, OTLP, SNMPv3.**
- **Hot reload** without dropping established forwards.

## What sshuttle does that spt doesn't

This is the honest part. If any of the following describe your
deployment, **stay on sshuttle** (or run both — they don't conflict).

- **Transparent subnet rerouting.** `sshuttle -r host 10.0.0.0/8` makes
  every TCP packet to that subnet — from any process, with no
  per-app config — flow through the tunnel. `spt` cannot do this.
  It cannot install iptables/nftables/pf rules to capture traffic.
  The architectural choice is intentional: `spt` provides
  point-tunnels-by-point and leaves OS-level routing to OS tools.

- **`0/0` "VPN-mode."** Same reason as above. If you want all your
  traffic over an SSH server, sshuttle is the right tool.

- **Capturing arbitrary processes' DNS.** sshuttle's `--dns` rewrites
  outbound UDP/53 at the firewall layer. `spt`'s DNS resolver is
  opt-in — clients have to point at `127.0.0.1:5353` or use the
  managed hosts block.

- **Auto-discovery of remote `/etc/hosts`.** sshuttle's `--auto-hosts`
  scrapes the remote and shares names back. `spt` requires you to
  declare names you care about as `[[dns.records]]`. (For long
  fleets, generate this section from a templating step in your
  config-management system.)

- **No-config fleet usage.** `sshuttle 0/0` works with zero local
  config. `spt` always wants a TOML file.

If you need *both* — transparent VPN-style routing for browser traffic
and supervised, observable port forwards for backend services — run
sshuttle for the former and `spt` for the latter on different ports.

## Side-by-side runtime comparison

| Dimension                       | sshuttle                                       | spt                                                    |
|---------------------------------|------------------------------------------------|--------------------------------------------------------|
| Cold-start                      | SSH handshake + Python helper upload (~1–3s)   | SSH handshake (~1× round-trip)                         |
| Privileges                      | Root locally for firewall                       | Unprivileged for local binds; root only for `:53`/`<1024` |
| Remote requirements             | Python interpreter                              | `sshd` only                                            |
| Resident memory                 | ~25–40 MiB (Python on both ends)               | ~6–10 MiB (Rust binary, no remote agent)                |
| Throughput                      | TCP-over-TCP via Python forwarder              | Raw `direct-tcpip` channel (close to native ssh `-L`) |
| Reconnect on drop               | Process exits; restart by hand or `--daemon`    | Supervised with backoff and instability detection       |
| Failure mode if SIGKILL'd       | Stale firewall rules; possible loss of network | Clean — nothing to roll back                            |

## Step-by-step migration recipe

If you're moving service-by-service away from sshuttle:

1. **Inventory your current `sshuttle` invocation.** What subnets are
   captured? Which actual hostnames/ports are accessed? Which apps
   reach them? You will need a forward per
   `(target_host, target_port)` tuple, not per subnet.

2. **Install `spt`** alongside sshuttle. They don't conflict — `spt`
   binds local ports, sshuttle captures the firewall layer. Belt and
   braces while you migrate.

3. **Translate one service.** Start with a stateless internal HTTP
   service. Add a `[[profiles.forwards]]` block as in the example
   above and bind it to a free local port.

4. **Validate.**

   ```sh
   spt config validate --config /etc/spt/spt.toml --strict
   ```

5. **Run in the foreground.**

   ```sh
   spt tunnel run --foreground --config /etc/spt/spt.toml
   ```

6. **Reconfigure clients.** Point the application from
   `service.internal:443` to either the local bind
   (`127.0.0.1:8443`) or, preferably, a managed DNS name
   (`service.internal.spt.local`). The latter requires no app
   change because the name is the same shape your app already
   expects.

7. **Reduce sshuttle's scope.** Remove the migrated subnet from the
   `sshuttle` argument list. Restart sshuttle.

8. **Repeat.** Walk through the inventory until sshuttle's argument
   list is empty (or you decide to keep it for genuine VPN-mode
   workloads).

9. **Install `spt` as a service** when you're ready to commit:

   ```sh
   sudo spt service install --config /etc/spt/spt.toml --system
   sudo systemctl enable --now spt.service
   ```

10. **Document the boundary** — record which traffic still flows
    through sshuttle (if any) and which is on `spt`. Future you will
    thank present you.

## See also

- [Configuration](../configuration.md)
- [DNS](../dns.md)
- [Forwards](../forwards.md)
- [`examples/dns-split-horizon.toml`](../../examples/dns-split-horizon.toml)
