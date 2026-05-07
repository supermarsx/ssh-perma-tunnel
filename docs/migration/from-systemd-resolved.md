# Migrating from systemd-resolved split-DNS + SSH tunnel

## Audience

You currently combine [`systemd-resolved`](https://www.freedesktop.org/software/systemd/man/systemd-resolved.service.html)'s
per-link DNS routing with an SSH tunnel to reach internal services. A
typical setup looks like:

- An SSH tunnel (autossh, plain `ssh -N`, or a systemd unit) keeps a
  local listener on `127.0.0.1:5300` (or similar) forwarding to an
  internal DNS server reachable from the bastion.
- `systemd-resolved` is configured to route lookups for one or more
  search domains (`internal.corp`, `vpn.example`) through that
  listener via `resolvectl dns` / `resolvectl domain` or a `.network`
  drop-in.

You want a single tool that owns both the tunnel and the
internal-name resolution.

## What systemd-resolved gives you

systemd-resolved (see upstream `systemd-resolved(8)`) is a system DNS
stub that supports per-link DNS servers, per-link search/route
domains, DNSSEC validation, mDNS, LLMNR, and DNS-over-TLS. The
tunnel-relevant subset:

- **Per-link routing.** Each interface (or virtual link) can have
  its own DNS server list and routing/search domains. Names matching
  a routing domain are sent to that link's servers; the rest go to
  the global DNS.
- **`~corp.internal` route-domain syntax.** Tells resolved "send
  queries for this suffix to *this* server, not the global default."
- **Stub on `127.0.0.53:53`.** Applications using libc resolution
  reach systemd-resolved transparently.

## What spt gives you that's similar

| systemd-resolved concept                          | spt counterpart                                                       |
|---------------------------------------------------|------------------------------------------------------------------------|
| Per-link DNS server                               | `[dns] mode = "transparent_forwarder"` plus managed records           |
| Routing domain (`Domains=~corp.internal`)         | Managed records under a chosen `zone` (e.g. `spt.local`) plus `[[dns.records]]` for known names |
| Stub at `127.0.0.53:53`                           | spt's resolver bind (default `127.0.0.1:5353`; see [DNS](../dns.md))  |
| `resolvectl flush-caches`                         | `spt dns flush` (see CLI Reference)                                   |
| `resolvectl status`                               | `spt tunnel status` and `spt dns status`                              |
| `/etc/hosts` integration                          | `[dns] hosts_file_mode = "render_only" \| "manage"` with managed block markers |
| DNSSEC validation                                 | Forwarded to upstream resolver(s); spt does not validate itself        |
| DNS-over-TLS upstream                             | Not yet — see "What systemd-resolved does" below                       |

## Concrete config translation

### Old setup

```ini
# /etc/systemd/resolved.conf.d/corp.conf
[Resolve]
DNS=127.0.0.1:5300
Domains=~corp.internal ~vpn.example
```

```bash
# Tunnel kept up by autossh (or similar):
autossh -M 0 -N -L 5300:dns.corp.internal:53 tunnel@bastion.example.com
```

Effect: any lookup ending in `corp.internal` or `vpn.example` is
sent to `127.0.0.1:5300`, which the SSH tunnel forwards to the
internal DNS server.

### New setup (spt-managed)

Two patterns work, depending on whether you want an active local
DNS resolver or a static hosts-file render. The transparent forwarder
mode mirrors the old setup most closely.

```toml
version = 1

[dns]
enabled = true
mode = "transparent_forwarder"
bind = "127.0.0.1:5353"
zone = "spt.local"
ttl = "30s"
upstream = ["1.1.1.1:53", "9.9.9.9:53"]   # for non-managed names
hosts_file_mode = "render_only"            # set to "manage" to actually write /etc/hosts

# A handful of synthetic A records for forwarded services.
[[dns.records]]
name = "db.spt.local"
type = "A"
value = "127.0.0.1"
ttl = "30s"

[[dns.records]]
name = "metrics.spt.local"
type = "A"
value = "127.0.0.1"
ttl = "30s"

[[profiles]]
name = "corp"
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
target = "db.corp.internal:5432"   # resolved on the bastion
target_resolve = "remote"
dns_names = ["db.spt.local"]
required = true

[[profiles.forwards]]
name = "metrics"
type = "local"
transport = "tcp"
bind = "127.0.0.1:9000"
target = "metrics.corp.internal:9000"
target_resolve = "remote"
dns_names = ["metrics.spt.local"]
required = true
```

Apps now reach `db.spt.local:5432` instead of
`db.corp.internal:5432`. Behind that name change:

- `spt` answers `db.spt.local` locally (fast, no upstream round-trip).
- The forward delivers bytes through the SSH tunnel.
- The bastion resolves the *real* upstream (`db.corp.internal`).

### Keeping the original names

If you don't want to rename anything, you have two options:

1. **Hosts-file integration.** Set
   `[dns] hosts_file_mode = "manage"` and declare records using
   the corp names directly:

   ```toml
   [[dns.records]]
   name = "db.corp.internal"
   type = "A"
   value = "127.0.0.1"
   ```

   `spt dns hosts apply --backup` writes a managed block (bracketed
   by `# >>> spt-managed >>>` / `# <<< spt-managed <<<`) into
   `/etc/hosts`. The names resolve to `127.0.0.1`, where the matching
   forward is bound. (Requires root to write `/etc/hosts`.)

2. **Point systemd-resolved at spt's listener instead.** Keep
   resolved as your stub but route corp names to
   `127.0.0.1:5353`:

   ```ini
   [Resolve]
   DNS=127.0.0.1:5353
   Domains=~corp.internal
   ```

   Then declare records using corp names so spt answers them.

## What changes for the operator

### One supervisor instead of two layers

Before, you had two moving parts:

- The SSH tunnel (kept alive by autossh / a systemd unit).
- systemd-resolved configuration drift (`resolvectl` calls,
  `.network` units, `nss-resolve` shimmery).

After, `spt` owns both. The TOML is the single source of truth; a
SIGHUP applies changes to forwards *and* records together.

### Privileges

- Binding `:53` requires root or `CAP_NET_BIND_SERVICE`. The
  default `127.0.0.1:5353` does not. systemd-resolved's stub at
  `:53` is a privileged daemon; `spt`'s default is unprivileged.
- Writing `/etc/hosts` requires root (use `sudo spt dns hosts apply`).

### Cohabitation

`spt`'s DNS resolver and systemd-resolved can run side-by-side as
long as they bind different ports. A common pattern during migration:

- systemd-resolved keeps `127.0.0.53:53` as the system stub.
- `spt` listens on `127.0.0.1:5353`.
- systemd-resolved's `Domains=~corp.internal` routes the corp
  suffix to `127.0.0.1:5353`.

This lets you migrate without touching the system stub. Once
confident, you can simplify by reducing systemd-resolved to its
default config.

## What spt does that systemd-resolved doesn't

- **Owns the tunnel.** Resolved knows nothing about whether the
  upstream it routes to is reachable. `spt` ties record health to
  the underlying forward — `answer_policy = "AnswerWhenHealthy"`
  returns NXDOMAIN while the tunnel is down, so clients fail fast
  instead of timing out.
- **Synthetic SRV.** Generate `_service._tcp` records from forward
  declarations (`spt_dns::srv::synthesize_srv_records`).
- **Managed hosts-file block** with explicit markers, backups,
  and `spt dns hosts restore`.
- **Per-record TTLs** in TOML, with hot reload.
- **Structured observability** for DNS — query metrics, event
  emission on resolution failures.

## What systemd-resolved does that spt doesn't

- **DNS-over-TLS / DNS-over-HTTPS upstream.** systemd-resolved can
  speak DoT to upstream resolvers. `spt`'s upstream is plain UDP/TCP
  DNS. (Run resolved as the upstream if you need DoT; point
  `[dns].upstream` at `127.0.0.53:53`.)
- **DNSSEC validation.** Resolved validates RRSIGs locally. `spt`
  passes through whatever the upstream returns; trust the upstream
  or chain through a validator.
- **mDNS / LLMNR.** Not implemented in `spt`.
- **Per-link configuration semantics.** Resolved binds DNS config
  to NetworkManager / systemd-networkd link state. `spt`'s
  resolver is global to the host process; link-up / link-down
  doesn't reconfigure it. (Use systemd unit ordering to start
  `spt.service` after the relevant network targets.)
- **`nss-resolve` integration.** The `nss-resolve` NSS module
  knows how to talk to resolved over D-Bus. `spt` is a plain
  DNS server — clients reach it via libc's normal stub-resolver
  path (`/etc/resolv.conf` or systemd-resolved's routing rules).
- **`resolvectl query` D-Bus introspection.** Use
  `dig @127.0.0.1 -p 5353 name` instead.

When in doubt about a systemd-resolved feature not covered here,
**see upstream `systemd-resolved(8)` and `resolved.conf(5)`** rather
than guessing.

## Side-by-side runtime comparison

| Dimension                              | resolved + autossh                         | spt                                                    |
|----------------------------------------|--------------------------------------------|--------------------------------------------------------|
| Processes to keep alive                | 2 (resolved + tunnel)                      | 1 (`spt`)                                              |
| Configuration locations                | `/etc/systemd/resolved.conf.d/`, autossh wrapper | `spt.toml` only                                  |
| Tunnel down → DNS behavior             | Lookups timeout against the dead tunnel    | NXDOMAIN immediately if `answer_policy = "AnswerWhenHealthy"` |
| Hot-reload DNS records                 | `systemctl reload systemd-resolved` (limited) | `systemctl reload spt` applies records + forwards atomically |
| Privileges                             | Resolved runs as `systemd-resolve`; tunnel often root | Unprivileged for `:5353`; root only for `:53` or `/etc/hosts` |

## Step-by-step migration recipe

1. **Inventory current routing.** Run `resolvectl status` and note
   the routing domains and upstream DNS servers in use. Identify
   which ones depend on the tunneled internal DNS server.

2. **Install `spt`** and add a `[dns]` section with
   `mode = "transparent_forwarder"`, `bind = "127.0.0.1:5353"`,
   and your existing global upstreams.

3. **Add records and forwards.** For each internal name your
   apps actually reach, add a `[[dns.records]]` and a matching
   `[[profiles.forwards]]` (see template above). Start with three
   or four; you don't need to migrate every name on day one.

4. **Validate.**

   ```sh
   spt config validate --config /etc/spt/spt.toml --strict
   ```

5. **Run in the foreground and test.**

   ```sh
   sudo spt tunnel run --foreground --config /etc/spt/spt.toml
   # In another shell:
   dig @127.0.0.1 -p 5353 db.spt.local
   curl http://127.0.0.1:5432/      # should hit the internal DB via the tunnel
   ```

6. **Wire systemd-resolved to spt.** As a transitional step:

   ```ini
   # /etc/systemd/resolved.conf.d/spt.conf
   [Resolve]
   DNS=127.0.0.1:5353
   Domains=~spt.local
   ```

   `sudo systemctl restart systemd-resolved`. Now apps that use
   the system stub resolve `*.spt.local` via spt.

7. **Cut over apps one at a time.** Update connection strings
   from `db.corp.internal` to `db.spt.local` (or apply the
   managed hosts block to keep the old names).

8. **Install as a service.**

   ```sh
   sudo spt service install --config /etc/spt/spt.toml --system
   sudo systemctl enable --now spt.service
   ```

9. **Retire the old wrappers.** Disable the autossh unit and the
   resolved drop-in that pointed at `127.0.0.1:5300`. Confirm
   `resolvectl status` shows the new spt-targeted routing only.

10. **Track health.** `spt_dns_queries_total` and
    `spt_profile_state` Prometheus metrics make this trivial to
    alert on.

## See also

- [DNS](../dns.md) — full resolver reference
- [`examples/dns-split-horizon.toml`](../../examples/dns-split-horizon.toml)
- [Configuration](../configuration.md)
- [Forwards](../forwards.md)
