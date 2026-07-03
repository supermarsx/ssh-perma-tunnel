# DNS

`spt` ships an opt-in transparent DNS resolver and a hosts-file manager so
operators can name forwarded services from local clients without touching
external DNS infrastructure. Both are disabled by default.

## Modes

The `mode` field controls what the DNS subsystem does at runtime:

| Mode | Behaviour |
|------|-----------|
| `transparent_forwarder` | Managed names answered locally; unmanaged names recursed to configured `upstream` resolvers. If no upstream is configured, unmanaged names return `REFUSED`. |
| `synthetic_only` | Authoritative-only. Only managed names are answered; unmanaged names return `NXDOMAIN` and are never recursed, even when upstreams are set. |
| `hosts_file` | No DNS listener is started. The managed zone is written into `/etc/hosts` (or the platform equivalent) via the hosts-file manager. |
| `disabled` | No listener is started and no hosts file is written. This is the default when `[dns]` is absent. |

Managed-zone answering and health gating behave identically across
`transparent_forwarder` and `synthetic_only`; the two modes differ only in
what happens to names outside the managed zone.

## Configuration

```toml
[dns]
enabled = true
mode = "transparent_forwarder"   # disabled | transparent_forwarder | synthetic_only | hosts_file
bind = "127.0.0.1:5353"          # default; avoids needing root or CAP_NET_BIND_SERVICE
zone = "spt.local"               # default zone for synthesized records
ttl = "30s"                      # default TTL for synthesized records
auto_records = true              # synthesize records from forward dns_names
upstream = ["1.1.1.1:53", "8.8.8.8:53"]
hosts_file_mode = "render_only"  # render_only | apply | restore
```

The default bind address `127.0.0.1:5353` does not require elevated privileges.
To bind on port 53 you must run as root or grant `CAP_NET_BIND_SERVICE` on
Linux.

## Declaring records

Static records are declared in `[[dns.records]]` arrays. Supported types are
`A`, `AAAA`, `SRV`, and `TXT`.

```toml
[[dns.records]]
name  = "smtp.relay.spt.local"
type  = "A"
value = "127.0.0.1"
ttl   = "30s"

[[dns.records]]
name     = "_smtp._tcp.spt.local"
type     = "SRV"
value    = "smtp.relay.spt.local"
priority = 10
weight   = 5
port     = 2525
ttl      = "30s"
```

`priority`, `weight`, and `port` are required for SRV records.

## Auto-records from forwards

When `auto_records = true`, `spt` synthesizes DNS records directly from each
forward's `dns_names` list:

- One `A` or `AAAA` record per name, pointing at the forward's listen address.
- One `SRV` record for any forward that declares SRV coordinates.

Synthesized names must fall inside the configured `zone`; names outside the
zone are skipped. These synthesized records carry the same `answer_policy` and
`forward_id` as static records, so health gating applies identically. The
synthesis is wired end-to-end and is not a config-only placeholder.

## Split-horizon example

From [`examples/dns-split-horizon.toml`](https://github.com/supermarsx/ssh-perma-tunnel/blob/main/examples/dns-split-horizon.toml):

```toml
[dns]
enabled = true
mode = "transparent_forwarder"
bind = "127.0.0.1:5353"
zone = "spt.local"
ttl = "30s"
auto_records = true
upstream = ["1.1.1.1:53", "8.8.8.8:53"]
hosts_file_mode = "render_only"

[[dns.records]]
name = "smtp.relay.spt.local"
type = "A"
value = "127.0.0.1"
ttl = "30s"

[[dns.records]]
name = "_smtp._tcp.spt.local"
type = "SRV"
value = "smtp.relay.spt.local"
priority = 10
weight = 5
port = 2525
ttl = "30s"

[[profiles]]
name = "smtp-relay"
# ...

[[profiles.forwards]]
name = "smtp"
type = "local"
transport = "tcp"
bind = "127.0.0.1:2525"
target = "smtp.internal:25"
dns_names = ["smtp.relay.spt.local"]
sni_name = "smtp.relay.spt.local"
target_resolve = "remote"
required = true
```

Here the forward declares `dns_names = ["smtp.relay.spt.local"]`, which
(with `auto_records = true`) causes `spt` to synthesize an `A` record for that
name pointing at `127.0.0.1:2525`. The static `[[dns.records]]` block adds an
explicit `A` and an `SRV` record. All three end up in the managed zone served
by the resolver.

The `sni_name` field on the forward tells the TLS stack what SNI name to use
when dialling the remote side. This lets TLS-aware services (like mTLS relays
or HTTPS upstreams) identify themselves by a stable hostname that matches what
the DNS resolver advertises locally.

## Health-aware answering

Records can carry an `answer_policy` that gates whether they appear in a
response:

| Policy | Condition |
|--------|-----------|
| `Always` | Always answered, regardless of forward state. |
| `AnswerWhenListening` | Answered only while the forward's local listener is bound. |
| `AnswerWhenHealthy` | Answered only while the profile and forward are both running with a live SSH session. |

The resolver consults a supervisor-backed health source at query time. When a
managed name has no records left after health filtering, the resolver returns
`NXDOMAIN`. When no supervisor health source is injected (for example in a
static-zone deployment), the default builder policy applies.

## Hosts-file management

When `mode = "hosts_file"` (or when using `spt dns hosts` commands directly),
`spt` manages a block inside the platform hosts file. The managed block is
delimited by:

```
# >>> spt-managed >>>
...
# <<< spt-managed <<<
```

Lines outside the block are never modified.

| Command | Effect |
|---------|--------|
| `spt dns hosts render` | Preview the rendered managed block without writing. |
| `spt dns hosts apply --backup` | Write the managed block and back up the previous file. |
| `spt dns hosts restore` | Roll back to the most recent backup. |

## CLI

See [CLI Reference](cli-reference.md) for the full `spt dns` command group,
including `spt dns query` (one-shot query against a running resolver),
`spt dns hosts`, and zone-inspection commands.
