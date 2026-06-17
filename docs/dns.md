# DNS

`spt` ships an opt-in transparent DNS resolver and a hosts-file manager so
operators can name forwarded services from local clients.

## Modes

    [dns]
    enabled = true
    mode = "transparent_forwarder"   # disabled | transparent_forwarder | synthetic_only | hosts_file
    bind = "127.0.0.1:5353"
    upstream = ["1.1.1.1:53", "9.9.9.9:53"]

The `mode` field is honored at runtime — it selects how unmanaged names are
handled and whether a listener is started at all:

- `transparent_forwarder` (default) — managed names answered locally;
  unmanaged names recurse to `upstream` if configured, otherwise `REFUSED`.
- `synthetic_only` — authoritative-only: only managed names answer, unmanaged
  names are `NXDOMAIN` and are **never** recursed even when upstreams are set.
- `disabled` — no DNS listener is started.
- `hosts_file` — no listener; record the managed zone into `/etc/hosts` via
  the hosts-file manager (see below) instead of serving DNS.

Managed-zone answering and health gating behave identically across the two
listener modes (`transparent_forwarder` / `synthetic_only`); they differ only
in the unmanaged-name path.

## Managed records

    [[dns.records]]
    name = "db.tunnel.local"
    type = "A"
    value = "127.0.0.1"
    ttl = "5m"

## Auto records from forwards

    [dns]
    auto_records = true

When `auto_records = true`, the runtime synthesises records directly from each
forward's `dns_names`: one `A`/`AAAA` per name pointing at the forward's
listen address, plus an `SRV` record for any forward that declares SRV
coordinates. Synthesised names are anchored to the configured `zone` (names
outside the zone are skipped). These records carry the same `answer_policy`
and `forward_id` as static records, so they health-gate identically. This is
now wired end-to-end (no longer a config-only / unused code path).

## Health-aware answering

Records can carry an `answer_policy` of `Always`, `AnswerWhenListening`, or
`AnswerWhenHealthy`. Health gating is **active at runtime**: the resolver
consults a supervisor-backed health source (mapping `forward_id` ⇒
`{listening, healthy}` from the on-disk status snapshot) before building
answers.

- `Always` — always answered.
- `AnswerWhenListening` — answered only while the forward's listener is bound.
- `AnswerWhenHealthy` — answered only while the profile + forward are both
  running with a live session.

When a managed name has no records left after health filtering, the resolver
returns `NXDOMAIN`. (When no supervisor health source is injected — e.g. a
static-zone deployment — the builder defaults apply.)

## Hosts file

    spt dns hosts render            # preview
    spt dns hosts apply --backup    # write managed block + backup original
    spt dns hosts restore           # roll back to most recent backup

The managed block is bracketed by `# >>> spt-managed >>>` / `# <<< spt-managed <<<`
markers; lines outside that block are preserved verbatim.

## Default bind

The default `127.0.0.1:5353` avoids needing root to bind :53.
For `:53` you must run as root or grant `CAP_NET_BIND_SERVICE`.
