# DNS

`spt` ships an opt-in transparent DNS resolver and a hosts-file manager so
operators can name forwarded services from local clients.

## Modes

    [dns]
    enabled = true
    mode = "transparent_forwarder"   # disabled | transparent_forwarder | synthetic_only | hosts_file
    bind = "127.0.0.1:5353"
    upstream = ["1.1.1.1:53", "9.9.9.9:53"]

- `transparent_forwarder` — managed names answered locally; everything else
  forwarded to upstream.
- `synthetic_only` — only managed names; non-managed are NXDOMAIN.
- `hosts_file` — no listener; record the managed zone into `/etc/hosts`.

## Managed records

    [[dns.records]]
    name = "db.tunnel.local"
    type = "A"
    value = "127.0.0.1"
    ttl = "5m"

`SRV` records can be synthesised from forward declarations via
`spt_dns::srv::synthesize_srv_records`.

## Health-aware answering

Records can carry an `answer_policy` of `Always`, `AnswerWhenListening`, or
`AnswerWhenHealthy`. The resolver consults the supervisor health source so
NXDOMAIN is returned while the underlying forward is down.

## Hosts file

    spt dns hosts render            # preview
    spt dns hosts apply --backup    # write managed block + backup original
    spt dns hosts restore           # roll back to most recent backup

The managed block is bracketed by `# >>> spt-managed >>>` / `# <<< spt-managed <<<`
markers; lines outside that block are preserved verbatim.

## Default bind

The default `127.0.0.1:5353` avoids needing root to bind :53.
For `:53` you must run as root or grant `CAP_NET_BIND_SERVICE`.
