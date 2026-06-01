# SSH3 (experimental, RTH3-specific)

> **About spt's SSH3 backend.** spt implements **RTH3** — Remote-Terminal-
> over-HTTP/3, the design tracked by IETF
> [`draft-michel-remote-terminal-http3-00`](https://datatracker.ietf.org/doc/draft-michel-remote-terminal-http3/)
> and the [francoismichel/ssh3](https://github.com/francoismichel/ssh3)
> reference. RTH3 is **one of several SSH3 designs** under active
> discussion; notably, **SSH Communications Security** (the company founded
> by SSH1's original author and one of the parties behind SSH2
> standardization) has proposed a separate SSH3 successor that is *not*
> RTH3 and is *not* what spt implements.
>
> **The spt SSH3 backend is experimental** and tracks the RTH3 draft only.
> Operators who need a non-experimental tunnel today should use the SSH2
> backend.

SSH3 (in the RTH3 sense) maps SSH semantics onto HTTP/3 (QUIC + TLS 1.3 +
Extended CONNECT). spt's SSH3 backend is compiled into default builds. It is
no longer a build stub: the crate performs QUIC, TLS, HTTP/3 CONNECT
bootstrap, and spt-to-spt forward channel setup.

## Status

Per spec §4.2, SSH3 is compiled into default builds with no feature gate, and
every startup / `validate` / `doctor` / `tunnel run` surfaces an experimental
warning unless the operator opts in. The protocol adapter validates profile
settings, builds a rustls-backed QUIC endpoint, performs HTTP/3 CONNECT, then
exchanges SSH3 settings over a control stream.

## Acknowledging experimental

    [[profiles]]
    name = "edge"
    protocol = "ssh3"
    endpoint = "https://edge.example.com:443/ssh"
    acknowledge_experimental = true   # silences the startup warning

`acknowledge_experimental = false` (or unset) leaves the warning enabled.

## What works

- Public type surface (`Ssh3Protocol`, `Ssh3Config`, `Ssh3Frame`,
  `Ssh3Settings`, `Ssh3Session`).
- Config parsing, validation, TLS root handling, optional CA file, optional
  SPKI pinning, and guarded self-signed support.
- QUIC + TLS 1.3 + HTTP/3 CONNECT bootstrap.
- Bearer and Basic auth headers from the configured auth source.
- spt-to-spt local TCP, remote TCP, UDP datagram, keepalive, and close flows.
- The mandatory experimental warning on every connect attempt unless
  `acknowledge_experimental = true`.

## Current Interop Boundary

The spt-to-spt wire contract is live and covered by integration tests. Direct
bit-level compatibility with the francoismichel/ssh3 reference remains gated
by the upstream SSH3 draft and the pinned `h3` crate: the current dependency
does not expose arbitrary Extended CONNECT `:protocol` tokens, so `spt` also
sends `X-Ssh3-Protocol: ssh3` for peers that support that compatibility path.
OIDC device-flow auth is parsed and validated by the wider auth/config stack,
but the SSH3 transport currently exercises Bearer and Basic headers.

## When not to use SSH3

Until the standards-track spec stabilises and the reference peer is
production-ready, SSH3 is unsuitable for production tunnels. Use SSH2.
