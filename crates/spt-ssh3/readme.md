# spt-ssh3

SSH3 backend for spt, built on QUIC, rustls, and HTTP/3 Extended CONNECT.

SSH3 is still experimental. This crate is compiled by default and is not a
feature-gated stub, but operators must explicitly acknowledge experimental
status with `acknowledge_experimental = true` to silence startup warnings.

## Status

Implemented:

- `Ssh3Protocol::connect()` validates config, emits the experimental warning,
  resolves the peer, builds a QUIC client endpoint, and performs HTTP/3
  CONNECT.
- TLS uses rustls with system roots, optional CA files, optional SPKI pinning,
  and guarded self-signed support.
- Bearer and Basic authentication headers are built from the configured auth
  source.
- `Ssh3Session` supports spt-to-spt local TCP, remote TCP, UDP datagrams,
  keepalive, and close.
- Frame/settings encode/decode helpers are real and covered by tests.

Interop boundary:

- The spt-to-spt channel framing is live.
- Direct bit-level compatibility with the francoismichel/ssh3 reference is
  still experimental. The pinned `h3` crate does not expose arbitrary
  Extended CONNECT `:protocol` tokens, so the transport also sends
  `X-Ssh3-Protocol: ssh3` for peers that implement that compatibility path.
- OIDC device-flow auth is parsed and validated by the auth/config stack, but
  this transport currently exercises Bearer and Basic headers.

## Tests

```text
cargo test -p spt-ssh3
```

The default suite covers config validation, experimental-warning emission,
frame/settings round-trips, QUIC two-endpoint session setup, local/remote TCP,
and UDP datagram forwarding. Reference-server interop remains opt-in through
the ignored `SPT_SSH3_TEST_SERVER` path because the upstream protocol is not a
stable standards-track target.
