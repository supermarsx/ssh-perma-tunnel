# Trust

`spt` validates every remote endpoint against operator-configured trust material
before transmitting any secret bytes. Trust failures produce exit code 6
(`TrustFailed`). A profile that omits `[profiles.trust]` entirely fails to load
with a structured diagnostic — the previous silent default that accepted any host
key on first connect no longer exists.

Trust verification runs before [authentication](authentication.md). A key
mismatch or pin failure terminates the connection immediately, so no credentials
are ever sent to an unauthenticated peer.

## SSH2 host-key verification

The `[profiles.trust]` table controls how the SSH2 host key presented by the
remote peer is validated.

```toml
[profiles.trust]
mode = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict = true
accept_new = false
```

The `mode` field selects the verification strategy:

| `mode`        | Behaviour                                                          |
|---------------|--------------------------------------------------------------------|
| `known_hosts` | Verify against an OpenSSH-format `known_hosts` file.              |
| `pinned`      | Verify against an explicit SHA-256 SPKI pin set only.             |

A profile may set both `known_hosts_file` and `pin_sha256`; the validator
requires at least one source of trust material to be present.

### known_hosts file format

The file follows the OpenSSH `known_hosts` format. The parser supports:

- Plain hostnames and comma-separated host lists.
- `[host]:port` form for non-default ports.
- Hashed hosts (`|1|<salt>|<hash>` — HMAC-SHA1).
- Wildcard patterns (`*` and `?`).
- `@cert-authority` marker — entry is a CA, not a direct host key.
- `@revoked` marker — any connection presenting this key is unconditionally
  refused with `TrustFailed`, even if the key is otherwise pinned.

The verifier uses an index for exact plaintext-host lookups (O(1) fast path) and
falls back to a full linear scan for hashed and wildcard entries.

### strict mode

When `strict = true` (the recommended setting), an unknown host — one with no
entry in the `known_hosts` file and no matching pin — causes the connection to
fail immediately. Set `strict = false` only in fully ephemeral or lab
environments where trust material is maintained out-of-band.

```toml
[profiles.trust]
mode = "known_hosts"
known_hosts_file = "/etc/spt/known_hosts"
strict = true
accept_new = false
```

## TOFU (trust on first use)

Service mode does not prompt interactively. Non-interactive TOFU is available by
setting `accept_new = true` against a `known_hosts_file`:

```toml
[profiles.trust]
mode = "known_hosts"
known_hosts_file = "/var/lib/spt/known_hosts"
accept_new = true
strict = false
```

Semantics:

- The first server key for a `(host, port)` pair that does not already appear in
  `known_hosts_file` is appended using a POSIX `O_APPEND` / Windows
  `FILE_APPEND_DATA` atomic write (safe for a single appended line) and the
  connection proceeds. A `WARN`-level audit record is emitted with the SHA-256
  fingerprint and the file path.
- A **mismatch** against an existing entry is never TOFU-accepted. The connection
  is refused with `TrustFailed`. `accept_new` controls only the absent-entry
  path.
- `accept_new = true` without a `known_hosts_file` is a load-time error: TOFU
  has nowhere to persist the first-seen key.
- `mode = "pinned"` is incompatible with `accept_new = true`. Pinned mode has no
  concept of first-use; it rejects every key not in the pin set.

The recommended workflow for high-trust deployments is to capture the host key
out-of-band with `spt key inspect <host:port>` before enabling the profile. TOFU
is intended for ephemeral or lab environments where interactive prompting is
impossible but post-hoc review of the populated `known_hosts_file` is
acceptable.

## SHA-256 host-key pins

`pin_sha256` is a list of SHA-256 SPKI fingerprints of acceptable host keys. The
format matches the `SHA256:` prefix used by OpenSSH `ssh-keygen -l`:

```toml
[profiles.trust]
mode = "pinned"
pin_sha256 = [
    "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
]
```

Multiple pins may be listed simultaneously to support key rotation. Comparison
is performed with `subtle::ConstantTimeEq` to avoid timing side-channels.

`mode = "known_hosts"` and `pin_sha256` can be combined: the key must match
both the `known_hosts` file and one of the listed pins. This is the strictest
possible mode and is shown in `examples/zero-trust-https.toml`:

```toml
[profiles.trust]
mode = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict = true
accept_new = false
pin_sha256 = [
    "SHA256:0000000000000000000000000000000000000000000000",
]
```

### Pin rotation

List both the old and new pin simultaneously during a key-rotation window:

```toml
pin_sha256 = [
    "SHA256:<old-pin>",
    "SHA256:<new-pin>",
]
```

Once all peers have updated to the new key, remove the old pin and reload with
`spt config reload`.

## TLS verification

SSH3 connections, the remote-config HTTPS fetcher, OIDC device flow, OTLP
exporters, syslog-TLS sinks, HTTPS-JSONL log sinks, event sinks, and SMTP
transports all use TLS. Every HTTPS surface routes its TLS handshake through
`spt_trust::PinnedTlsConnector`, a single builder that produces a
`Arc<rustls::ClientConfig>` with the following layered policy:

1. **Root store.** System roots via `rustls-native-certs` with a
   `webpki-roots` fallback, or a PEM bundle supplied via `ca_file` which
   replaces the system store entirely.
2. **WebPKI verification.** Hostname, validity window, signature chain, and
   chain construction are all enforced by default.
3. **`allow_self_signed = true`** disables WebPKI verification. When this flag
   is set, the SPKI pin set becomes the only trust anchor. The builder refuses
   to construct a connector with `allow_self_signed = true` and an empty pin
   set — a fully unauthenticated connection is never permitted.
4. **SPKI pins.** SHA-256 SPKI pins matched against the **leaf** certificate
   using `subtle::ConstantTimeEq`. Pin verification happens after WebPKI and
   chain-depth checks, so a malformed chain never reaches the pin comparator.
5. **Chain depth cap.** Connections whose chain has `n` or more intermediate
   certificates between the leaf and the trust anchor are rejected. The
   default cap is 5; set `max_cert_chain_depth` to adjust per surface.

### Per-profile TLS table

SSH3 profiles and remote-config surfaces expose `[profiles.tls]`:

```toml
[profiles.tls]
# Override the server name used for SNI and certificate verification.
server_name = "edge.example.com"
# Replace the system root store with a private CA bundle.
ca_file = "/etc/ssl/private/corp-ca.pem"
# Add leaf-level SPKI pins (matched in addition to standard chain validation).
pin_sha256 = ["SHA256:abc123..."]
# Allow self-signed certificates. Requires a non-empty pin_sha256 set.
allow_self_signed = false
# Maximum number of intermediate certificates in the chain (default: 5).
max_cert_chain_depth = 5
```

### Global sink TLS

`[[logging.remote]]` sinks, `[[events.sinks]]` entries, and `[mcp]` expose the
same `pin_spki_sha256`, `allow_self_signed`, and `max_cert_chain_depth` fields
directly in their own tables. All of them construct their TLS client config
through `PinnedTlsConnector`, so the semantics are identical.

### SPKI pin formats

Pins are accepted in any of the following forms (all equivalent):

- 64-character lowercase hexadecimal SHA-256 digest.
- 44-character standard base64 with padding.
- 43-character standard base64 without padding.
- `SHA256:<base64>` (OpenSSH-style prefix, as produced by
  `ssh-keygen -l` and `openssl x509 -fingerprint -sha256`).

Computing an SPKI pin manually:

```
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64
```

This produces the SHA-256 of the DER-encoded `SubjectPublicKeyInfo`, which is
what `PinnedTlsConnector` matches against.

## Certificate revocation (CRL)

`spt_trust::CrlCache` provides offline CRL lookup for TLS connections. CRL
distribution-point URLs are extracted from each leaf certificate's
`CRLDistributionPoints` extension (RFC 5280 §4.2.1.13). Pre-fetched CRLs are
parsed and cached at startup via
`PinnedTlsConnectorBuilder::prefetch_crls`; the synchronous
`ServerCertVerifier` callback consults the in-memory cache without
performing any network I/O during the handshake.

The policy when a leaf names CRL distribution points but no cached CRL is
present is controlled by `CrlPolicy`:

| Policy     | Behaviour on missing CRL                                        |
|------------|-----------------------------------------------------------------|
| `Disabled` | Default. CRL state is never consulted; existing behaviour.     |
| `Soft`     | Log a warning and accept the chain (high-availability mode).   |
| `Hard`     | Fail closed: missing CRL is treated as revoked-equivalent.     |

Serial-number comparison inside the CRL lookup uses `subtle::ConstantTimeEq`.

## Per-hop trust in jump chains

When a profile defines a ProxyJump / jump chain, each hop's host key is
validated independently against the trust material configured for that hop's
profile or endpoint. There is no mechanism to bypass trust checks on intermediate
hops — every TCP connection that `spt` initiates verifies the presented host key
before completing. See [Forwarding](forwarding.md) for the jump-chain
configuration syntax.

## Split-horizon DNS

Per spec §10.5, split-horizon DNS does not bypass trust. The trust check binds
to the IP address actually connected to, not the DNS name presented. A DNS
override that resolves a hostname to a different IP does not affect which host
key is accepted.

## Trust-related CLI

```
spt key inspect <host:port>
```

Connects to `host:port`, retrieves the server's host key, and prints its
SHA-256 fingerprint and algorithm without authenticating. Use this to capture
a host key for pinning before adding it to `pin_sha256` or `known_hosts`.

```
spt key fingerprint <keyfile>
```

Computes and prints the SHA-256 fingerprint of a local public-key file without
contacting any remote host.

See [CLI Reference](cli-reference.md) for the complete `spt key` sub-command
surface.

## See also

- [Authentication](authentication.md) — auth methods run after trust succeeds.
- [Transports](transports.md) — SSH2 vs. SSH3 transport selection; TLS in SSH3.
- [Security](security.md) — cryptographic policy, algorithm choices, and audit.
- [CLI Reference](cli-reference.md) — full `spt key` and `spt config` surfaces.
