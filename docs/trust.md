# Trust

`spt` validates remote endpoints against operator-configured trust material
before sending any secret bytes.

## SSH2 host-key

    [profiles.trust]
    mode = "known_hosts"           # known_hosts | pinned
    known_hosts_file = "/etc/spt/known_hosts"
    strict = true                  # fail closed on unknown host
    accept_new = false             # never auto-accept (no TOFU)

## SHA-256 pin

    [profiles.trust]
    mode = "pinned"
    pin_sha256 = ["SHA256:abc123..."]

A profile may set both `known_hosts_file` and `pin_sha256`; the validator
requires at least one source of trust material. Trust failures map to
`TrustFailed` (exit code 6).

## TLS (SSH3, remote-config, HTTPS sinks)

    [profiles.tls]
    ca_file = "/etc/ssl/private/edge-ca.pem"
    spki_pins = ["SHA256:..."]
    allow_self_signed = false
    max_cert_chain_depth = 5

Pin verification is performed *in addition* to PKIX validation by default;
no insecure modes are exposed.

### `PinnedTlsConnector`

Every HTTPS surface in `spt` (remote-config, OIDC device flow, OTLP
exporter, syslog-TLS, HTTPS-JSONL logs, generic HTTP/SMS/MCP-notify
event sinks, SMTP via `tokio-rustls`) routes its TLS handshake through
`spt_trust::PinnedTlsConnector`. This is a single builder that
produces a `Arc<rustls::ClientConfig>` carrying a verifier with the
following policy:

1. **Root store**. `system_roots()` (default — `rustls-native-certs`
   with `webpki-roots` fallback) **or** `ca_file(<path>)` (PEM bundle,
   replaces the system store).
2. **Strict WebPKI verification**. Hostname, validity window,
   signature, and chain construction are all enforced *unless* the
   operator opts into…
3. `allow_self_signed(true)` — the WebPKI verifier is skipped and
   the pin set becomes the *only* trust anchor. The builder will
   refuse to construct a connector with `allow_self_signed = true`
   and an empty pin set.
4. `pin_spki_sha256(TlsPin)` — SHA-256 SPKI pins, matched against
   the **leaf** certificate using constant-time comparison
   (`subtle::ConstantTimeEq`). Pin verification happens *after*
   WebPKI and chain-depth, so a malformed chain never reaches the
   pin check.
5. `max_cert_chain_depth(Some(n))` — reject any chain with `n` or
   more intermediate certificates. Routes through
   [`spt_trust::ChainDepthCap`] so every pinned-TLS surface applies
   identical depth semantics. `None` (the default on the builder)
   bypasses the depth check; sink configs default to
   `ChainDepthCap::default() == Some(5)`.

Builder shape:

```rust
use spt_trust::{PinnedTlsConnector, TlsPin};

let cfg = PinnedTlsConnector::builder()
    .system_roots()                       // or .ca_file("/etc/ca.pem")
    .pin_spki_sha256(TlsPin::from_strings(["SHA256:abc..."])?)
    .allow_self_signed(false)
    .max_cert_chain_depth(Some(5))
    .alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    .build()?;
// `cfg: Arc<rustls::ClientConfig>` — hand to `tokio_rustls::TlsConnector`,
// `reqwest::Client::builder().use_preconfigured_tls(cfg)`, etc.
```

### Pin formats

Pins are accepted in any of these forms, all equivalent:

- 64-char hexadecimal SHA-256 digest
- 44-char standard base64 (with padding)
- 43-char standard base64 (no padding)
- `SHA256:<base64>` (OpenSSH-style prefix)

Pin computation matches `openssl x509 -pubkey -noout | openssl rsa
-pubin -outform DER | openssl dgst -sha256` — i.e. the SHA-256 of the
DER-encoded `SubjectPublicKeyInfo`.

## Pin rotation

Replace the pin in config and reload (`spt config reload`). Both the old
and new pin can be listed simultaneously during a rotation window.

## TOFU (trust-on-first-use)

Service mode does not prompt interactively. Operators can still opt into
non-interactive TOFU by setting `accept_new = true` against a
`known_hosts_file`:

    [profiles.trust]
    mode = "known_hosts"
    known_hosts_file = "/var/lib/spt/known_hosts"
    accept_new = true              # first-seen key is appended to the file
    strict = false

Semantics:

- The first server key for a `(host, port)` not already in
  `known_hosts_file` is appended (POSIX `O_APPEND` / Windows
  `FILE_APPEND_DATA`; atomic for a single line) and the connection is
  allowed. A `WARN`-level audit record is emitted with the SHA-256
  fingerprint and the file path.
- A **mismatch** against an existing entry is *never* TOFU-accepted —
  the connection is refused with `TrustFailed`. `accept_new` controls
  only the absent-entry path.
- `accept_new = true` without `known_hosts_file` is a load-time error:
  TOFU has nowhere to persist the first-seen key.
- `mode = "pinned"` is incompatible with `accept_new = true`; pinned
  mode rejects every unknown key by design.

The historical workflow — `spt key inspect <ssh-host:port>` to capture +
explicitly pin a host key out-of-band — remains the recommended path for
high-trust deployments. TOFU is intended for ephemeral / lab
environments where prompting is impossible but operator review of the
populated `known_hosts_file` is acceptable.

A profile that omits `[profiles.trust]` entirely now fails to load with
a structured diagnostic — the previous silent default accepted any host
key on first connect.
