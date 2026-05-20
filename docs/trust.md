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

## TOFU

`spt` does **not** offer trust-on-first-use prompts in service mode. Use
`spt key inspect <ssh-host:port>` (M3) to capture and pin a host key
explicitly.
