# Remote Config

`spt` can fetch its config from HTTPS with body-fingerprint pinning.
Strict TLS is enforced; the SHA-256 pin guarantees integrity even when the
TLS chain is otherwise valid.

## Wire format

The endpoint must return a TOML document, status 200, with a stable URL.
ETag-based 304 responses are supported and reduce network load.

## Configuration

    [runtime.remote_config]
    enabled = true
    url = "https://cfg.example.com/spt.toml"
    fingerprint_sha256 = "abc123...64hex"
    cache_file = "/var/lib/spt/remote-config-cache.toml"
    allow_cached_on_failure = true
    poll_interval = "5m"

## Refresh

The supervisor polls at `poll_interval`, sending `If-None-Match` from the
last cached `ETag`. A `200` triggers fingerprint verification; a `304` is
served from cache. Fingerprint mismatches **never** replace the cache and
emit a `remote_config.fingerprint_mismatch` event.

## Cache

Each successful fetch is atomic-written via `spt_state::write_atomic` to
`<state_dir>/remote-config-cache.toml` plus a sidecar
`remote-config-cache.toml.sha256`. On boot, if `allow_cached_on_failure =
true` and the network is unreachable, the cache is reused after passing
fingerprint re-verification.

## CLI

    spt config pull --url https://cfg.example.com/spt.toml \
                    --fingerprint <sha256> --cache

(`config pull` is tracked in M5.)

## Safety

- HTTPS-only; `http://` URLs are rejected.
- Body size capped (`max_size_bytes`).
- Strict rustls + system roots (`rustls-native-certs`); no custom verifier.

## Pinned TLS (t5-e2)

`[runtime.remote_config]` accepts three optional fields that pin the TLS
handshake to the fetch endpoint via
`spt_trust::PinnedTlsConnector::from_config_parts`:

- `pin_spki_sha256 = ["SHA256:<base64>", ...]` — SPKI pin set. Empty by
  default; non-empty enables leaf-cert pinning in addition to the
  existing body-fingerprint pin.
- `allow_self_signed = false` — when `true`, skip WebPKI and trust only
  the pin set. Requires a non-empty `pin_spki_sha256`.
- `max_cert_chain_depth = 5` — defaults to `Some(5)` when omitted.

The body-fingerprint (`fingerprint_sha256`) and TLS SPKI pin
(`pin_spki_sha256`) are independent and complementary: the former
guarantees byte-exact body integrity, the latter prevents any TLS-time
substitution even by an attacker that controls a trusted CA.
