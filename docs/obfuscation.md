# Obfuscation transports (`spt-obfs`)

`spt` supports four pluggable obfuscation transports between the SSH
client and the upstream server, configured via
`[profiles.transport.obfuscation]`:

| `kind` | Backing crate(s) | Notes |
|---|---|---|
| `obfs4` | hand-rolled (X25519 + HMAC-SHA256 + XSalsa20-Poly1305 / NaCl secretbox) | "obfs4 client subset" — see caveats below |
| `meek-http` | `reqwest` (rustls TLS) | HTTPS POST/POST domain-fronting |
| `websocket` | `tokio-tungstenite 0.24` | RFC 6455, advertises `Sec-WebSocket-Protocol: ssh` |
| `shadowsocks` | `aes-gcm` + `chacha20poly1305` + `blake3` | AEAD-2022 with `blake3::derive_key` KDF |

All four ship audit-hook integration: every `connect` call fires the
configured `AuditHook` with the transport name.

## obfs4 client subset

The obfs4 transport is hand-rolled (operator decision: native over a
shell-out to `obfs4proxy`). It implements:

* NTOR-style X25519 handshake mixing both the server's identity public
  key and a fresh ephemeral key.
* HKDF-like KDF over the combined ECDH output, keyed by the obfs4
  PROTOID (`"ntor-curve25519-sha256-1"`) and the server `node_id`.
* **XSalsa20-Poly1305** (NaCl `crypto_secretbox`) frame layer with a
  24-byte per-direction counter nonce starting at 0. The 2-byte length
  prefix is XOR-obfuscated against a SHA-256 keystream so the prefix
  is not visible to a passive observer.
* IAT modes 0 (off), 1 (paranoid, 5 ms inter-frame), 2 (normal, 1 ms).

### Wire-incompatibility caveats vs `obfs4proxy`

* **AUTH tag derivation**: this client folds the AUTH tag into the
  HKDF output (third 32-byte block). The reference obfs4-spec computes
  AUTH as a separately-derived `HMAC-SHA256(NODEID || B || Y || X ||
  PROTOID || "Server", verify_key)`. Our mock-acceptor test mirrors
  the client's KDF; **interoperability with a real obfs4proxy bridge
  is not guaranteed**.
* **IAT distributions**: the heavy probabilistic packet-timing
  distributions from the obfs4-spec are not implemented. Mode 1 = fixed
  5 ms delay, mode 2 = fixed 1 ms delay.

### `t8-FixObfs4` — framing primitive change (operator action: reconnect)

The framing layer was migrated from **ChaCha20-Poly1305 with a 12-byte
nonce + AAD `b"obfs4-frame"`** to **XSalsa20-Poly1305 (NaCl secretbox)
with a 24-byte counter nonce + obfuscated length prefix**. This brings
the primitive in line with obfs4-spec §6 (the spec mandates
`crypto_secretbox`). **This is a wire change**: operators running the
old spt-flavored obfs4 against another spt peer must reconnect once
both ends pick up the fix — frames produced by the old code will fail
authentication on the new code, and vice-versa. **This is not a
security issue**, just compatibility with the reference primitive; the
NTOR handshake itself is unchanged.

For interop with a real obfs4 bridge, run an `obfs4proxy` sidecar and
point `spt` at the local proxy via the plain TCP path.

## meek-http

* TLS SNI = configured `sni` override, or the URL host.
* HTTP `Host:` header = configured `front_host` override, or URL host.
* Session continuity via `X-Session-Id` header (random 64-bit hex).

### Caveats vs reference `meek-server`

* This client issues a "probe" empty POST during `connect` to surface
  401/403/502 errors before the SSH layer commits. Real meek-client
  does not probe; the first POST carries SSH bytes.
* Bidirectional bytes flow inside POST request+response bodies. Real
  meek-server expects each POST body to be either upstream-only
  (request) or downstream-only (response). Our implementation may
  read upstream bytes from a response body that the server intends to
  carry no payload.

These deviations mean the transport works fine against an
spt-controlled meek server but **may not interoperate with the
upstream `meek-server`** without server-side adjustments.

## ssh-over-websocket

* RFC 6455 client via `tokio-tungstenite 0.24`.
* Advertised subprotocol: `ssh`.
* Custom HTTP headers from config are merged into the upgrade request.
* Only binary frames carry SSH bytes — text frames are rejected with
  `InvalidData`.

## ssh-over-shadowsocks

* AEAD-2022 ciphers: `2022-blake3-aes-128-gcm`,
  `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`.
* Legacy AEAD interop: `aes-128-gcm`, `aes-256-gcm`,
  `chacha20-poly1305`.
* AEAD-2022 KDF: `blake3::derive_key("shadowsocks 2022 session
  subkey", key || salt)` per SIP022 §2.2.
* Legacy KDF (pre-2022): HMAC-SHA256 counter mode.

### Wire-format reconciliation with SIP022

The AEAD layer now passes an **empty** additional-authenticated-data
byte string to every `encrypt` / `decrypt` call (length-prefix and
body chunks alike) per SIP022 §3.3.2. Earlier revisions used
spt-specific AAD strings (`b"spt-obfs/ss/len"`, `b"spt-obfs/ss/body"`,
`b"spt-obfs/ss"`) which made it impossible to interoperate with
reference `shadowsocks-rust` `ssserver`; those strings have been
removed.

#### Breaking change for operators

Existing tunnels using the older `spt-obfs`-flavoured Shadowsocks
frames will fail to decrypt against the current build. Operators
must **restart both endpoints** to pick up the SIP022-compliant
framing. The change is **not** a security issue — the old
non-standard AAD did not provide a security property; it merely
prevented interop. Session subkey derivation
(`blake3::derive_key("shadowsocks 2022 session subkey", key || salt)`)
and cipher choices are unchanged.

#### Remaining framing gaps versus full ssserver interop

After the AAD fix the framing layer matches SIP022 for the per-chunk
AEAD shape, but a complete `ssserver` round-trip still requires:

* **Dual-salt handshake** — client sends REQUEST_SALT, server replies
  with a separate RESPONSE_SALT; client→server and server→client
  subkeys are derived from different salts. The current code uses a
  single client-supplied salt for both directions.
* **Fixed-length header chunk** — the first AEAD chunk per direction
  carries a type byte + u64 BE timestamp + variable length / padding
  fields per SIP022 §3.2.
* **Per-direction nonce counters** — separate length / body counters
  per direction (the current AeadStream uses one read counter and one
  write counter, no length/body separation).

These are tracked for a follow-up; full shadowsocks-rust end-to-end interop
is deferred. KDF wire-shape (`ss_2022_kdf_known_vector_matches_reference`)
is byte-exact-correct and runs unconditionally.
