# Obfuscation transports (`spt-obfs`)

`spt` supports four pluggable obfuscation transports between the SSH
client and the upstream server, configured via
`[profiles.transport.obfuscation]`:

| `kind` | Backing crate(s) | Notes |
|---|---|---|
| `obfs4` | hand-rolled (X25519 + HMAC-SHA256 + ChaCha20-Poly1305) | "obfs4 client subset" — see caveats below |
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
* ChaCha20-Poly1305 frame layer with per-frame counter nonce.
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

### Caveats vs reference `shadowsocks-rust`

The session subkey derivation matches SIP022 exactly. However, the
per-frame AAD strings (`b"spt-obfs/ss/len"`, `b"spt-obfs/ss/body"`,
`b"spt-obfs/ss"`) are **spt-specific** and not part of the SIP022 wire
spec. A reference `shadowsocks-rust` server doing standard
length-AEAD framing will reject these frames. **Interop is
spt-server-to-spt-client only** at the framing layer; the KDF and
cipher choices match upstream.
