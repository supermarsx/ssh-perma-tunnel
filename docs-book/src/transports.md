# Transports

`spt` ships two protocol backends — SSH2 and SSH3 — and four pluggable obfuscation layers. Each backend implements the `TunnelProtocol` trait defined in `spt-protocol`; the supervisor selects the backend from `protocol = "ssh2"` or `protocol = "ssh3"` in the profile configuration. Obfuscation is layered beneath SSH using `[profiles.transport.obfuscation]` and is independent of which backend is active.

## SSH2 backend

The SSH2 backend is the stable, production-grade transport. It is built on `russh`, a pure-Rust SSH implementation. The legacy libssh2 C-library path was removed in t7-Phase0; russh is the only SSH2 backend.

### How it works

When a profile with `protocol = "ssh2"` is activated, the supervisor calls `Ssh2Protocol::connect(endpoint, auth)`. The backend:

1. Opens a TCP connection to the configured host and port, routing it through any configured obfuscation transport if `[profiles.transport.obfuscation]` is present.
2. Performs the SSH handshake and key exchange, enforcing the algorithm allow-lists from `[profiles.crypto]` (see [Crypto policy](#crypto-policy) below and the full field reference in [configuration-reference.md](configuration-reference.md)).
3. Authenticates using the configured method(s) in the order specified in `[profiles.auth]`. Supported methods: `public_key`, `agent`, `password`, `keyboard_interactive`, OpenSSH certificate (`certificate_file`), `gssapi` (Kerberos, requires `allow_gssapi` in `[capabilities]`), and `sspi` (Windows Negotiate, requires `allow_sspi`). See [authentication.md](authentication.md) for details.
4. Returns an `Ssh2Session` handle. The supervisor opens per-forward channels (`direct-tcpip`, `tcpip-forward`, `direct-streamlocal@openssh.com`, `streamlocal-forward@openssh.com`) through this session.

Host-key verification is performed by `spt-trust` via the `[profiles.trust]` table — either `known_hosts` file lookup or SHA-256 SPKI pinning. See [trust.md](trust.md).

### Crypto policy

Algorithm selection is controlled by `[profiles.crypto]`:

```toml
[profiles.crypto]
policy              = "modern"      # modern | interop | legacy
allow_deprecated    = false         # permit algorithms not in the policy set
warn_on_deprecated  = true          # log a warning when deprecated alg is negotiated
ciphers             = []            # explicit cipher allow-list (empty = policy default)
kex_algorithms      = []            # explicit KEX allow-list
macs                = []            # explicit MAC allow-list
host_key_algorithms = []            # explicit host-key type allow-list
compression         = []            # e.g. ["none", "zlib@openssh.com"]
```

`policy = "modern"` (default) admits only current strong algorithms. `"interop"` extends that set with algorithms needed for compatibility with older server software. `"legacy"` permits all algorithms russh can negotiate, including ones that carry known weaknesses; it is not recommended for production and emits deprecation warnings. Explicit allow-lists in `ciphers`, `kex_algorithms`, etc. override the policy defaults entirely for that category.

#### Post-quantum key exchange (on by default)

Every preset offers the hybrid post-quantum KEX **`mlkem768x25519-sha256` first**, followed by the classical algorithms (`curve25519-sha256`, …) as fallback. This means an SSH2 profile negotiates post-quantum key exchange **by default** — no configuration is required. `mlkem768x25519-sha256` is the one post-quantum KEX the underlying `russh` transport implements end-to-end (interoperable with OpenSSH ≥ 9.0). Because it is a hybrid (ML-KEM-768 combined with X25519), it is never weaker than classical X25519, and a peer that does not speak ML-KEM simply negotiates `curve25519-sha256` instead.

Three `[capabilities]` knobs refine this default:

| Capability | Effect |
| --- | --- |
| `allow_post_quantum_kex = false` (or `allow_ml_kem = false`) | Strips post-quantum KEX from the offer, leaving only the classical fallback. |
| `require_post_quantum_kex = true` | Restricts the offer to the supported post-quantum KEX only (drops classical), so the handshake fails closed rather than silently negotiating classical key exchange. Requires `allow_post_quantum_kex = true`. |
| *(none set)* | Post-quantum offered first with classical fallback (the default). |

Only `mlkem768x25519-sha256` is negotiable; unsupported post-quantum names such as `sntrup761x25519-sha512` are rejected at config load with guidance toward the supported algorithm.

The full field-by-field reference is in [configuration-reference.md](configuration-reference.md).

### Connection tuning

Socket and channel parameters live in `[profiles.connection]`:

```toml
[profiles.connection]
connect_timeout       = "15s"
auth_timeout          = "30s"
handshake_timeout     = "20s"
channel_open_timeout  = "10s"
channel_window_size   = "2MiB"
channel_max_packet_size = "64KiB"
tcp_nodelay           = true
socket_keepalive      = true
keepalive_idle        = "60s"
keepalive_interval    = "10s"
keepalive_retries     = 5
```

### When to use SSH2

SSH2 is the recommended backend for all production deployments. It is stable, interoperates with OpenSSH and any RFC 4253-compliant server, and supports the full forward and authentication surface described in this book.

### Minimal example

```toml
[[profiles]]
name     = "db-forward"
enabled  = true
protocol = "ssh2"
host     = "bastion.example.com"
port     = 22
user     = "relay"

[profiles.auth]
method        = "public_key"
identity_file = "~/.ssh/id_ed25519"
passphrase    = "secret://ssh/db-relay/passphrase"

[profiles.trust]
mode             = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict           = true

[profiles.crypto]
policy = "modern"

[[profiles.forwards]]
name      = "postgres"
type      = "local"
transport = "tcp"
bind      = "127.0.0.1:5432"
target    = "db.internal:5432"
```

See [authentication.md](authentication.md), [trust.md](trust.md), and [forwarding.md](forwarding.md) for the full configuration surface.

---

## SSH3 backend (experimental)

> **Design disclaimer.** spt implements **RTH3** — Remote-Terminal-over-HTTP/3, the design tracked by IETF `draft-michel-remote-terminal-http3-00` and the [francoismichel/ssh3](https://github.com/francoismichel/ssh3) reference implementation. RTH3 is one of several proposals sometimes called "SSH3"; notably, **SSH Communications Security** (the company co-founded by SSH1's original author and one of the parties behind SSH2 standardisation) has proposed a separate SSH3 successor that is *not* RTH3 and is *not* what spt implements. Do not conflate the two.
>
> **The SSH3 backend is experimental.** Every connect attempt prints a prominent warning unless the operator opts in with `acknowledge_experimental = true`. Operators who need a non-experimental tunnel today should use the SSH2 backend.

### How it works

SSH3 maps SSH semantics onto QUIC + TLS 1.3 + HTTP/3 Extended CONNECT:

1. The client opens a QUIC connection to the configured HTTPS endpoint using a rustls TLS config (system roots, optional CA file, optional SHA-256 SPKI pin, optional self-signed support).
2. An HTTP/3 Extended CONNECT request is sent with `:protocol = ssh3` (and `X-Ssh3-Protocol: ssh3` for peer compatibility). The authorization header carries a Bearer or Basic credential derived from `[profiles.auth]`.
3. A control stream is negotiated. Subsequent bidirectional QUIC streams carry per-forward channel data (local TCP, remote TCP) on the spt-to-spt wire contract. QUIC datagrams carry UDP payloads when `enable_datagrams = true`.

The spt-to-spt wire contract is live and covered by integration tests. Bit-level compatibility with the `francoismichel/ssh3` reference server framing is **not claimed** — direct interop is gated on the upstream draft stabilising and on QUIC Extended CONNECT extension support in the `h3` crate used.

### spt-to-spt mode: `spt ssh3-serve`

The `server` crate feature (also implied by the `testing` feature) compiles in the `spt ssh3-serve` subcommand. This starts an RTH3 responder that the SSH3 client backend can connect to directly, enabling spt-to-spt tunnels without an OpenSSH server. The server accepts connections, authenticates via the configured ACL, and dispatches forward channel requests using the same frame types as the client.

See [cli-reference.md](cli-reference.md) for the `spt ssh3-serve` option reference.

### UDP capability

When `[profiles.ssh3] enable_datagrams = true`, UDP forwards map datagram payloads directly onto QUIC datagrams rather than framing them over a stream. The per-forward `[[profiles.forwards]] max_datagram_size` caps datagram admission: a datagram larger than the configured value is dropped and counted in the `udp_oversize_drops` counter. When unset the flow uses a conservative transport default (the maximum well-formed UDP payload, 65535 bytes), so a normally-sized datagram is never rejected. This is an application-level admission gate independent of QUIC's own datagram-frame-size limit — raising it above what the QUIC peer negotiated does not make oversized datagrams sendable. See [forwarding.md](forwarding.md#udp-forwarding) for the forward configuration.

### Profile configuration

SSH3 profiles use `protocol = "ssh3"` and set `endpoint` to an HTTPS URL. The experimental acknowledgement field is required to silence the startup warning:

```toml
[[profiles]]
name                    = "edge"
enabled                 = true
protocol                = "ssh3"
endpoint                = "https://edge.example.com:443/ssh3"
user                    = "netops"
acknowledge_experimental = true
connect_timeout         = "10s"

[profiles.auth]
method = "bearer_token"
token  = "secret://ssh3/edge/token"

[profiles.tls]
server_name      = "edge.example.com"
system_roots     = true
allow_self_signed = false
```

The `[profiles.tls]` table controls TLS for the QUIC connection. Fields:

| Field | Description |
|---|---|
| `server_name` | SNI / verification name override. |
| `system_roots` | Use the OS root certificate store. |
| `ca_file` | Path to a PEM CA bundle. |
| `pin_sha256` | One or more SHA-256 SPKI pins. |
| `allow_self_signed` | Accept self-signed certs (requires a pin or `ca_file`). |
| `max_cert_chain_depth` | Maximum intermediate chain depth (default 5). |

#### Post-quantum key exchange (on by default)

Like the SSH2 backend, **SSH3 negotiates a hybrid post-quantum key exchange by default**. The QUIC/TLS-1.3 handshake offers the hybrid group **`X25519MLKEM768` first**, with classical X25519 / P-256 / P-384 as fallback. `X25519MLKEM768` is the TLS-1.3 analogue of SSH2's `mlkem768x25519-sha256` (draft-ietf-tls-ecdhe-mlkem / RFC 9370): ML-KEM-768 combined with X25519. Because it is hybrid it is never weaker than classical X25519, and a peer that does not speak ML-KEM simply negotiates classical X25519 instead. For `spt`-to-`spt` SSH3 the responder (`spt ssh3-serve`) always offers the group, so both ends negotiate post-quantum with no configuration required.

Implementation detail: only the SSH3 QUIC configuration uses the `aws-lc-rs` crypto provider that supplies `X25519MLKEM768`; the process-global rustls provider (used by the status API, syslog TLS, and remote-config HTTP client) is unchanged.

The operator off-switch is `post_quantum` in `[profiles.ssh3]`:

| Setting | Effect |
| --- | --- |
| *(unset)* / `post_quantum = true` | Hybrid `X25519MLKEM768` offered first, classical fallback (the default). |
| `post_quantum = false` | Classical-only handshake (no post-quantum group), reproducing the pre-PQ behaviour byte-for-byte. `validate` emits an informational `ssh3_post_quantum_disabled` warning to flag the downgrade. |

SSH3-specific tuning lives in `[profiles.ssh3]`:

| Field | Type | Description |
|---|---|---|
| `draft` | string | Reference draft identifier (informational). |
| `protocol_token` | string | HTTP/3 Extended CONNECT `:protocol` token. |
| `enable_datagrams` | bool | Enable QUIC datagram support for UDP forwards. |
| `idle_timeout` | duration | QUIC connection idle timeout. |
| `keepalive` | duration | QUIC keepalive probe interval. |
| `max_streams` | u32 | Maximum concurrent bidirectional QUIC streams. |
| `post_quantum` | bool | Offer the hybrid post-quantum group `X25519MLKEM768` on the QUIC handshake (default `true`; set `false` to force classical TLS key exchange). |

Auth for SSH3 profiles supports `bearer_token` (sets `Authorization: Bearer`) and `password` (sets `Authorization: Basic`). OIDC device-flow fields (`oidc_issuer`, `oidc_client_id`) are parsed and validated by the auth stack but the SSH3 transport currently exercises only Bearer and Basic headers. See [authentication.md](authentication.md).

### Full example

The `examples/ssh3.toml` file in the repository shows a complete SSH3 profile with a UDP DNS forward over QUIC datagrams:

```toml
version = 1

[[profiles]]
name                    = "ssh3-dns"
enabled                 = true
protocol                = "ssh3"
acknowledge_experimental = true
endpoint                = "https://edge.example.com:443/ssh3?user={username}"
user                    = "netops"
connect_timeout         = "10s"

[profiles.auth]
method = "bearer_token"
token  = "secret://ssh3/edge/token"

[profiles.tls]
server_name      = "edge.example.com"
system_roots     = true
allow_self_signed = false

[profiles.ssh3]
draft             = "michel-remote-terminal-http3-00"
protocol_token    = "remote-terminal"
enable_datagrams  = true

[[profiles.forwards]]
name                = "dns"
type                = "local"
transport           = "udp"
bind                = "127.0.0.1:1053"
target              = "dns.internal:53"
target_resolve      = "remote"
required            = true
udp_idle_timeout    = "30s"
max_datagram_size   = 1200
max_packets_per_second = 5000
```

### When not to use SSH3

SSH3 is unsuitable for production tunnels until the standards-track spec stabilises and a production-grade server peer exists. The spt-to-spt wire contract is tested, but bit-compat with the reference server is not guaranteed. Use SSH2 for production.

---

## Obfuscation transports

spt supports four pluggable obfuscation transports, configured via `[profiles.transport.obfuscation]`. When this sub-table is present, the SSH2 backend dials through the obfuscated `ConnectStream` instead of a plain TCP socket. Obfuscation is wired into the runtime; an absent `[profiles.transport.obfuscation]` block means a plain TCP connection.

> **Interop scope.** All four transports are validated against spt-controlled acceptors and mock acceptors that mirror spt's own framing. None has been validated against the reference server implementations (`obfs4proxy`, `meek-server`, `shadowsocks-rust ssserver`). Treat all four as **spt-to-spt obfuscation** unless stated otherwise for individual transports.

Every transport emits an audit event through the configured audit hook on every connect attempt.

### obfs4

`kind = "obfs4"` implements an obfs4-inspired obfuscation layer using a hand-rolled NTOR-style handshake and a NaCl secretbox frame layer.

Cryptographic construction:
- **Handshake:** X25519 ECDH mixing the server's static identity key (`public_key`) with a fresh ephemeral key pair per connection. Key material is derived via HKDF using `"ntor-curve25519-sha256-1"` as the PROTOID and `node_id` as the salt.
- **Frame layer:** XSalsa20-Poly1305 (NaCl `crypto_secretbox`) with a 24-byte per-direction counter nonce starting at zero. The 2-byte length prefix is XOR-obfuscated against a SHA-256 keystream to prevent passive observers from identifying frame boundaries.
- **IAT modes:** 0 = off, 1 = 5 ms inter-frame delay, 2 = 1 ms inter-frame delay.

**Wire-incompatibility with obfs4proxy:** This transport is **not** compatible with Tor obfs4 bridges. The NTOR handshake deviates from the obfs4 specification: it folds the bridge identity key into the HKDF salt rather than computing two ECDH outputs and concatenating them per obfs4-spec §3. The AUTH tag derivation also differs from the spec. Do not advertise this transport as a Tor pluggable transport or attempt to use it with a real `obfs4proxy` bridge without a server-side match.

**Threat model:** Passive traffic-shape analysis; DPI signatures. Protects against observers who look for SSH banner patterns or TLS fingerprints in the TCP stream.

```toml
[profiles.transport.obfuscation]
kind       = "obfs4"
node_id    = "a1b2c3d4e5f6..."   # hex-encoded 20-byte server node ID
public_key = "0102030405..."      # hex-encoded 32-byte server identity public key
iat_mode   = 0                    # 0 = off, 1 = paranoid (5 ms), 2 = normal (1 ms)
```

### meek-http

`kind = "meek-http"` implements domain-fronting via HTTPS POST tunnelling. SSH bytes flow inside HTTP POST request and response bodies; the visible TLS SNI and HTTP `Host:` header can be set independently to exploit CDN edge infrastructure that ignores Host verification.

Transport behaviour:
- TLS SNI is set to `sni` if provided, otherwise the URL host.
- The HTTP `Host:` header is set to `front_host` if provided, otherwise the URL host.
- Session continuity is maintained via an `X-Session-Id` header (random 64-bit hex value, stable per connection).
- A probe POST is sent during `connect` to surface 401/403/502 errors before the SSH layer commits.

**Caveats vs reference `meek-server`:** The probe POST and the bidirectional-body framing both differ from the reference meek protocol. The transport works against spt-controlled meek acceptors but may not interoperate with upstream `meek-server` without server-side adjustment.

**Threat model:** Censorship evasion where the fronting CDN domain is allowed but the true destination is blocked. The SSH session is invisible to DPI; only HTTPS traffic to a fronting domain is observed.

```toml
[profiles.transport.obfuscation]
kind       = "meek-http"
url        = "https://cdn.example.com/path"   # fronting HTTPS URL
front_host = "allowed-cdn.example.com"        # optional Host: override
sni        = "allowed-cdn.example.com"        # optional SNI override
```

### websocket

`kind = "websocket"` upgrades the TCP connection to an RFC 6455 WebSocket, advertising `Sec-WebSocket-Protocol: ssh`. SSH bytes are carried in binary WebSocket frames. Only binary frames are accepted; text frames are rejected with `InvalidData`.

Implementation: `tokio-tungstenite 0.24`.

**Threat model:** Port 80/443 traversal in environments that permit WebSocket traffic but block raw SSH. The connection appears as a WebSocket upgrade to an observer; the `ssh` subprotocol is declared in the upgrade but is not itself secret.

```toml
[profiles.transport.obfuscation]
kind = "websocket"
url  = "wss://proxy.example.com/tunnel"
headers = [
    ["X-Auth-Token", "secret://websocket/token"],
]
```

`headers` is a list of `[name, value]` pairs merged into the WebSocket upgrade request. Useful for authentication or routing headers required by an intermediate proxy.

### shadowsocks

`kind = "shadowsocks"` wraps the SSH stream in Shadowsocks AEAD-2022 framing.

Supported ciphers (`method` field):

| Method | Standard |
|---|---|
| `2022-blake3-aes-128-gcm` | AEAD-2022 (SIP022) |
| `2022-blake3-aes-256-gcm` | AEAD-2022 (SIP022) |
| `2022-blake3-chacha20-poly1305` | AEAD-2022 (SIP022) |
| `aes-128-gcm` | Legacy AEAD |
| `aes-256-gcm` | Legacy AEAD |
| `chacha20-poly1305` | Legacy AEAD |

AEAD-2022 key derivation: `blake3::derive_key("shadowsocks 2022 session subkey", key || salt)` per SIP022 §2.2. The per-direction subkeys are derived separately (`c2s` / `s2c` HMAC-SHA256 labels) so the two traffic directions never share a `(key, nonce)` pair.

The `password` field must be a `secret://` reference resolved at runtime by the configured secrets backend. See [secrets.md](secrets.md).

**Remaining gaps vs full `ssserver` interop:** The AEAD chunk shape now matches SIP022 (empty AAD per §3.3.2). Full dual-salt handshake and SIP022 fixed-length header chunk support are deferred. The transport works against spt-controlled Shadowsocks acceptors.

**Threat model:** Encrypted, traffic-obfuscated proxy that resists DPI-based blocking by lacking identifiable protocol signatures. Suitable for environments where other obfuscation layers are blocked.

```toml
[profiles.transport.obfuscation]
kind     = "shadowsocks"
method   = "2022-blake3-aes-256-gcm"
password = "secret://obfs/shadowsocks/psk"
```

---

## Selecting and combining transports

A complete profile selects a protocol backend and, optionally, an obfuscation transport:

```toml
[[profiles]]
name     = "hardened-forward"
protocol = "ssh2"
host     = "edge.example.com"
port     = 443
user     = "ops"

[profiles.auth]
method        = "public_key"
identity_file = "~/.ssh/id_ed25519"

[profiles.trust]
mode       = "pinned"
pin_sha256 = ["SHA256:AbCdEf..."]

[profiles.transport.obfuscation]
kind = "websocket"
url  = "wss://edge.example.com/tunnel"
```

Obfuscation sits beneath SSH: the SSH handshake, auth, and all channel data pass through the obfuscated stream. The outer layer (meek HTTPS, WebSocket, Shadowsocks AEAD, obfs4 secretbox) is what a network observer sees.

For related topics see [authentication.md](authentication.md), [trust.md](trust.md), [secrets.md](secrets.md), and [configuration-reference.md](configuration-reference.md). For the `spt ssh3-serve` CLI surface see [cli-reference.md](cli-reference.md).
