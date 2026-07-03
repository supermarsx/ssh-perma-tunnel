# Secrets

`spt` never stores credentials in plaintext configuration files. Every field
that carries sensitive material (passwords, passphrases, tokens, OTP seeds,
SNMP secrets) accepts a secret reference that is resolved at runtime through a
pluggable backend chain. Inline plaintext values are accepted by the parser but
are rejected in strict mode and surfaced as validation warnings outside it.

## Reference syntax

Three reference forms are accepted wherever a secret value is expected:

| Form                | Resolved by                                                       |
|---------------------|-------------------------------------------------------------------|
| `secret://ns/name`  | `KeychainBackend` then `VaultBackend` (or configured backend).   |
| `env:NAME`          | `EnvBackend` — reads `SPT_SECRET_<NS_UPPER>__<NAME_UPPER>`.      |
| `file:///abs/path`  | `FileBackend` — reads the file at the given absolute path.       |

The `secret://` form is the canonical choice for production. Both namespace and
name are restricted to ASCII alphanumerics plus `_`, `-`, and `.`. Empty
segments are rejected with a typed `ReferenceError`.

The `env:` form uses the variable name exactly as written, with no namespace
prefix. For a `secret://ssh/edge-key` reference using the env backend, the
equivalent is `env:SPT_SECRET_SSH__EDGE_KEY` (namespace and name uppercased,
hyphens and dots converted to underscores).

The `file:///` form requires an absolute path. On Unix the file must be readable
by the process owner only (`0o400` or `0o600`); mode violations are surfaced as a
backend error, not silently ignored. On Windows, ACLs are checked on a
best-effort basis.

## Backend priority and resolver order

The default resolver tries backends in this order (spec §14.6):

1. **Keychain** — OS keychain (macOS Keychain Services, Windows Credential
   Manager, Linux Secret Service via `libsecret`).
2. **Vault** — local AES-256-GCM encrypted file (see below).
3. **Env** — process environment variables.
4. **File** — mode-checked files under a configured root directory.

The first backend that returns a value for the reference wins. Missing
references fall through all backends and produce `SecretUnavailable` (which maps
to exit code 16).

Override the active backend in `[secrets]`:

```toml
[secrets]
backend = "auto"               # auto | keychain | vault | env
keychain_namespace = "spt"
vault_file = "/var/lib/spt/vault.spt"
memory_protection = "best_effort"
```

`backend = "auto"` enables the full priority chain above. Specifying a single
backend name restricts resolution to that backend only; missing references are
not tried against the others.

## Keychain backend

`KeychainBackend` wraps the native OS keychain via the `keyring` crate:

- **macOS** — Keychain Services. Secrets are stored in the login keychain and
  protected by the OS access-control model.
- **Windows** — Credential Manager. Stored under the configured
  `keychain_namespace` as the credential target name.
- **Linux** — Secret Service via `libsecret`. Requires a running Secret Service
  daemon (GNOME Keyring, KWallet, or equivalent).

On headless Linux without a Secret Service daemon, keychain operations fail and
the resolver falls through to the vault backend when `backend = "auto"`.

Store a secret interactively:

```
spt secret set ssh/edge-key --prompt
```

The value is stored in the OS keychain under the key
`<keychain_namespace>/ssh/edge-key` and is never written to disk in plaintext.

The keychain backend does **not** perform additional application-level
encryption; protection is delegated entirely to the OS. On Linux with an
untrusted or absent Secret Service, prefer the vault backend with an
explicit passphrase.

## Vault backend

`VaultBackend` is a local encrypted file providing portable at-rest protection
independent of the OS keychain.

### On-disk layout

Two files are written side-by-side:

- `vault.spt` — binary blob, JSON-encoded. Each record is stored as
  `{ nonce: "<12-byte hex>", ciphertext: "<AES-256-GCM output>" }` keyed by
  `"ns/name"`. The AEAD AAD for each record is `ns || 0x00 || name`, so a
  ciphertext cannot be silently rebound to a different reference.
- `vault.spt.meta` — TOML sidecar holding the format version (currently `1`),
  the Argon2id KDF parameters, and the passphrase salt.

### Master-key derivation

The vault master key (32 bytes, AES-256) is resolved in order:

1. OS keychain entry `(service = "spt", account = "vault-master")`.
2. Argon2id derivation from a passphrase supplied at open time. KDF parameters
   are read from `.meta` to allow future tuning without breaking existing vaults.

`spt secret store init` writes a fresh random master key to the keychain when
available; when a keychain is absent or `--backend vault` is given explicitly,
the caller must supply a passphrase (or `--passphrase-from <ref>`).

### Vault configuration

```toml
[secrets]
backend = "vault"
vault_file = "~/.local/share/spt/vault.spt"
encrypt_at_rest = true
memory_protection = "strict"
```

`encrypt_at_rest = true` asserts that the selected backend stores secrets with
application-level encryption. It is satisfied by the vault backend
(AES-256-GCM) and by the OS keychain on platforms that provide hardware-backed
key storage. It is not satisfied by the env or file backends, which carry
secrets in plaintext in their respective storage locations. The config validator
emits an error if `encrypt_at_rest = true` is paired with a backend that cannot
satisfy the constraint.

### Vault CLI workflow

```
# Initialise a new vault (master key goes to OS keychain when available):
spt secret store init --backend vault --vault-path ./secrets

# Initialise with an explicit passphrase instead of keychain:
spt secret store init --backend vault --vault-path ./secrets \
    --passphrase-from env:VAULT_PP

# Store a secret:
spt secret set ssh/edge-key --prompt --vault-path ./secrets

# Read (shows [REDACTED], not the plaintext):
spt secret get ssh/edge-key

# Remove:
spt secret remove ssh/edge-key

# Backend health summary:
spt secret doctor
```

## Environment backend

`EnvBackend` reads `SPT_SECRET_<NS_UPPER>__<NAME_UPPER>`, converting hyphens
and dots to underscores. For example, `secret://db/conn-string` maps to
`SPT_SECRET_DB__CONN_STRING`. Use `env:VAR_NAME` when the variable name is
arbitrary and does not follow the `secret://` namespace convention.

The env backend stores nothing at rest. Secrets exist only for the lifetime of
the process environment.

## File backend

`FileBackend` resolves `secret://ns/name` as `<root>/<ns>/<name>`. The root
directory defaults to `<state_dir>/secrets`; override it via:

```toml
[secrets.file]
root = "/run/secrets"
```

Setting `root = "/run/secrets"` makes the file backend compatible with Docker
Compose secrets, Kubernetes projected volumes, and systemd `LoadCredential`.
Each file contains the raw secret bytes (no newline trimming is applied by
default).

The file backend stores nothing in encrypted form. On Unix, each file must be
mode `0o400` or `0o600`; a mode violation is a backend error.

## Memory protection

Resolved secret bytes are always wrapped in `SecretBytes`, a
`secrecy::SecretBox` over a `zeroize::Zeroizing<Vec<u8>>`. This guarantees:

- The buffer is **zeroed on drop**, even on panic unwind.
- The value is **excluded from `Debug`** output and structured log fields.

The `memory_protection` field in `[secrets]` controls whether the process also
attempts to lock secret pages into physical RAM:

| Value          | Behaviour                                                        |
|----------------|------------------------------------------------------------------|
| `none`         | No locking. Pages may be swapped to disk.                        |
| `best_effort`  | Default. `mlock`/`VirtualLock` is attempted; failure is warned. |
| `strict`       | `mlock`/`VirtualLock` failure is a fatal startup error.         |

`mlock` failure (commonly `RLIMIT_MEMLOCK` on unprivileged containers) under
`best_effort` emits a `tracing::warn!` and continues. Under `strict`, the
process refuses to start.

### Non-swappable allocations (SecretAlloc)

For hot in-memory secrets that must never reach swap even if `mlock` fails,
`spt-secrets` provides `SecretAlloc` and the typed `MemfdSecretBox<T>` wrapper.
The returned allocation is:

1. Zero-initialised.
2. Non-swappable via the best available mechanism, selected at runtime:

| Platform       | Primary backend                             | Fallback         |
|----------------|---------------------------------------------|------------------|
| Linux >= 5.14  | `memfd_secret(2)` + `mmap(MAP_SHARED)`     | mlocked heap     |
| Linux < 5.14   | `ENOSYS` probe; `memfd_secret` unavailable  | mlocked heap     |
| Windows        | `VirtualLock`-ed heap                       | (same)           |
| macOS / BSD    | `mlock`-ed heap                             | (same)           |

3. Zeroed on drop, even on panic.

`memfd_secret(2)` is runtime-probed once per process. Memory backed by it is
unmapped from the kernel direct map and is therefore not accessible via
`/proc/<pid>/mem`, kdump, or direct-map kernel read primitives. This is
materially stronger than `mlock`.

`mlock` failure under `SecretAlloc` is non-fatal: the allocation succeeds, the
page is just swappable. A `tracing::warn!` is emitted. This matches the spec
§14.6 guidance of "attempt, diagnose if unavailable."

```rust
// Internal usage example (library consumers):
let s = spt_secrets::SecretAlloc::new(4096)?;
if s.is_memfd_secret() {
    // Kernel 5.14+ with CONFIG_SECRETMEM=y; pages are off the direct map.
} else {
    // mlocked heap fallback.
}
```

`MemfdSecretBox<T>` is a thin typed wrapper sized for exactly `size_of::<T>()`
bytes. It requires `T: Default + Zeroize` and is intended for fixed-size key
material (raw key bytes, nonces). Indirect allocations inside `T` (such as a
`Vec<u8>` heap buffer) are not protected by the wrapper; for those, use
`SecretSlice` directly.

Process-level RSS monitoring and memory-leak heuristics are handled by the
separate `[mem_hygiene]` subsystem. See [Resilience](resilience.md) and
[Security](security.md) for details.

## Sealed config envelopes (SPTENC1)

`spt-config-crypt` implements the `SPTENC1` on-disk format for shipping
encrypted configuration files. The sealed envelope is AEAD-protected and
supports three key sources:

| Source            | Mechanism                                                          |
|-------------------|--------------------------------------------------------------------|
| Passphrase        | Argon2id (m=64 MiB, t=3, p=4) derives a 32-byte key.             |
| Vault master key  | 32-byte key resolved from `spt_secrets::VaultBackend`.            |
| X25519 recipients | Body key encrypted per recipient via X25519 ECDH + HKDF-SHA-256. |

An optional Ed25519 detached signature covers `magic || meta || body`, allowing
publishers to prove provenance independently of the sealing key.

### File layout

```
offset  bytes        contents
------  -----------  -----------------------------------------------
0       8            magic = b"SPTENC1\n"
8       4            meta_len  (big-endian u32)
12      meta_len     meta-toml (UTF-8 TOML with single [meta] table)
..      4            body_len  (big-endian u32)
..      body_len     body-toml (UTF-8 TOML with single [body] table)
..      4            sig_len   (big-endian u32; absent at EOF if unsigned)
..      sig_len      sig-toml  (UTF-8 TOML with single [signature] table)
```

The AEAD AAD is `magic || meta_toml_bytes` (exactly as on disk), so any
tampering with the header is detected before decryption.

### Sealing a configuration file

```
# Generate a symmetric PSK:
spt config gen-key --type psk --out psk.key

# OR generate an X25519 keypair (encrypt-to-public-key):
spt config gen-key --type x25519 --out config.key
# Writes config.key (private) and config.key.pub (public).

# Seal with a PSK:
spt config encrypt config.toml \
    --psk-from file:///etc/spt/psk.key \
    --out config.sealed

# Seal for multiple X25519 recipients:
spt config encrypt config.toml \
    --recipient "$(cat alice.key.pub)" \
    --recipient "$(cat bob.key.pub)" \
    --out config.sealed

# Add an Ed25519 signature:
spt config sign config.sealed --key signing.key

# Verify a signature:
spt config verify config.sealed --pubkey signing.pub
```

### Fetching and auto-unsealing a remote config

Configure the remote-config fetcher to auto-unseal a `SPTENC1` body:

```toml
[runtime.remote_config]
enabled = true
url = "https://cfg.example.com/edge/config.sealed"
# SHA-256 fingerprint of the SEALED (SPTENC1) bytes hosted at `url`.
fingerprint_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
poll_interval = "5m"
allow_cached_on_failure = true

# Secret reference resolving to the PSK or X25519 private key.
encryption_key_from = "file:///etc/spt/psk.key"

# Reject a response that is not a sealed SPTENC1 envelope.
require_encrypted = true

# Optional: verify the Ed25519 publisher signature before unsealing.
signing_pubkey = "env:REMOTE_CONFIG_SIGNING_PUBKEY"
require_signature = true

# HTTPS pin for the remote-config HTTPS endpoint itself.
pin_spki_sha256 = ["SHA256:abc..."]
```

The `fingerprint_sha256` pin covers the *sealed* bytes as fetched; the body is
unsealed locally after the pin check. The `signing_pubkey` / `require_signature`
fields verify the Ed25519 signature inside the envelope before the body is
parsed, authenticating the publisher independently of the transport channel.

### Vault-sealed fleet configs

For fleet deployments, seal configs under the vault master key so that the
decryption key never appears on disk outside the vault:

```
spt config encrypt spt.toml \
    --use-vault-master \
    --vault-path /var/lib/spt/vault.spt \
    --out spt.sealed
```

## spt secret CLI

```
# Store secrets interactively:
spt secret set db/password --prompt
spt secret set db/password --from-env DB_PASSWORD
spt secret set api/token --from-file /run/secrets/api

# Read (always prints [REDACTED] — the value is never printed):
spt secret get db/password

# Remove:
spt secret remove db/password

# Backend health summary (reports which backends are reachable):
spt secret doctor
```

See [CLI Reference](cli-reference.md) for the full `spt secret` and
`spt config` sub-command surfaces.

## See also

- [Authentication](authentication.md) — how secret references appear in auth
  method configuration.
- [Trust](trust.md) — TLS and host-key trust material.
- [Security](security.md) — cryptographic choices, overflow-checks, fuzz
  harnesses, and the 2026 security audit baseline.
- [Resilience](resilience.md) — `[mem_hygiene]` RSS monitoring and
  leak-heuristic configuration.
