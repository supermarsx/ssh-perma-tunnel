# Secrets

`spt` never stores secrets in plaintext config. References are resolved at
runtime through pluggable backends.

## Reference syntax

| Form              | Resolved by                                |
|-------------------|--------------------------------------------|
| `secret://ns/name`| `KeychainBackend` then `VaultBackend`     |
| `env:NAME`        | `EnvBackend` (`SPT_SECRET_<NS>__<NAME>`)  |
| `file:///abs`     | `FileBackend` (mode-checked)              |

Both `ns` and `name` are limited to alphanumerics plus `_`, `-`, `.`.

## Backend priority

Default order (per spec §14.6): keychain → vault → env → file. Override via
`[secrets].backend`:

    [secrets]
    backend = "auto"               # auto | keychain | vault | env
    keychain_namespace = "spt"
    vault_file = "/var/lib/spt/vault.spt"

## Keychain

`KeychainBackend` wraps the OS keychain via the `keyring` crate:

- macOS: Keychain Services.
- Windows: Credential Manager.
- Linux: Secret Service (libsecret).

`spt secret set foo/bar --prompt` stores under the configured service name.
Headless Linux without Secret Service falls back to the local vault.

## Vault

`VaultBackend` is an AES-256-GCM file with an Argon2id-derived KDF. The
master key may live in the OS keychain (preferred) or be unlocked with a
passphrase (`spt secret store init --backend vault`).

Vault records can be used as sealed-config passphrases:

```text
spt secret store init --backend vault --vault-path ./secrets --passphrase-from env:VAULT_PP
spt secret set cfg/seal-passphrase \
  --from-env CONFIG_SEAL_PP \
  --vault-path ./secrets \
  --passphrase-from env:VAULT_PP
spt config encrypt spt.toml \
  --passphrase-from secret://cfg/seal-passphrase \
  --vault-path ./secrets \
  --vault-passphrase-from env:VAULT_PP
```

For fleet configs, `spt config encrypt --use-vault-master` seals directly
under the vault master key. The decrypt/edit/rotate commands accept the same
`--vault-path` and `--vault-passphrase-from` options.

## Environment

`EnvBackend` looks up `SPT_SECRET_<NS_UPPER>__<NAME_UPPER>`, with `-`/`.`
normalised to `_`.

## File

`FileBackend` reads `<root>/<ns>/<name>`. On Unix the file mode must be
`0o400` or `0o600` (owner-only). On Windows ACLs are best-effort checked.

## Memory protection

Returned bytes are wrapped in `secrecy::SecretBox<Zeroizing<Vec<u8>>>`,
zeroed on drop and excluded from `Debug`. `mlock` / `VirtualLock` is
attempted when `[secrets].memory_protection = "strict"`.

### Non-swappable allocations (`SecretAlloc`)

For hot in-memory secrets that must never hit swap, `spt-secrets` offers
`SecretAlloc::new(len) -> SecretSlice` (and the typed `MemfdSecretBox<T>`
wrapper). The returned slice is:

1. **Zero-initialised.**
2. **Non-swappable** — via one of two backends, selected at runtime:

   | Platform        | Primary backend                          | Fallback             |
   |-----------------|------------------------------------------|----------------------|
   | Linux ≥5.14     | `memfd_secret(2)` + `mmap(MAP_SHARED)`   | mlocked heap         |
   | Linux <5.14     | (n/a — probe returns `ENOSYS`)           | mlocked heap         |
   | Windows         | `VirtualLock`-ed heap                    | (same)               |
   | macOS / BSD     | `mlock`-ed heap                          | (same)               |

3. **Zeroed on drop**, even on panic.

The `memfd_secret(2)` syscall is runtime-probed once per process via
`libc::syscall(libc::SYS_memfd_secret, 0)`. A successful probe means the
kernel was built with `CONFIG_SECRETMEM=y`; the returned fd is sized with
`ftruncate` and mapped `MAP_SHARED`. Memory backed this way is unmapped
from the kernel direct map and is therefore not accessible via
`/proc/<pid>/mem`, kdump, or direct-map kernel read primitives.

`mlock` failure (typically `RLIMIT_MEMLOCK` on unprivileged containers) is
**not** an error — the allocation still succeeds, the page is just
swappable. A `tracing::warn!` is emitted. This matches spec §14.6 ("attempt,
diagnose if unavailable").

`MemfdSecretBox<T>` is a thin typed wrapper sized for exactly
`size_of::<T>()` bytes; it requires `T: Default + Zeroize` and is intended
for `bytemuck::Pod`-shaped types (raw key material, nonces, fixed-size
ciphertext envelopes). Indirect allocations inside `T` (e.g. `Vec<u8>`'s
heap buffer) are **not** protected by the wrapper — for those, use
`SecretSlice` directly and serialise into it.

#### Verifying which backend is in use

```rust
let s = spt_secrets::SecretAlloc::new(4096)?;
if s.is_memfd_secret() {
    tracing::info!("secret pages backed by memfd_secret(2)");
} else {
    tracing::info!("secret pages on mlocked heap (memfd_secret unavailable)");
}
```

On a CI host that you know runs kernel 5.14+ with `CONFIG_SECRETMEM=y`,
flipping `is_memfd_secret()` to `assert!(...)` confirms the kernel
feature path is exercised.

## CLI

    spt secret set db/password --prompt
    spt secret set db/password --from-env DB_PASSWORD
    spt secret set api/token --from-file /run/secrets/api
    spt secret get db/password         # prints [REDACTED]
    spt secret remove db/password
    spt secret doctor                  # backend health summary
