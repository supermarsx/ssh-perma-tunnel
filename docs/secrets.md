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

## CLI

    spt secret set db/password --prompt
    spt secret set db/password --from-env DB_PASSWORD
    spt secret set api/token --from-file /run/secrets/api
    spt secret get db/password         # prints [REDACTED]
    spt secret remove db/password
    spt secret doctor                  # backend health summary
