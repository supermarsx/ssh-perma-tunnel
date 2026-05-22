# Authentication

`spt` supports every SSH2 authentication mechanism plus the HTTP-style methods
SSH3 needs (bearer / HTTP-basic / OIDC / SSH3-style public key). Each profile
declares one method in `[profiles.auth]` via the `method` field. The supervisor
attempts the configured method on connect; persistent failures map to
`AuthFailed` (exit code 5).

The canonical method names accepted by the validator are listed in spec §9.12
and reflected by [`crates/spt-config/src/schema.rs`](../crates/spt-config/src/schema.rs):

| `method`               | Layer | Notes                                    |
|------------------------|-------|------------------------------------------|
| `public_key`           | SSH2  | Identity file, optional certificate.     |
| `agent`                | SSH2  | Delegate to a running ssh-agent.         |
| `password`             | SSH2  | Password (with optional kbi fallback).   |
| `keyboard_interactive` | SSH2  | Server-driven prompt/response.           |
| `gssapi` / `kerberos`  | SSH2  | GSSAPI/Kerberos shape + policy gates.    |
| `sspi` / `negotiate`   | SSH2  | Windows SSPI/Negotiate shape + gates.    |
| `bearer_token`         | SSH3  | HTTP `Authorization: Bearer …`.          |
| `http_basic`           | SSH3  | HTTP `Authorization: Basic …`.           |
| `oidc`                 | SSH3  | OIDC device-flow / authorization-code.   |
| `ssh3_public_key`      | SSH3  | SSH3-style public-key auth.              |

Inline plaintext password / token / passphrase values are rejected in strict
mode and surface as warnings outside it. Always use a `secret://`, `env:`, or
`file://` reference — see [Secrets](secrets.md).

## SSH2 public key

```toml
[profiles.auth]
method = "public_key"
identity_file = "~/.ssh/id_ed25519"
# Optional OpenSSH user certificate alongside the key:
certificate_file = "~/.ssh/id_ed25519-cert.pub"
# Encrypted-at-rest key? Resolve the passphrase from a secret backend:
passphrase = "secret://ssh/edge/passphrase"
agent = false
```

The identity file must be readable owner-only (mode `0600` on Unix; ACLs on
Windows). The validator emits `KeyFailure` (exit code 19) on a mode-check
failure.

### Supported signature algorithms

`spt` accepts the modern SSH public-key signature algorithms via the
`ssh-key` 0.6 + `russh-keys` 0.46 stack (see
[`crates/spt-key/docs/algorithms.md`](../crates/spt-key/docs/algorithms.md)
for the full crypto rationale and implementation matrix):

| Algorithm                | Curve / hash    | Status                                |
|--------------------------|-----------------|---------------------------------------|
| `ssh-ed25519`            | Curve25519      | Accepted (recommended default).       |
| `ecdsa-sha2-nistp256`    | NIST P-256      | Accepted.                             |
| `ecdsa-sha2-nistp384`    | NIST P-384      | Accepted.                             |
| `ecdsa-sha2-nistp521`    | NIST P-521      | Accepted.                             |
| `rsa-sha2-256`           | RSA + SHA-256   | Accepted. RSA modulus ≥ 3072 bits.    |
| `rsa-sha2-512`           | RSA + SHA-512   | Accepted. RSA modulus ≥ 3072 bits.    |
| `ssh-rsa`                | RSA + SHA-1     | **Rejected by default** (see below).  |

`ssh-rsa` is the legacy RFC 4253 RSA signature using SHA-1. SHA-1 is
collision-broken, so `spt` refuses to authenticate with it. Modern servers
(OpenSSH 7.2+) negotiate `rsa-sha2-256` or `rsa-sha2-512` automatically
against the same private key — no config change is required.

If you must connect to a pre-7.2 OpenSSH or a non-OpenSSH peer that has not
been updated past RFC 4253, the escape hatch enables `ssh-rsa` for that
single profile:

```toml
[profiles.auth]
method = "public_key"
identity_file = "~/.ssh/id_rsa_legacy"
# Permit legacy ssh-rsa (SHA-1) — only required for old or proprietary
# servers that have not been updated to RFC 8332. Leave this OUT for any
# modern server.
allow_ssh_rsa_sha1 = true
```

The rejection error message has the stable prefix `algorithm policy:` so it
is easy to match in CI:

```text
algorithm policy: refusing legacy `ssh-rsa` (SHA-1); enable `allow_ssh_rsa_sha1 = true` to permit
```

## SSH agent

```toml
[profiles.auth]
method = "agent"
# Optional: pin a specific agent identity by its public-key prefix.
identity_hint = "ssh-ed25519 AAAA..."
```

`agent` mode is the recommended default for interactive operators. The agent
socket is read from `$SSH_AUTH_SOCK`; for service installs you must export
this in the unit's environment (see
[Service Integration](service-integration.md)).

## SSH2 password (and keyboard-interactive fallback)

```toml
[profiles.auth]
method = "password"
password = "secret://ssh/edge/password"
keyboard_interactive = true   # try kbi if password fails
```

```toml
[profiles.auth]
method = "keyboard_interactive"
password = "secret://ssh/edge/password"
```

`keyboard_interactive` is server-driven: the response to each prompt is taken
from the resolved `password` secret. For multi-prompt servers, configure your
prompts at the IdP, not in the config file.

## SSH2 GSSAPI, Kerberos, And SSPI

```toml
[capabilities]
allow_gssapi = true
allow_sspi = true
allow_gssapi_delegation = false
allow_ntlm_fallback = false

[profiles.auth]
method = "kerberos"
gssapi_service = "host/edge.example.com"
gssapi_principal = "alice@EXAMPLE.COM"
gssapi_delegate = false
```

```toml
[profiles.auth]
method = "sspi"
sspi_service = "host/edge.example.com"
sspi_principal = "alice@example.com"
sspi_delegate = false
sspi_allow_ntlm_fallback = false
```

These methods are real, end-to-end auth paths over russh as of t7. They are
gated by `[capabilities]`; delegation and NTLM fallback require their own
explicit policy flags.

* **Unix (`method = "kerberos"` / `"gssapi"`)** — driven by the vendored
  `libgssapi 0.9` fork under [`vendor/libgssapi-fork/`](../vendor/libgssapi-fork/),
  which adds `gss_get_mic` / `gss_verify_mic` bindings on top of upstream so
  the integrity tokens are real RFC 2743 `MIC` tokens (wire-compatible with
  RFC 4462 §3.5 OpenSSH peers). The Kerberos ticket cache is taken from the
  ambient KRB5 environment; `KRB5CCNAME` / `gssapi_principal` honoured per
  MIT KRB5 / Heimdal conventions.
* **Windows (`method = "sspi"` / `"negotiate"`)** — driven by `sspi 0.15`
  (pure-Rust Negotiate / Kerberos / NTLM). Because `sspi-rs` does **not**
  call the OS SSPI subsystem, ambient current-user SSO is not available;
  thread explicit credentials via supervisor inputs, or via the
  `SPT_SSPI_USER` / `SPT_SSPI_PASS` / `SPT_SSPI_KDC_URL` environment
  variables.
* Token issuance, MIC sign, and MIC verify each fire structured audit
  events via the optional `AuditHook` (see
  [Events](events.md) and `crates/spt-auth-sspi/src/audit.rs`).

## SSH3 bearer token

```toml
[profiles.auth]
method = "bearer_token"
token = "secret://ssh3/edge/token"
```

The token is sent verbatim in the HTTP `Authorization` header on the Extended
CONNECT exchange. SSH3 itself is experimental — see [SSH3](ssh3.md) before
enabling.

## SSH3 HTTP Basic

```toml
[profiles.auth]
method = "http_basic"
password = "secret://ssh3/edge/password"
# `user` is taken from the parent profile's `user = "..."` field.
```

## SSH3 OIDC (experimental)

```toml
[profiles.auth]
method = "oidc"
oidc_issuer = "https://idp.example.com"
oidc_client_id = "spt-edge"
```

The device-flow handshake is parsed and validated in M0 but not yet exercised
on a live transport (see [SSH3](ssh3.md)).

## See also

- [Secrets](secrets.md) — backends and reference syntax.
- [Trust](trust.md) — host-key / TLS pinning, validated *before* auth runs.
- [Examples](../examples/) — `minimal.toml` (agent), `smtp-relay.toml`
  (`public_key` + passphrase), `ssh3.toml` (bearer token),
  `zero-trust-https.toml` (vault-resolved `public_key`).
