# Authentication

`spt` supports every SSH2 authentication mechanism plus the HTTP-level methods
that SSH3 requires. Each profile declares one or more methods in its
`[profiles.auth]` table via the `method` field. The supervisor attempts the
configured method on each connect attempt; persistent failures produce exit code
5 (`AuthFailed`).

`[profiles.auth]` is the profile-level (global) default applied to every
endpoint in the profile that does not declare its own credentials. An individual
endpoint can override it with an inline `[profiles.endpoints.auth]` block and an
optional `user` field. That override is a whole-block replacement, not a
field-level merge. See the [Configuration Reference](configuration-reference.md)
for the endpoint auth override syntax.

All credential values must be [secret references](secrets.md), never inline
plaintext. Inline passwords and tokens are accepted by the parser but are
rejected in strict mode and surfaced as validation warnings outside it.

## Method summary

| `method`               | Layer | Notes                                              |
|------------------------|-------|----------------------------------------------------|
| `public_key`           | SSH2  | Identity file; optional certificate.               |
| `certificate`          | SSH2  | OpenSSH user certificate with separate key file.  |
| `agent`                | SSH2  | Delegate to a running ssh-agent or Pageant.        |
| `password`             | SSH2  | Password; optional keyboard-interactive fallback.  |
| `keyboard_interactive` | SSH2  | Server-driven prompt/response with regex matching. |
| `gssapi` / `kerberos`  | SSH2  | GSSAPI Kerberos (Unix; vendored libgssapi 0.9).   |
| `sspi` / `negotiate`   | SSH2  | SSPI Negotiate/Kerberos/NTLM (Windows; sspi 0.15).|
| `bearer_token`         | SSH3  | HTTP `Authorization: Bearer ...`.                  |
| `http_basic`           | SSH3  | HTTP `Authorization: Basic ...`.                   |
| `oidc`                 | SSH3  | OIDC device-flow; experimental.                    |

The canonical list and string names are defined by spec §9.12 and reflected in
`crates/spt-auth/src/method.rs`.

## SSH2 public key

```toml
[profiles.auth]
method = "public_key"
identity_file = "~/.ssh/id_ed25519"
# Optional passphrase for an encrypted-at-rest key:
passphrase = "secret://ssh/edge/passphrase"
# Optional OpenSSH user certificate alongside the key:
certificate_file = "~/.ssh/id_ed25519-cert.pub"
```

The identity file must be readable by the process owner only (`0600` on Unix;
equivalent ACLs on Windows). A mode-check failure produces exit code 19
(`KeyFailure`).

The passphrase value is always resolved through the secret backend chain — see
[Secrets](secrets.md). Storing a raw passphrase string in the config file is
rejected in strict mode.

### Supported signature algorithms

`spt` accepts modern SSH public-key signature algorithms via the `ssh-key` 0.6
and `russh-keys` 0.46 stacks. The full crypto rationale is in
`crates/spt-key/docs/algorithms.md`.

| Algorithm              | Curve / hash  | Status                                  |
|------------------------|---------------|-----------------------------------------|
| `ssh-ed25519`          | Curve25519    | Accepted. Recommended default.          |
| `ecdsa-sha2-nistp256`  | NIST P-256    | Accepted.                               |
| `ecdsa-sha2-nistp384`  | NIST P-384    | Accepted.                               |
| `ecdsa-sha2-nistp521`  | NIST P-521    | Accepted.                               |
| `rsa-sha2-256`         | RSA + SHA-256 | Accepted. Key modulus must be >= 3072 bits. |
| `rsa-sha2-512`         | RSA + SHA-512 | Accepted. Key modulus must be >= 3072 bits. |
| `ssh-rsa`              | RSA + SHA-1   | **Rejected by default.** See below.     |

### Legacy ssh-rsa (SHA-1)

`ssh-rsa` is the original RFC 4253 RSA signature using SHA-1. SHA-1 is
collision-broken and `spt` refuses to sign with it by default. Modern servers
(OpenSSH 7.2 and later) automatically negotiate `rsa-sha2-256` or `rsa-sha2-512`
from the same private-key bytes with no configuration change required.

If you must connect to a pre-7.2 OpenSSH or a non-OpenSSH peer that has not
been updated beyond RFC 4253, enable the escape hatch for that one profile:

```toml
[profiles.auth]
method = "public_key"
identity_file = "~/.ssh/id_rsa_legacy"
# Required only for pre-OpenSSH-7.2 or non-standard servers.
# Leave this field out for any modern server.
allow_ssh_rsa_sha1 = true
```

The rejection error has the stable prefix `algorithm policy:` so it can be
matched reliably in CI output:

```
algorithm policy: refusing legacy `ssh-rsa` (SHA-1); enable `allow_ssh_rsa_sha1 = true` to permit
```

### OpenSSH user certificates

To use an OpenSSH user certificate, pass `certificate_file` alongside
`identity_file`. The certificate must be the signed `*-cert.pub` file; the
private key is still required to sign the auth exchange:

```toml
[profiles.auth]
method = "public_key"
identity_file = "~/.ssh/id_ed25519"
certificate_file = "~/.ssh/id_ed25519-cert.pub"
passphrase = "secret://ssh/corp/key-passphrase"
```

Alternatively, `method = "certificate"` uses separate `cert` and `key` paths and
is intended for non-default file layouts where the private key does not live
next to the certificate:

```toml
[profiles.auth]
method = "certificate"
cert = "/etc/spt/id_ed25519-cert.pub"
key = "/etc/spt/id_ed25519"
passphrase = "secret://ssh/corp/key-passphrase"
```

## SSH agent

```toml
[profiles.auth]
method = "agent"
# Optional: pin a specific agent identity by fingerprint or key comment.
identity_hint = "SHA256:abc..."
```

Agent mode is the recommended default for interactive operators. The agent
socket is read from `SSH_AUTH_SOCK` on Unix; on Windows `spt` connects to
Pageant or a compatible named-pipe agent. For service installs, export
`SSH_AUTH_SOCK` in the unit's environment — see [Service](service.md).

When multiple identities are loaded, `identity_hint` selects by exact key
comment match or SHA-256 fingerprint prefix. When absent, the agent's identities
are tried in their natural order.

An optional explicit socket path is available for environments where
`SSH_AUTH_SOCK` cannot be set:

```toml
[profiles.auth]
method = "agent"
socket = "/run/user/1000/gnupg/S.gpg-agent.ssh"
```

## SSH2 password

```toml
[profiles.auth]
method = "password"
password = "secret://ssh/edge/password"
# Optional: try keyboard-interactive if password auth is rejected.
keyboard_interactive = true
```

The `password` field must be a [secret reference](secrets.md). `keyboard_interactive = true`
enables a fallback attempt using the same resolved secret if the server rejects
plain password authentication — this covers servers that accept passwords only
through the keyboard-interactive exchange.

## Keyboard-interactive

The `keyboard_interactive` method supports scripted prompt-response bindings.
Each binding specifies a regex matched against the server-supplied prompt and the
answer source to use on a match.

```toml
[profiles.auth]
method = "keyboard_interactive"

# Respond to a simple password prompt with a secret-backed value.
[[profiles.auth.responders]]
prompt_regex = "(?i)password:"
answer = { secret_ref = "secret://ssh/edge/password" }

# Respond to an OTP prompt with a live TOTP code.
[[profiles.auth.responders]]
prompt_regex = "(?i)one.?time|otp|verification code"
answer = { totp = { secret_ref = "secret://ssh/edge/totp-seed", digits = 6, period = 30, algo = "sha1" } }

# Accept a legal-banner acknowledgement with a static string.
[[profiles.auth.responders]]
prompt_regex = "(?i)do you agree"
answer = { static = "yes" }
echo = true
```

Responders are matched in order; the first matching entry wins. The `echo` flag
records an informational note when the prompt text does not match the `echo`
expectation; it does not affect connection behaviour.

### TOTP (RFC 6238)

The `totp` answer variant computes an RFC 6238 Time-based One-Time Password at
prompt time. The implementation is pure-Rust (workspace `hmac`, `sha1`, `sha2`,
`subtle`) with no external TOTP dependency.

| Field        | Default | Notes                                                    |
|--------------|---------|----------------------------------------------------------|
| `secret_ref` | —       | Secret reference resolving to the raw OTP seed bytes.    |
| `digits`     | `6`     | OTP length; 1 to 9 inclusive. 6 and 8 are most common.  |
| `period`     | `30`    | Step period in seconds. RFC 6238 §5.2 recommends 30.    |
| `algo`       | `sha1`  | HMAC hash: `sha1`, `sha256`, or `sha512`.                |

The OTP seed in the secret backend must be the raw key bytes, not base32-encoded.
Decode the authenticator's base32 seed before storing it.

TOTP code comparison uses `subtle::ConstantTimeEq` to avoid timing side-channels.
The verifier accepts a configurable skew window (number of steps) to tolerate
minor clock drift between client and server.

### YubiKey OATH

The `yubikey_oath` answer variant retrieves an OATH-TOTP code from a connected
YubiKey by shelling out to `ykman oath accounts code`:

```toml
[[profiles.auth.responders]]
prompt_regex = "(?i)otp"
answer = { yubikey_oath = { oath_name = "corp-bastion", serial = "12345678" } }
```

`serial` is optional and disambiguates between multiple connected YubiKeys.
This variant requires the `yubikey` Cargo feature; without it the answer always
returns `UnsupportedPlatform`.

## GSSAPI and Kerberos (Unix)

```toml
[capabilities]
allow_gssapi = true
allow_gssapi_delegation = false

[profiles.auth]
method = "kerberos"
gssapi_service = "host/edge.example.com"
gssapi_principal = "alice@EXAMPLE.COM"
gssapi_delegate = false
```

Both `method = "gssapi"` and `method = "kerberos"` select the same GSSAPI
Kerberos path. The implementation uses the vendored `libgssapi 0.9` fork at
`vendor/libgssapi-fork/`, which adds `gss_get_mic` and `gss_verify_mic` bindings
over upstream so that integrity tokens are genuine RFC 2743 MIC tokens,
wire-compatible with the RFC 4462 §3.5 OpenSSH `gssapi-with-mic` exchange.

The Kerberos ticket cache is taken from the ambient KRB5 environment.
`KRB5CCNAME` and `gssapi_principal` are honoured following MIT KRB5 and Heimdal
conventions. The auth flow is:

1. Client sends `SSH_MSG_USERAUTH_REQUEST` selecting `gssapi-with-mic` and the
   OID list.
2. Server selects one OID in `SSH_MSG_USERAUTH_GSSAPI_RESPONSE`.
3. Client and server exchange opaque tokens until the local GSSAPI context
   reports `complete = true`.
4. Client computes a MIC over the session-id-bound transcript and sends
   `SSH_MSG_USERAUTH_GSSAPI_MIC`; the server verifies. Auth succeeds when the
   MIC verifies.

Each of token issuance, MIC sign, and MIC verify fires a structured audit event
via the optional `AuditHook` defined in `crates/spt-auth-sspi/src/audit.rs`.

GSSAPI is Unix-only. Calling the GSSAPI path on a non-Unix build returns
`UnsupportedPlatform`.

Credential delegation (`GSS_C_DELEG_FLAG`) is disabled by default and requires
both `allow_gssapi_delegation = true` in `[capabilities]` and
`gssapi_delegate = true` on the specific auth block.

## SSPI and Negotiate (Windows)

```toml
[capabilities]
allow_sspi = true
allow_ntlm_fallback = false

[profiles.auth]
method = "sspi"
sspi_service = "host/edge.example.com"
sspi_principal = "alice@example.com"
sspi_delegate = false
sspi_allow_ntlm_fallback = false
```

Both `method = "sspi"` and `method = "negotiate"` select the Windows SSPI path.
The implementation uses the pure-Rust `sspi 0.15` crate, which implements
Negotiate, Kerberos, and NTLM without calling into the operating-system SSPI
subsystem. As a consequence, ambient current-user single-sign-on (SSO) is not
available; credentials must be supplied explicitly through supervisor inputs or
environment variables:

| Variable           | Meaning                                   |
|--------------------|-------------------------------------------|
| `SPT_SSPI_USER`    | Windows username (domain\user or UPN).    |
| `SPT_SSPI_PASS`    | Password (best set via secret injection). |
| `SPT_SSPI_KDC_URL` | KDC URL override for cross-realm cases.   |

NTLM fallback is disabled by default. Enabling it requires both
`allow_ntlm_fallback = true` in `[capabilities]` and
`sspi_allow_ntlm_fallback = true` on the specific auth block. Requesting NTLM
fallback on a Unix build returns `AuthFailed` with the stable marker
`UnsupportedOnUnix`.

Credential delegation (`ISC_REQ_DELEGATE`) follows the same two-gate pattern as
GSSAPI: `allow_sspi_delegation = true` in `[capabilities]` and
`sspi_delegate = true` in the auth block.

## SSH3 bearer token

```toml
[profiles.auth]
method = "bearer_token"
token = "secret://ssh3/edge/token"
```

The token is sent verbatim in the HTTP `Authorization: Bearer ...` header on the
Extended CONNECT exchange. SSH3 itself is experimental and carries
caveats covered in [Transports](transports.md) before enabling.

## SSH3 HTTP basic

```toml
[profiles.auth]
method = "http_basic"
password = "secret://ssh3/edge/password"
# The username is taken from the profile's top-level `user` field.
```

The `user` field at the profile level provides the username component of the
`Authorization: Basic ...` header.

## SSH3 OIDC (experimental)

```toml
[profiles.auth]
method = "oidc"
oidc_issuer = "https://idp.example.com"
oidc_client_id = "spt-edge"
```

The device-authorization grant (RFC 8628) is fully implemented: discovery
document fetch, device-code request, polling loop, and token storage. The
resulting access token is stored through the secret backend and used on
subsequent connections. Token bytes are held in zeroizing `SecretBytes` buffers
and never appear in structured log output.

The OIDC path has been validated against a live device-flow provider in
isolation but is not yet exercised through a complete SSH3 transport stack in CI.
Treat it as experimental and verify against your specific identity provider.

## Crypto policy

Each profile's `[profiles.crypto]` table controls which ciphers, KEX algorithms,
MACs, and host-key algorithms are permitted for the SSH session. The `policy`
field accepts `modern` (recommended), `interop`, or `legacy`. Setting
`allow_deprecated = false` with `warn_on_deprecated = true` lets the validator
surface deprecated-algorithm negotiation without refusing the connection.

```toml
[profiles.crypto]
policy = "modern"
allow_deprecated = false
warn_on_deprecated = true
```

Fine-grained allow-lists (`ciphers`, `kex_algorithms`, `macs`,
`host_key_algorithms`, `compression`) override the policy defaults for that
profile.

## Per-hop authentication in jump chains

When a profile defines a ProxyJump / jump chain, each hop authenticates
independently. Assign a distinct profile (with its own `[profiles.auth]` block)
for each bastion and terminal host, or use per-endpoint auth overrides to keep
the hops in a single profile. See [Forwarding](forwarding.md) for the jump-chain
configuration syntax.

## See also

- [Secrets](secrets.md) — backends, resolver order, and the `secret://` syntax.
- [Trust](trust.md) — host-key and TLS pinning, validated before auth runs.
- [Transports](transports.md) — SSH2 vs. SSH3 transport selection.
- [CLI Reference](cli-reference.md) — `spt key generate`, `spt key inspect`.
- [Security](security.md) — cryptographic rationale and algorithm policy.
