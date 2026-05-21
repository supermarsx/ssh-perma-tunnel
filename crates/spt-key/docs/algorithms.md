# SSH Public-Key Algorithm Support

`spt-key` generates, signs with, and verifies SSH public keys across the
following algorithms. This document captures (a) the exact algorithm set the
crate accepts, (b) which `ssh-key` / `russh-keys` API paths drive each one,
and (c) the rationale for the legacy-RSA policy.

## Supported algorithms

| SSH algorithm name        | Curve / hash      | Default? | Status   | Notes                                                  |
|---------------------------|-------------------|---------:|----------|--------------------------------------------------------|
| `ssh-ed25519`             | Curve25519        |   Yes    | Accepted | Recommended. Constant-time. 256-bit security.          |
| `ecdsa-sha2-nistp256`     | NIST P-256        |    No    | Accepted | Hardware-token interop.                                |
| `ecdsa-sha2-nistp384`     | NIST P-384        |    No    | Accepted | Higher-security ECDSA.                                 |
| `ecdsa-sha2-nistp521`     | NIST P-521        |    No    | Accepted | Highest-security ECDSA in this family.                 |
| `rsa-sha2-256`            | RSA + SHA-256     |    No    | Accepted | RFC 8332. Requires RSA modulus ≥ 3072 bits.            |
| `rsa-sha2-512`            | RSA + SHA-512     |    No    | Accepted | RFC 8332. Requires RSA modulus ≥ 3072 bits.            |
| `ssh-rsa`                 | RSA + SHA-1       |    No    | Rejected | Legacy (RFC 4253). Escape hatch: `allow_ssh_rsa_sha1`. |

DSA (`ssh-dss`), `rsa-sha1`-only servers, and any modulus below 3072 bits are
out of scope for new keys. Existing RSA-2048 keys may be *loaded* but the
generator rejects sub-3072 sizes.

## Algorithm policy: why `ssh-rsa` (SHA-1) is rejected by default

`ssh-rsa` names the legacy RSA signature algorithm defined in RFC 4253, which
uses SHA-1 over the signed buffer. SHA-1 is collision-broken; OpenSSH
disables `ssh-rsa` by default starting with OpenSSH 8.8 (2021-09).

RFC 8332 added `rsa-sha2-256` and `rsa-sha2-512` — the SAME RSA private key
can sign under either modern algorithm. The on-disk PEM does not change; the
two libraries we depend on (`ssh-key 0.6`, `russh-keys 0.46`) negotiate the
SHA-2 variants whenever the server announces support.

Therefore:

* For every server that has been updated past OpenSSH 7.2 (2016-03), the
  client and server negotiate `rsa-sha2-{256,512}` automatically when the
  configured `identity_file` points at an RSA key. **The escape hatch is not
  needed and should not be enabled.**
* For pre-7.2 OpenSSH, certain proprietary SSH servers, or appliances that
  have not received firmware updates, the server may *only* support
  `ssh-rsa`. In that narrow case operators must explicitly opt in by setting
  `allow_ssh_rsa_sha1 = true` on the relevant `[profiles.auth]` block — see
  the user-facing `docs/auth.md` for the config syntax and a runnable
  example.

The rejection path returns `Error::AuthFailed` (exit code 5) with a stable
message prefix `algorithm policy:` so operators and CI grep can pin the
behavior:

```text
algorithm policy: refusing legacy `ssh-rsa` (SHA-1); enable `allow_ssh_rsa_sha1 = true` to permit
```

## Implementation notes

The matrix integration test
[`crates/spt-key/tests/algorithm_matrix.rs`](../tests/algorithm_matrix.rs)
exercises every algorithm in the table above. The test covers:

* keygen (`spt_key::generate` for ed25519 / ecdsa-p256; `ssh_key::PrivateKey::random`
  for ecdsa-p384/521; `ssh_key::private::RsaKeypair::random` for RSA);
* sign + verify in **both libraries** — `ssh-key`'s `Signer<Signature>` /
  `Verifier<Signature>` impls drive ed25519 + ECDSA, `russh-keys`'s
  `KeyPair::sign_detached` drives RSA (see the bug note below);
* cross-library wire-format compatibility — a public key encoded by `ssh-key`
  must decode byte-identical in `russh-keys` and vice-versa;
* OpenSSH PEM round-trip byte-exactness on the unencrypted serialization
  path;
* OpenSSH user-certificate signing with an Ed25519 CA across every subject
  algorithm; principals + serial are preserved across the certificate
  round-trip;
* the SHA-1 rejection + escape-hatch policy gates surfaced by
  `spt_auth::method::check_pubkey_algorithm_allowed`.

### Known upstream bug: `ssh-key 0.6.7` RSA signing

`ssh-key 0.6.7`'s `private/rsa.rs:192-204` reconstructs an `rsa::RsaPrivateKey`
from a parsed `RsaKeypair` by passing the `p` prime *twice* instead of
`(p, q)`. Every path that flows through `Signer<Signature> for RsaKeypair`
(including `SshSig::sign` and `certificate::Builder::sign` for an RSA CA)
therefore fails with a `Crypto` error.

`RsaPublicKey` is unaffected because it only uses `(n, e)`, so verification
of signatures produced elsewhere works correctly. The matrix test routes
every RSA *signing* operation through `russh-keys`, which sources the RSA
implementation independently from the same `rsa` crate but reconstructs the
private-key components correctly. The resulting raw signature bytes are
wrapped into an `ssh_key::Signature` and verified through ssh-key's
`Verifier<Signature> for KeyData` — exercising the wire-format compatibility
between the two libraries.

When `ssh-key` ships a fix for this bug (a `(p, q)` rather than `(p, p)`
construction), the matrix test can drop the russh-keys RSA dependency and
exercise RSA via the same `Signer<Signature>` path used for ed25519 + ECDSA.

## See also

* [`docs/auth.md`](../../../docs/auth.md) — operator-facing config syntax,
  including the `allow_ssh_rsa_sha1` escape hatch example.
* [`docs/security.md`](../../../docs/security.md) — threat model and
  algorithm-deprecation policy.
* [RFC 4253 §6.6](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
  — the legacy `ssh-rsa` signature definition.
* [RFC 8332](https://datatracker.ietf.org/doc/html/rfc8332) — `rsa-sha2-256`
  and `rsa-sha2-512` for RSA keys.
