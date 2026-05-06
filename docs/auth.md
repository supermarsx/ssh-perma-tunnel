# Authentication

`spt` supports every SSH2 authentication mechanism plus the HTTP-style methods
SSH3 needs (bearer / basic / OIDC). Each profile declares one or more methods
in `[profiles.auth]`; the supervisor tries them in `methods` order on connect.

## Public key

    [profiles.auth]
    method = "pubkey"
    private_key = "/etc/spt/id_ed25519"
    # or:
    private_key_secret = "secret://ssh/edge-priv"

Encrypted-at-rest keys are loaded with `passphrase = "secret://..."`.

## SSH agent

    [profiles.auth]
    method = "agent"
    socket = "$SSH_AUTH_SOCK"   # optional; defaults to env

`agent` mode is the recommended default for interactive operators.

## Password

    [profiles.auth]
    method = "password"
    password = "secret://ssh/edge-pw"

Inline plaintext is rejected in strict mode.

## Keyboard-interactive

    [profiles.auth]
    method = "kbi"
    [[profiles.auth.kbi_answers]]
    prompt = "Password:"
    answer = "secret://ssh/edge-pw"

## Certificate

    [profiles.auth]
    method = "cert"
    private_key = "/etc/spt/id_ed25519"
    certificate = "/etc/spt/id_ed25519-cert.pub"

Generate with `spt key sign-cert` (M1+).

## Bearer / Basic / OIDC (SSH3 only)

    [profiles.auth]
    method = "oidc"
    issuer = "https://idp.example.com"
    client_id = "spt-edge"
    scopes = ["openid", "profile"]

## Method ordering

    [profiles.auth]
    methods = ["pubkey", "agent", "password"]

The supervisor tries methods in order and stops on the first success.
Persistent failures map to `AuthFailed` (exit code 5).

## See also

- [Secrets](secrets.md)
- [Trust](trust.md)
- [SSH3](ssh3.md)
