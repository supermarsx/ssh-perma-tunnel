# Trust

`spt` validates remote endpoints against operator-configured trust material
before sending any secret bytes.

## SSH2 host-key

    [profiles.trust]
    mode = "known_hosts"           # known_hosts | pinned
    known_hosts_file = "/etc/spt/known_hosts"
    strict = true                  # fail closed on unknown host
    accept_new = false             # never auto-accept (no TOFU)

## SHA-256 pin

    [profiles.trust]
    mode = "pinned"
    pin_sha256 = ["SHA256:abc123..."]

A profile may set both `known_hosts_file` and `pin_sha256`; the validator
requires at least one source of trust material. Trust failures map to
`TrustFailed` (exit code 6).

## TLS (SSH3, remote-config, HTTPS sinks)

    [profiles.tls]
    ca_file = "/etc/ssl/private/edge-ca.pem"
    spki_pins = ["SHA256:..."]
    allow_self_signed = false

Pin verification is performed *in addition* to PKIX validation by default;
no insecure modes are exposed.

## Pin rotation

Replace the pin in config and reload (`spt config reload`). Both the old
and new pin can be listed simultaneously during a rotation window.

## TOFU

`spt` does **not** offer trust-on-first-use prompts in service mode. Use
`spt key inspect <ssh-host:port>` (M3) to capture and pin a host key
explicitly.
