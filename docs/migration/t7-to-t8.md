# Migrating from t7 to t8 — libssh2 demolition

t7-Phase0 deleted the libssh2 SSH2 backend. The pure-Rust `russh` crate is
now the only SSH2 implementation. The workspace no longer depends on
`ssh2`, `async-ssh2-lite`, `libssh2-sys`, or `openssl-src` (Strawberry-Perl
is no longer required on Windows; libssl-dev / openssl@3 are no longer
required on Linux/macOS for spt itself).

## Deprecated configuration keys

`[capabilities].ssh2_backend` and `[capabilities].allow_libssh2` are
**deprecated**. They are still accepted at config load — `spt config
validate` emits the structured warning code
`capabilities_ssh2_backend_deprecated_t7` once per key and the values are
silently ignored at runtime.

Strip the keys by running:

    spt config migrate --to 2

The migration bumps `version = 1` to `version = 2`, removes the two
deprecated keys, and leaves every other field untouched.

## Functional impact

* Agent userauth, GSSAPI (`gssapi-with-mic` / RFC 4462), and SSPI
  Negotiate are now real on the russh path (delivered by t7-A1, t7-A3,
  and the vendored russh / libgssapi forks in `vendor/russh-fork` and
  `vendor/libgssapi-fork`).
* SFTP, multi-hop, UDS forwarding, and dynamic SOCKS/HTTP proxy listeners
  all run on russh. Multi-hop no longer needs the loopback socketpair
  trick (russh accepts any `AsyncRead+AsyncWrite` transport).
* `rhai` scripting, `obfs4` / meek-http / ssh-over-websocket transports,
  SFTP mount session loops (Linux FUSE, Windows Dokany2, macOS sshfs),
  and the FTP→SFTP translator's RFC 4217 AUTH TLS in-place upgrade are
  all real (no longer contract-enforcing stubs).

## MSRV bump

The workspace MSRV moved from Rust 1.83 to **Rust 1.85** during t7 to
accommodate `sspi 0.15.12` and a handful of `cargo update` transitives
that the lifted "no `cargo update`" policy pulled in. Source builds now
require:

    rustup install 1.85.0
    rustup default 1.85.0

`rust-toolchain.toml` is pinned to channel `1.85` so toolchain-managed
builds pick the right version automatically.

## Algorithm parity

russh 0.46 covers every modern KEX, cipher, MAC, hostkey, and compression
algorithm spt advertised through libssh2's `method_pref`. Deprecated
algorithms libssh2 still shipped (`blowfish-cbc`, `cast128-cbc`,
`arcfour*`, `hmac-md5*`, `hmac-sha1-96`) are not in russh — losing them is
a deliberate hardening. PQ-KEX (`mlkem*`, `sntrup761*`) is not yet in
russh 0.46; configuring one will fail negotiation at runtime, and
`spt config validate` warns when the policy recognizes a PQ-KEX algorithm.

See `.orchestration/logs/t7-Phase0.md` for the full algorithm audit.
