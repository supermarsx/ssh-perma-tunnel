# Bitvise SSH Client Comparison

This is the current engineering comparison against the public Bitvise SSH
Client feature page, checked on 2026-05-21:
<https://bitvise.com/ssh-client>.

The comparison is not a product-positioning claim. Bitvise is a Windows SSH
client suite with GUI, terminal, SFTP, drive mapping, and companion command
line tools. `spt` is a cross-platform, CLI/config-first tunnel supervisor. A
gap here means either "not implemented yet" or "not a product goal"; the
status column calls that out.

## Summary Matrix

| Bitvise capability | `spt` status | Notes |
|--------------------|--------------|-------|
| Windows GUI SSH/SFTP client | Non-goal | `spt` remains Rust-only CLI/config software. The TUI config wizard is not a file-transfer GUI or terminal. |
| Terminal access, terminal recording, remote exec | Gap / non-goal pending decision | No `sexec`/`stermc` equivalent. This should stay out unless the product scope expands beyond permanent tunnels, SFTP operations, and service management. |
| Local TCP forwarding | Parity target implemented | SSH2/russh and forwarding runner cover local TCP forwards. |
| Remote TCP forwarding, server-to-client direction | Parity target implemented | `remote` forwards are implemented and tested for server-originated connections back to a local target. |
| Dynamic proxy forwarding | Parity target implemented | `spt` supports SOCKS4, SOCKS4A, SOCKS5, and HTTP CONNECT over SSH2/russh with config/CLI protocol selection. |
| UDP forwarding | Differentiator with SSH3 | `spt` supports UDP through SSH3/QUIC capability gates. SSH2 UDP remains unsupported by protocol design. |
| Server-side Unix socket forwarding | Gap | `spt` parses Unix bind addresses in core types but forward targets reject Unix sockets today. |
| Centrally managed server-side forwarding rules | Partial / different model | `spt` uses config, remote config, MCP guarded reload, and GPO-style policy. It does not mirror Bitvise Server central rule management. |
| Auto reconnect | Implemented | Supervisor backoff, failover modes, reload, and session state are covered. |
| Jump proxy / jump server | Partial | Config has `[[profiles.hops]]`, but current russh path still reports unsupported for multi-hop runtime. |
| SFTP one-shot operations | Partial parity | `spt sftp` supports test/list/stat/get/put/mkdir/rm/rmdir/rename through russh SFTP. |
| Advanced SFTP transfers: recursive, wildcard, resume, mirror, check-file integrity | Gap | Current SFTP operations are single-operation primitives, not a Bitvise `sftpc` equivalent. |
| SFTP drive mapping | Planning/config only | `spt sftp drive` stores and validates drive plans and reports helper requirements; it does not mount through WinFsp/FUSE yet. |
| FTP-to-SFTP bridge | Gap | No FTP listener/translator exists. |
| Scriptable tunneling client | Implemented in `spt` style | `spt tunnel`, `forward`, `profile`, service commands, JSON output, man pages, and completions cover automation. |
| Portable/no-registry operation | Partial | `spt` is config/state-dir driven and can run rootless. Windows registry is used only for explicit policy/service/event-log operations. |
| SSPI/GSSAPI Kerberos and NTLM auth | Config/diagnostic surface only | Methods and gates exist; runtime negotiation returns explicit unsupported until SSH2 backend support lands. |
| Kerberos/GSSAPI key exchange | Gap | Not implemented. |
| Public-key auth: Ed25519, ECDSA, RSA | Partial | Supported through underlying SSH2 backends; current comparison does not prove full Bitvise algorithm breadth. |
| Password and keyboard-interactive auth | Implemented | SSH2/russh covers password and keyboard-interactive. Password change during auth is not implemented. |
| TOTP/two-factor keyboard-interactive | Partial | KBI responder support exists, but no dedicated TOTP generator or multi-prompt policy surface is implemented. |
| Host-key verification and pinning | Implemented | known_hosts and SHA-256 pinning surfaces exist. Automatic host-key synchronization is not equivalent to Bitvise. |
| Obfuscated SSH | Gap | No obfuscation transport or OpenSSH patch compatibility. |
| ML-KEM post-quantum KEX | Config/diagnostic surface only | Names are recognized and gated; runtime returns unsupported until transport KEX engines exist. |
| Curve25519, ECDH, DH GEX/fixed groups | Partial | Crypto allow-lists exist and backend defaults apply. Full Bitvise algorithm-by-algorithm runtime parity is not verified. |
| Ed25519/ECDSA/RSA/DSA signatures | Partial | Modern public-key paths exist; DSA/SHA-1 are deprecated and warning-gated where configured. |
| ChaCha20-Poly1305, AES-GCM/CTR/CBC, 3DES | Partial | Crypto policy can express modern/deprecated algorithms, but full backend runtime coverage has not been accepted across all listed Bitvise algorithms. |
| HMAC SHA-2 ETM/classic and SHA-1 | Partial | MAC allow-lists and deprecated warnings exist; full runtime parity matrix remains acceptance work. |
| FIPS 140 mode | Gap | No FIPS mode, Windows CNG provider switch, or FIPS validation story. |
| Windows service/unattended use | Implemented differently | `spt service` covers SCM/Task Scheduler plus systemd/launchd/OpenRC/SysV. |
| Windows Event Log | Implemented surface | CLI lifecycle and non-Windows unsupported diagnostics exist; Windows acceptance still must run on Windows. |
| GPO-style management | Implemented surface | `spt firewall policy` and config policy bindings cover GPO-like controls including capabilities and network policy. |

## Crypto Parity Details

Bitvise lists ML-KEM hybrid KEX, Curve25519, NIST and secp256k1 ECDH, DH
GEX/fixed groups, GSSAPI KEX, Ed25519/ECDSA/RSA/legacy DSA signatures,
ChaCha20-Poly1305, AES-GCM, AES-CTR, legacy AES-CBC/3DES, and HMAC SHA-2/SHA-1.

`spt` currently has three layers:

1. Config allow-lists for ciphers, KEX, MACs, host keys, and compression.
2. Deprecated-algorithm warnings in validation, diagnostics, status, and docs.
3. Explicit unsupported errors for requested PQ KEX (ML-KEM / sntrup761)
   until russh ships the matching engines. Kerberos/SSPI runtime auth is
   real as of t7.

That means `spt` should not claim Bitvise crypto parity yet. The production
acceptance item is an algorithm-by-algorithm negotiation suite against a
known server matrix on the pure-Rust `russh` backend (the only SSH2 backend
since t7).

## Highest-Value Gaps

These are the gaps that matter most if the target is "Bitvise-class tunneling
and secure file operations" rather than GUI parity. Items struck through were
delivered in t7:

1. ~~Runtime GSSAPI/Kerberos/SSPI auth~~ — landed in t7-A3 / t7-P3.
   GSSAPI KEX (`gss-group14-sha256` etc.) remains absent in russh 0.46.
2. Runtime ML-KEM hybrid KEX support in the pure-Rust SSH2 backend.
3. ~~SFTP recursive/resume/mirror/check-file operations~~ — landed in t6-e4.
4. ~~Real SFTP mount/drive execution through platform helpers~~ — landed in
   t7-A5 (Linux FUSE), t7-P2 (Windows Dokany2). macOS sshfs remains the
   deprecation-warned path; FSKit deferred.
5. ~~FTP-to-SFTP bridge if legacy FTP client support is in scope~~ — landed
   in t6-e6; AUTH-TLS in-place upgrade landed in t7-A8.
6. Algorithm-by-algorithm SSH2 crypto acceptance tests.

## Deliberate Non-Goals Unless Scope Changes

- GUI SFTP browser.
- Integrated terminal emulator and terminal recording.
- Remote graphical administration of an SSH server.
- FlowSsh-style .NET library.
- Marketing claims of FIPS validation.

## Acceptance Additions

Before claiming parity against Bitvise-class features, add these acceptance
rows to release reports:

- `russh` SSH2 auth matrix: password, public key, certificate,
  keyboard-interactive, GSSAPI, SSPI, and denial cases.
- SSH2 crypto matrix: each configured KEX/cipher/MAC/host-key algorithm either
  negotiates successfully or returns a documented unsupported diagnostic.
- SFTP transfer matrix: single file, recursive, resume, mirror, integrity
  check, large file, permission failure, interrupted transfer, and retry.
- Dynamic proxy matrix: SOCKS4, SOCKS4A, SOCKS5, HTTP CONNECT, protocol
  allowlist subsets, disabled-protocol failures, and max-connection limits.
- Windows file-system integration matrix: WinFsp drive mapping install,
  mount, read, write, reconnect, unmount, service account, and policy-denied.
