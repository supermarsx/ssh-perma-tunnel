# Security policy

`spt` takes security seriously. This document describes how to report
vulnerabilities and what is — and is not — in scope.

## Supported versions

Security fixes are issued for the latest minor release.

| Version  | Supported          |
| -------- | ------------------ |
| `0.1.x`  | Yes                |
| `< 0.1`  | No                 |

When `0.2.0` ships, `0.1.x` will continue to receive security fixes
for one minor cycle and then be retired.

## How to report

Please report vulnerabilities through one of the following private
channels:

- **GitHub Security Advisories** — preferred. Use the "Report a
  vulnerability" button on the repository's *Security* tab.
- **Email** — `security@spt.invalid` (replace with the project
  maintainer's published address).

Please include:

- A description of the issue and its impact.
- Steps to reproduce, ideally a minimal repro case.
- The `spt --version` output and target triple.
- Any relevant `state.json` snippet (redacted) and trace output.

We aim to acknowledge reports within **3 business days** and to issue
a fix or coordinated disclosure within a **90-day window** from the
date of the initial report. If a coordinated release date works
better for the reporter we will accommodate it where reasonable.

## Scope

`spt` is **client-only**. It connects to existing SSH/SSH3 servers
and maintains forwards through them — there is no server role.

### In scope

- Memory-safety, secret-handling, or authentication bugs in the `spt`
  client itself.
- Incorrect TLS or SSH host-key handling, including the trust store
  (`spt-trust`).
- Vulnerabilities in `spt`'s **listening sockets**, which include:
  - the built-in transparent **DNS resolver**,
  - the **MCP loopback TCP** transport,
  - **local TCP forwards** that `spt` opens on the operator's host,
  - any debug/diagnostic listener.
- Redaction failures — i.e. plaintext secrets reaching a sink that
  the configured redaction policy says they shouldn't.
- Privilege-escalation paths in the service-integration installers
  (systemd, launchd, Windows SCM, OpenRC, SysV, Task Scheduler).

### Out of scope

- Issues caused by **operator-supplied untrusted config files**.
  `spt` reads its config from the local filesystem; protecting that
  filesystem is the operator's responsibility. Specifically:
  - secret references that point at attacker-controlled paths,
  - profiles that intentionally lower trust levels,
  - service unit files edited by hand to disable hardening.
- Behaviour of remote SSH/SSH3 servers `spt` connects to — file bugs
  with those upstreams.
- Issues caused by running `spt` with elevated privileges that the
  spec or docs explicitly recommend against.
- DoS by resource exhaustion when the operator has explicitly disabled
  the relevant rate limit.

### Special note: the SSH3 backend

`spt`'s SSH3 transport (over QUIC + HTTP/3) is **experimental** and
tracks the in-progress `francoismichel/ssh3` reference implementation.
It is **excluded from the security scope** until SSH3 reaches
standards-track status. We will still accept reports against it on a
best-effort basis, but they will not be treated as embargoed
vulnerabilities and will not block a release.

## Accepted dependency advisories

The weekly `cargo audit` scan (`.github/workflows/audit.yml`) reports
RustSec advisories against our pinned dependencies. Most are triaged
by upgrading. A small number are **accepted risks** — suppressed in
`.cargo/audit.toml` (and mirrored as `--ignore` flags on the CI
invocation) with the justification recorded here. Every advisory *not*
in this list is still reported and opens the tracking issue.

| Advisory | Crate | Why accepted | Revisit when |
| -------- | ----- | ------------ | ------------ |
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) | `rsa` | RSA "Marvin Attack" timing side-channel. No fixed `rsa` release exists (both `rsa 0.9.x` and the `rsa 0.10.0-rc.*` prereleases are flagged). The attack is a timing oracle in RSA **PKCS#1 v1.5 decryption**, exploitable only when an attacker can submit chosen ciphertexts and measure decryption timing. `spt`'s RSA usage is **signing / verification only** — `spt-key`'s `RsaCertSigner` signs SSH certificates with an RSA CA, and `russh` uses RSA for SSH host-key / public-key *signatures*. We never expose an attacker-controlled RSA decryption oracle, so the vulnerable path is unreachable. Dropping RSA would remove real SSH / certificate capability. | A fixed `rsa` crate release ships (bump + remove the ignore entry), or `spt` ever starts performing RSA PKCS#1 v1.5 decryption. |

## Disclosure

After a fix ships we publish a brief advisory in the GitHub Security
tab with a CVE where applicable, the affected versions, and credit
to the reporter (unless they prefer to remain anonymous).
