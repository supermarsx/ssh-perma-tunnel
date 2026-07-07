# Software supply chain

`spt` treats its dependency graph as part of its attack surface. Three
mechanisms guard it, layered from broad-and-informational to
narrow-and-gating:

| Mechanism | Tool | Trigger | Gating? |
|---|---|---|---|
| Vulnerability feed | `cargo audit` | Weekly cron + manual | No — opens a tracking issue |
| Policy gate | `cargo deny` | Every push to `main` + every PR | **Yes** — blocks the merge |
| Provenance | `cargo cyclonedx` | Every push to `main` + every PR | No — uploads an SBOM artifact |

The gating check lives in `.github/workflows/supply-chain.yml`; the weekly feed
lives in `.github/workflows/audit.yml`.

## Dependency graph at a glance

- **41 workspace crates** (the `spt-*` crates plus a few test/bench helpers),
  resolving to roughly **775 external components** in `Cargo.lock`.
- **Every dependency resolves from crates.io.** There are no `git`, `path`
  (other than intra-workspace), or private-registry sources. The
  `cargo deny` `sources` check enforces that this stays true.
- **Licenses are uniformly permissive** — overwhelmingly `MIT` and
  `Apache-2.0`, plus BSD/ISC/Zlib/Unicode/Unlicense and a handful of
  public-domain dedications. The only weak-copyleft entries are two leaf crates
  under `MPL-2.0` (`option-ext`, `smartstring`), which are consumed unmodified
  (file-level copyleft imposes no obligation on `spt`'s own code).
- **Duplicate versions exist and are tolerated as warnings.** `russh 0.61`
  pulls the RustCrypto *pre-release* line (`aead 0.6`, `aes-gcm 0.11-rc`,
  `ssh-key 0.7-rc`, `der 0.8`, `sha2 0.11`, `rsa 0.10-rc`, …) alongside the
  stable RustCrypto line used elsewhere, and the several `windows` /
  `windows-sys` generations are pulled by different transitive deps. These are
  unavoidable until the upstream crypto stack stabilises, so they warn rather
  than fail.

## cargo-audit (weekly, non-gating)

`cargo audit` reads the committed `Cargo.lock` against the RustSec advisory
database. It runs on a weekly cron and on manual dispatch — never on `push` or
`pull_request` — and on findings it opens or updates a single tracking issue
instead of failing a required check. Its accepted-risk suppressions live in
`.cargo/audit.toml`. See [Security](security.md) → *Accepted dependency
advisories* for the rationale of each.

## cargo-deny (gating)

`cargo deny check` runs all four checks against `deny.toml` on every push and
PR. A violation fails the job and blocks the merge.

### `advisories`

Re-runs the RustSec scan as a **gate** (fail-fast) rather than an issue feed.
Vulnerabilities and yanked crates fail the build. The only escape hatch is the
explicit, per-ID `ignore` list in `deny.toml`, kept in sync with
`.cargo/audit.toml`. Currently accepted:

| Advisory | Crate | Class | Why accepted |
|---|---|---|---|
| `RUSTSEC-2023-0071` | `rsa` | vuln | Marvin timing oracle in RSA *decryption*; `spt` only *signs/verifies*. No fixed release exists. |
| `RUSTSEC-2026-0204` | `crossbeam-epoch` | vuln | Null-pointer deref only in the `Display` impl, which `moka`/`hickory` never call. **Temporary** — real fix is `cargo update -p crossbeam-epoch` (≥ 0.9.20). |
| `RUSTSEC-2025-0134` | `rustls-pemfile` | unmaintained | Frozen compatibility shim re-exporting `rustls-pki-types`; no defect. |
| `RUSTSEC-2023-0037` | `xsalsa20poly1305` | unmaintained | Rename to `crypto_secretbox`; no vulnerability, no safe upgrade for the old name. |

Each ignore carries a full, in-file justification and a "revisit when" note.

### `licenses`

An **allow-list** of exactly the SPDX licenses present in the current graph
(MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, 0BSD, Unlicense, Unicode-3.0,
Unicode-DFS-2016, BSL-1.0, CC0-1.0, WTFPL, CDLA-Permissive-2.0, and MPL-2.0).
Any crate whose license is not satisfiable from this set fails the check, so a
new copyleft or unknown license surfaces for a fresh review instead of sliding
in under a blanket allow.

### `bans`

Duplicate versions are a **warning** (see the graph note above). Wildcard
(`*`) version requirements are **denied** — a `*` dep is a supply-chain blank
cheque — with an exemption only for intra-workspace `path` crates.

### `sources`

Only the crates.io registry is allowed. Unknown registries and any `git`
source are **denied**, so a dependency cannot be silently repointed at an
unaudited source.

## SBOM (CycloneDX)

The `sbom` job generates a **CycloneDX 1.3 JSON** Software Bill of Materials
with `cargo cyclonedx` (one SBOM per workspace member, all features, all target
platforms) and uploads them as the `cyclonedx-sbom` build artifact (90-day
retention). The SBOM enumerates every component + version + license and lets
downstream consumers correlate `spt` against new CVEs without re-resolving the
build.

## MSRV / pinned-toolchain policy

Both jobs pin the repo's single contract toolchain, **Rust 1.88**, and neither
runs `cargo update`: they read the committed `Cargo.lock` as-is, so results
describe exactly what `spt` ships. `cargo-deny` is pinned to `0.19.9` (0.17 and
earlier cannot parse the CVSS v4.0 advisory entries now in the RustSec DB);
`cargo-cyclonedx` is pinned to `0.5.7`.

## Running the checks locally

```sh
# Install the tools (pinned to the CI versions).
cargo install cargo-deny --version 0.19.9 --locked
cargo install cargo-cyclonedx --version 0.5.7 --locked
cargo install cargo-audit --locked   # optional; matches the weekly workflow

# Full supply-chain gate (advisories + licenses + bans + sources).
cargo deny --all-features check --show-stats

# Individual sections.
cargo deny check advisories
cargo deny check licenses
cargo deny check bans
cargo deny check sources

# Generate the SBOM set (writes <crate>.cdx.json next to each Cargo.toml).
cargo cyclonedx --format json --all --target all --all-features

# Weekly advisory feed, run on demand (mirrors .cargo/audit.toml).
cargo audit
```

A clean run prints `advisories ok, bans ok, licenses ok, sources ok` and exits
`0`. Duplicate-version warnings under `bans` are expected and do not fail the
gate.
