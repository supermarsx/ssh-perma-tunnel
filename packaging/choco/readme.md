# spt — Chocolatey package

This directory holds the Chocolatey community-feed submission for **spt**
(SSH Permanent Tunnel). The package is an *installer wrapper*: at install
time it downloads the official MSI from the matching GitHub Release and
runs it silently.

## Layout

```
packaging/choco/
├── spt.nuspec                       # NuGet/Chocolatey package metadata
├── tools/
│   ├── chocolateyinstall.ps1        # Downloads + runs the MSI
│   ├── chocolateyuninstall.ps1      # Removes the MSI via auto-detected ProductCode
│   ├── chocolateybeforemodify.ps1   # Gracefully stops the spt service on upgrade/uninstall
│   ├── LICENSE.txt                  # MIT, copy of upstream license.md
│   └── VERIFICATION.txt             # Reviewer-facing integrity guide
└── readme.md                        # (this file)
```

## Build the .nupkg locally

From this directory:

```powershell
cd packaging\choco
choco pack
```

Output: `spt.<VERSION>.nupkg` in the current directory.

## Test the package locally

Install from the local source (no upload, no internet round-trip through
chocolatey.org), but the install.ps1 will still hit GitHub Releases for the
MSI:

```powershell
choco install spt -s . -y --version <VERSION>
```

To verify the wrapper without actually hitting the MSI download, run with
`--noop`:

```powershell
choco install spt -s . -y --noop
```

Uninstall test:

```powershell
choco uninstall spt -y
```

Upgrade test (requires two builds with different `<version>`):

```powershell
choco install spt -s . --version 26.1 -y
choco upgrade spt -s . --version 26.2 -y
```

`chocolateybeforemodify.ps1` will stop the `spt` Windows service (if
installed) before the upgrade swaps `spt.exe`.

## Push to the community feed

You need an API key from <https://community.chocolatey.org/account>:

```powershell
choco apikey --key <your-api-key> --source https://push.chocolatey.org/
choco push spt.<VERSION>.nupkg --source https://push.chocolatey.org/
```

## Community moderation flow

Chocolatey's public feed is **manually moderated**. Every submission and
every version bump is reviewed by a human moderator. The review typically
checks:

1. **Metadata sanity** — `id`, `version`, license URL, project URLs all
   resolve and aren't broken.
2. **Checksums present** — `Install-ChocolateyPackage` MUST supply
   `checksum64`/`checksumArm64` plus `checksumType`. Packages that download
   binaries without checksums are auto-rejected.
3. **VERIFICATION.txt** — Required whenever the package downloads binaries
   from a third-party URL. Tells the moderator exactly how to reproduce the
   checksum from upstream artifacts.
4. **LICENSE.txt** — Required next to `tools/`. We ship a literal copy of
   the upstream MIT license.
5. **No silent installers without `/qn`** — silentArgs must produce no UI.
6. **No 32-bit-only / no architecture-mismatched binaries** — we ship x64
   and ARM64.

Signed MSIs (Authenticode) substantially shorten the review queue and let
moderators verify provenance without re-running checksum math. spt's MSI
build (`packaging/msi/`) is signed when the release CI has access to the
code-signing certificate; see `packaging/signing.md`. The Chocolatey package
itself does NOT need to be signed — the MSI signature is what reviewers
trust transitively.

Expected timeline: 1–14 days from `choco push` to listing, depending on
moderator backlog and whether any review comments come back. Fix-then-resubmit
loops happen via the same `choco push` command with a bumped version (or by
replying to the moderator on the package's community page).

## Per-release bump checklist

Every time a new spt release is cut on GitHub:

| Step | File                          | Field                                          |
| ---- | ----------------------------- | ---------------------------------------------- |
| 1    | `spt.nuspec`                  | `<version>`                                    |
| 2    | `spt.nuspec`                  | `<releaseNotes>` (optional inline notes)       |
| 3    | `tools/chocolateyinstall.ps1` | `url64bit`  → new MSI URL with new tag         |
| 4    | `tools/chocolateyinstall.ps1` | `urlArm64` → new MSI URL with new tag          |
| 5    | `tools/chocolateyinstall.ps1` | `checksum64` → SHA-256 of new x64 MSI          |
| 6    | `tools/chocolateyinstall.ps1` | `checksumArm64` → SHA-256 of new ARM64 MSI     |
| 7    | `tools/VERIFICATION.txt`      | refresh `v<VERSION>` reference                 |

A scripted bumper lives at `scripts/release/bump-choco.ps1` (planned; see
`scripts/release/` for the sibling Homebrew/Scoop bumpers). It accepts the
new version + the two SHA-256s and rewrites the three files in place:

```powershell
pwsh scripts/release/bump-choco.ps1 -Version 0.2.0 `
    -Sha256X64 <hex> -Sha256Arm64 <hex>
```

Until that bumper is committed, do the edits by hand and re-run `choco pack`.

## Notes on the wrapper-vs-embed choice

Chocolatey allows two distribution styles:

1. **Embed the binary** in the .nupkg (must be < 200 MB; the moderators
   prefer this for small CLIs).
2. **Download + verify** at install time (what we do).

We picked (2) because:

- spt ships **two architectures** (x64 and ARM64); embedding both doubles
  the .nupkg size and forces two-step install logic anyway.
- The upstream MSI is **Authenticode-signed**; downloading the signed MSI
  preserves the signature chain end-to-end. Re-embedding it inside the
  .nupkg is fine but adds zero security and one extra round of moderator
  hash-checking.
- A **SHA256SUMS** file is published alongside every GitHub release; the
  hash that the .nupkg pins is cross-checkable against an independently
  signed (minisign) sums file, which is the strongest verification story
  Chocolatey supports today.
