# Windows Package Manager (winget) packaging for spt

This directory holds the winget manifests for `Mariana.spt`, laid out exactly
the way [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs)
expects them so the contents can be lifted into a fork and submitted as-is.

## Layout

```
packaging/winget/
├── README.md                           — this file
├── spt.yaml.legacy                     — old singleton, kept only as a
│                                         redirect for any local scripts
│                                         that still reference it
└── manifests/
    └── m/
        └── Mariana/
            └── spt/
                └── 0.1.0/
                    ├── Mariana.spt.installer.yaml
                    ├── Mariana.spt.locale.en-US.yaml
                    └── Mariana.spt.yaml          (version manifest)
```

The `manifests/m/Mariana/spt/<VERSION>/` path mirrors the exact directory
structure used inside the upstream `winget-pkgs` repo
(`manifests/<first-letter-of-publisher-lowercased>/<Publisher>/<Package>/<Version>/`).
Copying the `0.1.0/` directory straight into a fork at
`manifests/m/Mariana/spt/0.1.0/` is the entire mechanical step of a
submission.

## Per-release placeholder substitution

`scripts/release/bump-winget.sh <NEW_VERSION>` (referenced by the release
pipeline) clones the previous version directory to a new one and rewrites
the following placeholders in every file:

| Placeholder            | Source                                                                  |
|------------------------|-------------------------------------------------------------------------|
| `<VERSION>`            | The new release tag without the leading `v` (e.g. `0.2.0`).             |
| `<SHA256_WIN_AMD64>`   | `sha256sum spt-<VERSION>-x86_64-pc-windows-msvc.msi`.                   |
| `<SHA256_WIN_ARM64>`   | `sha256sum spt-<VERSION>-aarch64-pc-windows-msvc.msi`.                  |
| `<RELEASE_DATE>`       | UTC release date, `YYYY-MM-DD`.                                         |
| `<PRODUCT_CODE_X64>`   | `msiinfo export ... Property` → `ProductCode` row (uppercase GUID).     |
| `<PRODUCT_CODE_ARM64>` | Same, for the ARM64 MSI.                                                |
| `<RELEASE_NOTES>`      | First section of `CHANGELOG.md` for the new version (≤ 10000 chars).    |

The bump script also renames the directory from
`manifests/m/Mariana/spt/<OLD>/` to `manifests/m/Mariana/spt/<NEW>/` and
updates every `PackageVersion:` field, every URL containing the old version,
and the `0.1.0/` segment of every `InstallerUrl`.

## Local validation

The Microsoft `winget` client ships a manifest validator. Run it against the
populated (placeholders-substituted) directory before opening a PR:

```powershell
winget validate --manifest packaging/winget/manifests/m/Mariana/spt/0.1.0/
```

Smoke-test the install end-to-end from the local manifest:

```powershell
winget install --manifest packaging/winget/manifests/m/Mariana/spt/0.1.0/
```

For schema-only validation without `winget` installed (CI sanity check),
fetch the JSON Schemas referenced in each file's
`# yaml-language-server: $schema=...` comment and run any
`ajv`/`check-jsonschema`-style validator.

## winget-pkgs submission flow

Microsoft recommends [`wingetcreate`](https://github.com/microsoft/winget-create)
for end-to-end submissions; it handles cloning, branching, and the PR. The
short version:

1. Install: `winget install Microsoft.WingetCreate`.
2. Update an existing package:
   ```powershell
   wingetcreate update Mariana.spt `
     --version 0.1.0 `
     --urls https://github.com/Mariana/ssh-perma-tunnel/releases/download/v0.1.0/spt-0.1.0-x86_64-pc-windows-msvc.msi `
            https://github.com/Mariana/ssh-perma-tunnel/releases/download/v0.1.0/spt-0.1.0-aarch64-pc-windows-msvc.msi `
     --submit
   ```
   `wingetcreate` pulls the latest manifests, swaps in the new URLs/hashes,
   validates, forks `microsoft/winget-pkgs`, commits, and opens the PR.
3. For the first-ever submission (package not yet in winget-pkgs), use
   `wingetcreate new <InstallerUrl>` and answer the prompts. The resulting
   manifests should match the structure in this directory.

Manual flow (no `wingetcreate`), if needed:

1. Fork https://github.com/microsoft/winget-pkgs.
2. Create a branch `Mariana.spt-<VERSION>`.
3. Copy `packaging/winget/manifests/m/Mariana/spt/<VERSION>/` (after
   placeholder substitution) into the fork at the same relative path.
4. `winget validate --manifest manifests/m/Mariana/spt/<VERSION>/`.
5. Commit, push, open a PR titled
   `New version: Mariana.spt version <VERSION>`. The validation pipeline
   in winget-pkgs runs automatically and approves/labels.

## Per-user installs

The installer manifest declares `Scope: machine` because the MSI registers
the Windows service via the SCM, which requires per-machine state. Users
who want a per-user install (no service, no admin elevation) can pass
`--scope user` on the `winget install` invocation; the MSI's WiX authoring
detects `MSIINSTALLPERUSER=1` and skips the service component. We do not
ship a separate per-user installer entry in the manifest — the same MSI
handles both scopes.

## Why the layout has both `m/` and `Mariana/`

`winget-pkgs` shards by the lowercased first letter of the publisher to
keep directory listings manageable. `Mariana` starts with `M`, so the
shard is `m/`. Do not change the casing of `Mariana/` itself — winget is
case-sensitive about the package identifier components.
