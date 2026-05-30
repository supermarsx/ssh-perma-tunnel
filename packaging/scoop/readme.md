# Scoop packaging for `spt`

This directory holds the [Scoop](https://scoop.sh) manifest for **ssh-perma-tunnel**
(`spt`), the SSH/SSH3 permanent-tunnel supervisor.

The manifest is `spt.json`. It is written in the shape Scoop's **main** bucket
([ScoopInstaller/Main](https://github.com/ScoopInstaller/Main)) and **extras**
bucket ([ScoopInstaller/Extras](https://github.com/ScoopInstaller/Extras)) expect,
including `checkver`, `autoupdate`, per-architecture URLs, `shortcuts`,
`psmodule` (completions), and a `persist` block for the user's config dir.

---

## Quick install (no bucket required)

If you are testing a release candidate or running off a checkout:

```powershell
# from inside this directory
scoop install .\spt.json

# or by raw URL once the release tag is published
scoop install `
    https://raw.githubusercontent.com/supermarsx/ssh-perma-tunnel/v<VERSION>/packaging/scoop/spt.json
```

Scoop will:

1. Download the per-arch zip from the GitHub release.
2. Verify the SHA-256 from the manifest.
3. Unpack into `~\scoop\apps\spt\<VERSION>\<extract_dir>\`.
4. Link `spt.exe` into `~\scoop\shims\` (already on `PATH`).
5. Register a Start-Menu shortcut "spt — SSH Permanent Tunnel".
6. Symlink `~\scoop\persist\spt\.spt` -> `%USERPROFILE%\.spt` so your config
   survives `scoop update spt`.

To uninstall:

```powershell
scoop uninstall spt          # keeps persisted .spt
scoop uninstall -p spt       # purges persisted .spt too
```

---

## Running your own (internal / private) bucket

Operators that want a controlled rollout (corporate, air-gapped, pre-release
channel) should publish a private Scoop bucket rather than committing to
scoop-main directly.

A Scoop bucket is just a Git repo that contains a `bucket/` directory of
manifests. Minimal layout:

```
my-internal-bucket/
└── bucket/
    └── spt.json          <- copy of this file with concrete <VERSION> + hashes
```

End users add the bucket and install from it:

```powershell
scoop bucket add internal https://git.example.com/ops/scoop-bucket
scoop install internal/spt
```

To wire automatic update PRs against your bucket, add a GitHub Action that runs
`scoop checkver -u spt` on a schedule — the `checkver`/`autoupdate` blocks in
`spt.json` already drive that flow without any modification.

---

## Submitting to `scoop-main` or `scoop-extras`

Scoop has two upstream buckets that matter for public distribution:

| Bucket | Repo | Criteria |
|---|---|---|
| **Main** | [ScoopInstaller/Main](https://github.com/ScoopInstaller/Main) | CLI-only, OSS, no GUI, no installer, no admin rights required, no dependencies outside Scoop, ≥ a few hundred GitHub stars or comparable popularity. |
| **Extras** | [ScoopInstaller/Extras](https://github.com/ScoopInstaller/Extras) | Everything else that is OSS or has a free-to-use redistributable. GUIs, installers, niche tools land here. |

`spt` is a portable, dependency-free, CLI-only zip with no admin requirement
and a `bin` entry — i.e. it is a **Main candidate**. If popularity is the
blocker, target **Extras** first and migrate later.

### PR flow

1. **Fork** the target bucket (`ScoopInstaller/Main` or `ScoopInstaller/Extras`).

2. **Copy** `packaging/scoop/spt.json` into `bucket/spt.json` of your fork,
   *with `<VERSION>` and the two `<SHA256_WIN_*>` placeholders replaced by the
   real values from the latest GitHub release*. (See substitution table below.)

3. **Validate locally** before pushing:

   ```powershell
   # Scoop ships these helpers; clone the bucket repo first.
   .\bin\checkver.ps1 spt           # confirms checkver block works
   .\bin\checkurls.ps1 spt          # all URLs reachable
   .\bin\formatjson.ps1 spt         # canonicalises whitespace
   .\bin\test.ps1 -App spt          # end-to-end install/uninstall test
   ```

   Plus, parse as JSON:

   ```powershell
   Get-Content .\bucket\spt.json | python -m json.tool > $null
   ```

4. **Commit** with the exact message format the bucket expects:

   ```
   spt: Add version <VERSION>
   ```

   or for an update of an existing manifest:

   ```
   spt: Update to version <VERSION>
   ```

5. **Open a PR**. CI runs `Excavator` (the bucket bot) which re-runs
   `checkver -u`, lints, and tries an install on a Windows runner.

### Acceptance criteria (Scoop reviewers look for)

- Manifest is valid JSON (Excavator rejects malformed input).
- `version`, `description`, `homepage`, `license` are all present and accurate.
- Per-arch `url` + `hash` are present; hash is real SHA-256 of the artifact.
- `checkver` finds the latest tag and `autoupdate` regenerates a working
  manifest (Excavator runs `checkver -u <app>` and fails the PR if the diff
  isn't clean).
- `bin` (and/or `shortcuts`) is correct — the shim must actually launch.
- No PowerShell in `pre_install` / `installer` / `post_install` that requires
  admin, downloads extra binaries, or mutates global state outside `$dir` and
  `$persist_dir`.
- `persist` covers state that must outlive an upgrade.
- For Main: no GUI window, no dependency outside Scoop, single-zip download.

### Post-merge ongoing maintenance

Once merged, **Excavator** auto-opens PRs against the bucket whenever a new
GitHub release matching the `checkver` block appears. The maintainer's only
ongoing job is producing a release with:

- A tag `v<VERSION>`.
- Per-arch artefacts named exactly `spt-<VERSION>-x86_64-pc-windows-msvc.zip`
  and `spt-<VERSION>-aarch64-pc-windows-msvc.zip`.
- A `SHA256SUMS` file in the release containing one
  `<hash> *spt-<VERSION>-<triple>.zip` line per artefact (so the
  `autoupdate.hash` regex matches).

---

## Placeholder-substitution table

The manifest in this directory is a **template**: when shipping a release,
substitute every placeholder before committing to a bucket repo.

| Placeholder | Where it appears | Replace with | Example |
|---|---|---|---|
| `<VERSION>` | `version`, both `architecture.*.url`, both `architecture.*.extract_dir` | The release version, without the leading `v`. | `1.4.0` |
| `<SHA256_WIN_AMD64>` | `architecture.64bit.hash` | SHA-256 of `spt-<VERSION>-x86_64-pc-windows-msvc.zip`. | `a1b2c3...` (64 hex chars) |
| `<SHA256_WIN_ARM64>` | `architecture.arm64.hash` | SHA-256 of `spt-<VERSION>-aarch64-pc-windows-msvc.zip`. | `f9e8d7...` (64 hex chars) |

You do **not** need to touch the `$version`-prefixed values inside the
`autoupdate` block — those are Scoop variables, expanded by `scoop checkver -u`
at update time. They must remain literal strings in source.

### One-shot substitution (PowerShell)

```powershell
$ver  = '1.4.0'
$h64  = (Get-FileHash -Algorithm SHA256 .\spt-$ver-x86_64-pc-windows-msvc.zip).Hash.ToLower()
$ha64 = (Get-FileHash -Algorithm SHA256 .\spt-$ver-aarch64-pc-windows-msvc.zip).Hash.ToLower()

(Get-Content packaging\scoop\spt.json -Raw) `
    -replace '<VERSION>',            $ver  `
    -replace '<SHA256_WIN_AMD64>',   $h64  `
    -replace '<SHA256_WIN_ARM64>',   $ha64 |
    Set-Content bucket\spt.json -Encoding utf8
```

### One-shot substitution (sh / git-bash)

```bash
VER=1.4.0
H64=$(sha256sum spt-$VER-x86_64-pc-windows-msvc.zip   | awk '{print $1}')
HA64=$(sha256sum spt-$VER-aarch64-pc-windows-msvc.zip | awk '{print $1}')

sed -e "s|<VERSION>|$VER|g"             \
    -e "s|<SHA256_WIN_AMD64>|$H64|g"    \
    -e "s|<SHA256_WIN_ARM64>|$HA64|g"   \
    packaging/scoop/spt.json > bucket/spt.json
```

---

## Notes on the manifest's design choices

- **`depends: []`** — `spt` ships a fully static MSVC build (rustls + ring,
  no OpenSSL dependency, no MSVC runtime DLL beyond what Windows already
  carries). The only thing a user might *want* alongside is OpenSSH for ad-hoc
  `ssh-keygen` / `ssh-keyscan` use, surfaced as a non-mandatory `suggest`.
  If a future build switches to a CNG-backed crypto stack that requires a
  redistributable, add `"depends": ["main/vcredist2022"]` here.

- **`extract_dir`** — every release zip extracts into a top-level
  `spt-<VERSION>-<triple>/` directory (the GitHub release naming convention).
  Without `extract_dir`, the `bin` and `shortcuts` paths would be relative to
  the wrong root.

- **`shortcuts`** — registers `spt.exe` in the Start Menu under
  "spt — SSH Permanent Tunnel". Scoop applies this for both 64-bit and arm64.

- **`psmodule`** — the manifest writes generated completions to
  `spt.psm1` in the install dir; the `psmodule` block makes Scoop link
  that file into the user's `Modules` path so `Import-Module spt`
  (or auto-import in PowerShell 5+) picks up the completions.

- **`persist: [".spt"]`** — by default Scoop blasts the install dir on every
  upgrade. Persisting `.spt` (which `post_install` symlinks to
  `%USERPROFILE%\.spt`) keeps `spt.toml`, the secret store, and the supervisor
  state intact across `scoop update spt`.

- **`env_add_path: "."`** — exposes the install dir on `PATH` (in addition to
  the shim) so PowerShell completions and the `psmodule` autoload can find
  `spt.exe`.
