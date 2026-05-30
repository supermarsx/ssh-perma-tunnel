# Packaging

This directory holds every distribution-format definition for `spt`. Each
sub-directory is a self-contained manifest/template; the existing OS-native
formats (`deb/`, `rpm/`, `msi/`, `pkg/`, plus service units under
`systemd/`, `launchd/`, `openrc/`, `sysv/` and man pages under `man/`) are
produced by CI from the metadata in
`crates/spt-bin/Cargo.toml`. Generated man pages and shell completions are
committed under `man/` and `completions/` so every package can ship the same
CLI surface. The newer entries (homebrew, scoop, AUR, snap, flatpak, winget,
nix) are templated manifests that a release script fills in after artifacts
have been uploaded.

## Status matrix

| Format    | Path                                  | Status                | Hosted on                  |
|-----------|---------------------------------------|-----------------------|----------------------------|
| deb       | `packaging/deb/`                      | stable (built in CI)  | GitHub Releases            |
| rpm       | `packaging/rpm/`                      | stable (built in CI)  | GitHub Releases            |
| msi       | `packaging/msi/`                      | stable (built in CI)  | GitHub Releases            |
| pkg       | `packaging/pkg/`                      | stable (built in CI)  | GitHub Releases            |
| Homebrew  | `packaging/homebrew/spt.rb`           | community-maintained  | tap (later: homebrew-core) |
| Scoop     | `packaging/scoop/spt.json`            | community-maintained  | bucket (later: ScoopInstaller/Main) |
| AUR       | `packaging/aur/PKGBUILD`              | community-maintained  | aur.archlinux.org/spt      |
| AUR (bin) | `packaging/aur/PKGBUILD-bin`          | community-maintained  | aur.archlinux.org/spt-bin  |
| Snap      | `packaging/snap/snapcraft.yaml`       | alpha                 | snapcraft.io               |
| Flatpak   | `packaging/flatpak/io.spt.spt.yaml`   | alpha                 | Flathub                    |
| winget    | `packaging/winget/spt.yaml`           | alpha                 | microsoft/winget-pkgs      |
| Nix       | `packaging/nix/default.nix`           | alpha                 | nixpkgs / overlay          |

"Alpha" means the manifest is shipped in-tree and validated, but the
package has not yet been accepted by the upstream registry. "Community-
maintained" means a tap/bucket/AUR entry exists but is not part of the
canonical core distro repos.

## End-user installation

```bash
# Homebrew (macOS / Linux)
brew install Mariana/tap/spt

# Scoop (Windows)
scoop bucket add spt https://github.com/supermarsx/scoop-spt
scoop install spt

# AUR (Arch Linux)
yay -S spt          # source build
yay -S spt-bin      # pre-built binary

# Snap
sudo snap install spt

# Flatpak
flatpak install flathub io.spt.spt

# winget (Windows)
winget install Mariana.spt

# Nix
nix-env -iA nixpkgs.spt        # once accepted into nixpkgs
nix-build packaging/nix        # in-tree build
```

`deb`, `rpm`, `msi`, and `pkg` artifacts are attached directly to each
GitHub Release; install them with the OS-native tool (`apt`, `dnf`,
`msiexec`, `installer`).

## Placeholders

All templated manifests use the same set of placeholder tokens. A single
release script (see `scripts/release/`) is responsible for substituting
them after uploading artifacts to a GitHub Release.

| Placeholder            | Where it lives                                                   | How to compute                                                             |
|------------------------|------------------------------------------------------------------|----------------------------------------------------------------------------|
| `<VERSION>`            | every manifest                                                   | release tag without the leading `v`                                        |
| `<RELEASE_DATE>`       | flatpak metainfo (as `@RELEASE_DATE@`), winget                   | `date -u +%Y-%m-%d`                                                        |

> The Flatpak AppStream metainfo XML uses `@VERSION@` and `@RELEASE_DATE@`
> instead of the `<VERSION>` / `<RELEASE_DATE>` form because the angle-
> bracket form is not well-formed inside XML attributes. The release script
> must substitute both spellings.
| `<SHA256_LINUX_AMD64>` | homebrew, AUR-bin                                                | `sha256sum spt-<VERSION>-x86_64-unknown-linux-gnu.tar.gz`                  |
| `<SHA256_LINUX_ARM64>` | homebrew, AUR-bin                                                | `sha256sum spt-<VERSION>-aarch64-unknown-linux-gnu.tar.gz`                 |
| `<SHA256_MACOS_AMD64>` | homebrew                                                         | `shasum -a 256 spt-<VERSION>-x86_64-apple-darwin.tar.gz`                   |
| `<SHA256_MACOS_ARM64>` | homebrew                                                         | `shasum -a 256 spt-<VERSION>-aarch64-apple-darwin.tar.gz`                  |
| `<SHA256_WIN_AMD64>`   | scoop, winget                                                    | `sha256sum spt-<VERSION>-x86_64-pc-windows-msvc.{zip,msi}`                 |
| `<SHA256_WIN_ARM64>`   | scoop, winget                                                    | `sha256sum spt-<VERSION>-aarch64-pc-windows-msvc.{zip,msi}`                |
| `<SHA256_SRC_TAR>`     | AUR (source), flatpak                                            | `sha256sum v<VERSION>.tar.gz` (GitHub source archive)                      |
| `<NIX_HASH>`           | nix                                                              | `nix-prefetch-github Mariana ssh-perma-tunnel --rev v<VERSION>`            |

> **Gap:** `scripts/release/` does not yet substitute these placeholders in
> the homebrew/scoop/AUR/snap/flatpak/winget/nix manifests. The current
> CI release flow only produces and uploads the binary artifacts. Add a
> step (e.g. `scripts/release/update-packaging.sh`) that, after the
> Release is created:
>
> 1. Downloads SHA256SUMS from the Release.
> 2. Runs `sed`/`yq` substitutions against each templated file in
>    `packaging/`.
> 3. Pushes the updated manifest to the appropriate registry (tap, bucket,
>    AUR, Flathub, snapcraft, winget-pkgs, nixpkgs) — see "Submission" below.
> 4. For AUR, regenerates `.SRCINFO` via `makepkg --printsrcinfo`.

## Submission to upstream registries

### Homebrew
- **Now:** publish to a personal tap (`Mariana/homebrew-tap`); users add
  it via `brew tap Mariana/tap`.
- **Later:** open a PR against `Homebrew/homebrew-core` once the project
  meets the [acceptable-formula](https://docs.brew.sh/Acceptable-Formulae)
  criteria (notable, stable, ≥30 days since first release, etc.).

### Scoop
- **Now:** publish to a bucket repo (`Mariana/scoop-spt`).
- **Later:** open a PR to `ScoopInstaller/Main` once usage is established.

### AUR
- One-time: create the AUR accounts `spt` and `spt-bin`, push the
  PKGBUILD + `.SRCINFO`. Subsequent releases are `git push` updates.
- Reference: <https://wiki.archlinux.org/title/AUR_submission_guidelines>.

### winget
- Fork [`microsoft/winget-pkgs`](https://github.com/microsoft/winget-pkgs).
- Place the manifest at `manifests/m/Mariana/spt/<VERSION>/`. The
  singleton form in this repo is a starting point; convert to the
  multi-file form (`Mariana.spt.installer.yaml`,
  `Mariana.spt.locale.en-US.yaml`, `Mariana.spt.yaml`) before opening
  the PR. `wingetcreate` automates this.
- Validate with `winget validate --manifest <path>` and
  `winget install --manifest <path>` before submitting.

### Flathub
- Fork [`flathub/flathub`](https://github.com/flathub/flathub) (the
  `new-pr` branch) with `io.spt.spt.yaml` + `io.spt.spt.metainfo.xml`.
- Validate locally:
  `flatpak-builder --force-clean build-dir packaging/flatpak/io.spt.spt.yaml`.
- AppStream: `appstream-util validate-relax io.spt.spt.metainfo.xml`.

### Snapcraft
- `snapcraft register spt` (one-time, requires Ubuntu One account).
- `snapcraft` (build), `snapcraft upload --release=stable spt_*.snap`.

### nixpkgs
- Fork [`NixOS/nixpkgs`](https://github.com/NixOS/nixpkgs).
- Add `pkgs/by-name/sp/spt/package.nix` re-exporting this `default.nix`
  (or copy and inline). Add a `meta.maintainers` entry.
- Validate: `nix-build -A spt` from your nixpkgs checkout.

## Maintainer workflow per release

1. Tag a release; CI builds and uploads artifacts to GitHub Releases.
2. Run `scripts/release/update-packaging.sh <VERSION>` (see gap note
   above — add this script if it does not exist yet). It:
   - Computes every SHA referenced in the placeholder table.
   - `sed`-substitutes placeholders into the templated manifests.
   - Regenerates `packaging/aur/.SRCINFO`.
   - Commits the updated manifests on a release branch.
3. For each registry: open the corresponding PR / push to the AUR / run
   `snapcraft upload`. The script can do this automatically if the
   appropriate credentials are present in the CI environment.

## Files in this directory

```
packaging/
├── deb/                     existing — cargo-deb maintainer scripts
├── rpm/                     existing — cargo-generate-rpm metadata
├── msi/                     existing — cargo-wix templates
├── pkg/                     existing — macOS .pkg scaffolding
├── systemd/                 existing — spt.service unit
├── launchd/                 existing — io.spt.spt.plist
├── openrc/                  existing — OpenRC init script
├── sysv/                    existing — SysV init script
├── man/                     existing — generated man pages
├── completions/             existing — generated bash/zsh/fish/PowerShell/Elvish completions
├── homebrew/spt.rb          new      — Homebrew formula
├── scoop/spt.json           new      — Scoop manifest
├── aur/PKGBUILD             new      — AUR source-build PKGBUILD
├── aur/PKGBUILD-bin         new      — AUR pre-built binary PKGBUILD
├── aur/.SRCINFO             new      — AUR metadata (generated)
├── snap/snapcraft.yaml      new      — Snap manifest
├── flatpak/io.spt.spt.yaml  new      — Flatpak manifest
├── flatpak/io.spt.spt.metainfo.xml  new — AppStream metainfo
├── winget/spt.yaml          new      — winget singleton manifest
├── nix/default.nix          new      — Nix package
├── signing.md               existing — release signing process
└── readme.md                this file
```
