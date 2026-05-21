# Flathub submission set for `io.spt.spt`

This directory contains the complete, submission-ready Flathub manifest set
for spt. The legacy starter manifest in `packaging/flatpak/` predates this
directory and is kept only for local one-off builds; Flathub submissions
must always use the files here.

## Layout

```
packaging/flathub/
|-- io.spt.spt.yaml             # top-level manifest
|-- io.spt.spt.metainfo.xml     # AppStream metainfo
|-- io.spt.spt.desktop          # XDG .desktop entry
|-- flathub.json                # Flathub side-channel metadata (only-arches)
|-- icons/
|   |-- 64x64/io.spt.spt.png
|   |-- 128x128/io.spt.spt.png
|   |-- 256x256/io.spt.spt.png
|   `-- scalable/io.spt.spt.svg
|-- modules/
|   `-- spt-build.yaml          # cargo --offline build module
`-- readme.md
```

## Placeholder substitution table

Every release these tokens must be rewritten in-place. The script
`scripts/release/update-packaging.sh` does this automatically; the
table is here for manual / one-off operations.

| Token                 | Where                              | Source                                     |
|-----------------------|------------------------------------|--------------------------------------------|
| `<VERSION>`           | `io.spt.spt.yaml`, `modules/*.yaml`| The release tag minus the leading `v`.     |
| `<SHA256_SRC_TAR>`    | `modules/spt-build.yaml`           | `sha256sum spt-<VERSION>.tar.gz`.          |
| `<SHA256_VENDOR_TAR>` | `modules/spt-build.yaml`           | `sha256sum spt-<VERSION>-vendor.tar.xz`.   |
| `@VERSION@`           | `io.spt.spt.metainfo.xml`          | Same as `<VERSION>`.                       |
| `@RELEASE_DATE@`      | `io.spt.spt.metainfo.xml`          | `date -u +%Y-%m-%d` at tag time.           |

After substitution, the working tree must contain no `<` or `@`-wrapped
tokens in any `packaging/flathub/**` file. Verify with:

```sh
grep -RnE '<VERSION>|<SHA256_[A-Z_]+>|@VERSION@|@RELEASE_DATE@' packaging/flathub/ \
  && { echo "unfilled tokens remain"; exit 1; } || true
```

## Vendoring sources for the offline build

Flathub forbids network access during the build phase. To satisfy
`cargo --offline build --locked`, we ship a vendored sources tarball
alongside the GitHub release tag.

Reproducer (run from the repository root on a clean checkout of the
release tag):

```sh
cargo vendor --locked vendor > .cargo/config.toml
tar --sort=name --owner=0 --group=0 --numeric-owner \
    -cJf "spt-${VERSION}-vendor.tar.xz" vendor .cargo/config.toml
sha256sum "spt-${VERSION}-vendor.tar.xz"
```

Upload `spt-${VERSION}-vendor.tar.xz` to the GitHub release page so that
the URL referenced by `modules/spt-build.yaml` resolves. The
`.cargo/config.toml` written by `cargo vendor` looks like:

```toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

`strip-components: 0` in the source entry preserves the `vendor/` and
`.cargo/` paths so cargo finds them at the repository root inside the
sandbox.

## Local test build

```sh
# Install the SDKs once.
flatpak install --user flathub \
    org.freedesktop.Platform//23.08 \
    org.freedesktop.Sdk//23.08 \
    org.freedesktop.Sdk.Extension.rust-stable//23.08

# Build + install into the user remote.
flatpak-builder --user --install --force-clean \
    build-dir packaging/flathub/io.spt.spt.yaml

# Run it.
flatpak run io.spt.spt --version
```

To rebuild without re-downloading sources, add `--ccache --keep-build-dirs`.

## Manifest validation

```sh
# AppStream (Flathub accepts the relaxed ruleset).
appstream-util validate-relax packaging/flathub/io.spt.spt.metainfo.xml

# Desktop entry.
desktop-file-validate packaging/flathub/io.spt.spt.desktop

# Manifest dependency dump (sanity check that all sources resolve).
flatpak-builder --show-deps packaging/flathub/io.spt.spt.yaml

# Manifest lint via flatpak-builder dry-run.
flatpak-builder --download-only --force-clean \
    build-dir packaging/flathub/io.spt.spt.yaml

# JSON sanity.
python -m json.tool packaging/flathub/flathub.json > /dev/null
```

For a heavier check, run `flatpak run --command=appstream-util org.flatpak.Builder validate ...`
inside the official `org.flatpak.Builder` flatpak.

## Icon regeneration

The committed PNGs were rendered from the SVG with the .NET
`System.Drawing` API on Windows during initial bring-up. To regenerate
them on a Linux host (matching what Flathub graders will see), use
either ImageMagick or Inkscape:

```sh
# ImageMagick (rsvg-convert preferred for quality).
for s in 64 128 256; do
  rsvg-convert -w $s -h $s \
      packaging/flathub/icons/scalable/io.spt.spt.svg \
      -o packaging/flathub/icons/${s}x${s}/io.spt.spt.png
done

# Inkscape fallback.
for s in 64 128 256; do
  inkscape --export-type=png --export-width=$s --export-height=$s \
      --export-filename=packaging/flathub/icons/${s}x${s}/io.spt.spt.png \
      packaging/flathub/icons/scalable/io.spt.spt.svg
done
```

The committed icons are intentionally minimal ("spt" wordmark on a
solid square) so the manifest validates and screenshots render without
pulling external brand assets. Swap in the final brand mark before
public submission.

## Flathub submission flow

Flathub uses a per-app repository under the `flathub` org. Submission
is a GitHub PR to `flathub/flathub` (the index) followed by an
application repository.

1. **Fork the index.** Fork <https://github.com/flathub/flathub> and
   create a branch named `new-pr/io.spt.spt`.
2. **Open the new-application PR.** Use the
   [`new-app.yml`](https://github.com/flathub/flathub/blob/master/.github/ISSUE_TEMPLATE/new-app.yml)
   issue template. Link to this README and to the latest GitHub release
   tag. Note that the binary is console-only and that the manifest uses
   the `rust-stable` SDK extension.
3. **Wait for an Application repo.** Once the new-app PR is approved,
   a Flathub admin creates `flathub/io.spt.spt`. Push the contents of
   this directory there, preserving paths:
   ```sh
   git clone git@github.com:flathub/io.spt.spt.git
   cp -a packaging/flathub/. io.spt.spt/
   cd io.spt.spt
   git add -A && git commit -m "Initial submission of spt v<VERSION>"
   git push -u origin main
   ```
4. **Open the build PR** against the `master` branch of
   `flathub/io.spt.spt`. The Flathub buildbot will produce a test
   build; iterate until it is green.
5. **Per-release updates.** Subsequent releases bump only the version,
   the two SHA256s, and the `<releases>` block. The
   `scripts/release/update-packaging.sh` helper does this in-tree;
   copy the regenerated `packaging/flathub/` contents over the
   `flathub/io.spt.spt` checkout and open a new PR.

A starter PR description template:

```markdown
### Update spt to v<VERSION>

- Source tarball SHA256: `<SHA256_SRC_TAR>`
- Vendor tarball SHA256: `<SHA256_VENDOR_TAR>`
- Release notes: https://github.com/Mariana/ssh-perma-tunnel/releases/tag/v<VERSION>

The manifest builds against `org.freedesktop.Platform//23.08`. All
crates resolve offline from the vendored sources tarball.
```

## Open items / operator handoff

- **Screenshots.** The `<screenshots>` block in `io.spt.spt.metainfo.xml`
  references paths under `docs/screenshots/`. Capture and commit the
  PNGs before the first Flathub PR is opened, or temporarily remove the
  block from the metainfo.
- **Final brand icon.** Replace the placeholder SVG/PNGs with the
  designed mark when available; keep the filenames.
- **Tag-time release notes.** The metainfo `<releases>` block contains
  one historical 0.1.0 entry and one templated `@VERSION@` slot. Every
  new release prepends a new `<release>` and rewrites the template
  slot; the script handles both.
