# Releasing `spt`

Operator runbook for cutting an `spt` release. The process is fully
tag-driven: pushing an annotated `vX.Y.Z` tag to `main` triggers
[`release.yml`](.github/workflows/release.yml) and, in parallel,
[`docker.yml`](.github/workflows/docker.yml).

## 1. Pre-flight checklist

Before tagging, confirm every box on this list:

- [ ] Working tree is clean (`git status` shows nothing).
- [ ] You are on `main` and up to date with `origin/main`.
- [ ] CI on `main` is green for the commit you intend to tag — check
      `ci.yml`, `msrv.yml`, `audit.yml`, and `coverage.yml`.
- [ ] Workspace `version` in the root `Cargo.toml` matches the tag you
      are about to push (no trailing `-dev` or `-pre`).
- [ ] `Cargo.lock` was regenerated against the new version (run
      `cargo build --workspace --locked` and commit the lockfile churn,
      if any).
- [ ] [`CHANGELOG.md`](CHANGELOG.md) has a dated `## [X.Y.Z]` section
      and the `## [Unreleased]` section is empty (or only has entries
      that are deferred to the next release — be explicit).
- [ ] The man-page regenerator produces no diff:
      `cargo run --bin spt-mangen -- --out packaging/man` and
      `git diff --exit-code packaging/man/`.
- [ ] Spec version field in `spec.md` matches the release version.

## 2. Tag the release

Use an annotated, signed tag. The tag message should be the
`## [X.Y.Z]` section from the changelog, verbatim.

```sh
git tag -s vX.Y.Z -m "spt vX.Y.Z" -m "$(awk '/^## \[X.Y.Z\]/,/^## \[/' CHANGELOG.md | head -n -1)"
git push origin vX.Y.Z
```

## 3. Watch the release pipeline

Pushing the tag fires two workflows:

- [`release.yml`](.github/workflows/release.yml) — cross-builds the
  eight supported targets, produces `.deb`, `.rpm`, `.pkg`, and `.msi`
  artifacts, signs them (minisign + per-OS code signing), generates
  the SBOM and provenance, and creates a **draft** GitHub release.
- [`docker.yml`](.github/workflows/docker.yml) — builds and publishes
  multi-arch container images to GHCR.

Both workflows must finish green. If either fails, **delete the tag**
(`git tag -d vX.Y.Z && git push --delete origin vX.Y.Z`), fix the
underlying issue on `main`, and re-tag.

## 4. Verify draft release artifacts

On the draft release page:

- Confirm all expected artifacts are attached (one per target plus
  signatures, checksums, SBOM).
- Pull at least one binary per OS family (Linux x86_64, macOS arm64,
  Windows x86_64) and run a smoke test:
  - `spt --version` reports `X.Y.Z`.
  - `spt config validate --config examples/minimal.toml` succeeds.
  - `spt diagnose --redact strict` produces a bundle with no obvious
    redaction misses.
- Verify one signature with `minisign -V` against the published public
  key.

## 5. Promote the draft

Once smoke tests pass, click **Publish release** on the draft. This
makes the tag visible in package indexes and triggers any downstream
notification channels.

## 6. Confirm Docker images

`docker.yml` runs in parallel and publishes:

- `ghcr.io/<owner>/spt:X.Y.Z`
- `ghcr.io/<owner>/spt:X.Y` (rolling minor)
- `ghcr.io/<owner>/spt:latest` (only for non-prerelease tags)

Pull `:X.Y.Z` and run `docker run --rm ghcr.io/<owner>/spt:X.Y.Z --version`
as a final smoke test.

## 7. Post-release: bump to next-dev

On `main`, immediately after the release is published:

1. Bump the workspace `version` to the next patch with a `-dev` suffix
   (e.g. `0.1.4-dev`).
2. Add an empty `## [Unreleased]` section to `CHANGELOG.md`.
3. Commit as `chore: begin X.Y.Z+1-dev cycle`.

This guarantees that any new `main` build is unambiguously not the
just-released version.

## Signing setup (one-time per maintainer)

Releases are signed at three levels. Setup is documented in the
internal release-keys vault; this section is a pointer.

- **Minisign** — every release artifact is signed with the project's
  minisign keypair. The public key is published at
  `packaging/keys/spt-release.pub` and the private half lives in the
  CI secret store as `MINISIGN_SECRET_KEY` + `MINISIGN_PASSWORD`.
- **macOS notarization** — the `.pkg` is signed with a Developer ID
  Installer certificate and notarized via `notarytool`. Secrets:
  `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`,
  `MACOS_DEVELOPER_ID_INSTALLER_P12` (base64), and
  `MACOS_DEVELOPER_ID_INSTALLER_PASSWORD`.
- **Windows Authenticode** — the `.msi` is signed with an EV code-signing
  certificate. Secrets: `WINDOWS_PFX_BASE64` and `WINDOWS_PFX_PASSWORD`.
  The certificate is HSM-backed; the PFX is a thin wrapper that points
  at the cloud HSM.

Rotate keys every 24 months or on suspected compromise; see the keys
vault README for the rotation procedure.
