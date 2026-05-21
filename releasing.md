# Releasing `spt`

`spt` ships on a **rolling release** model: every commit landed on `main`
that passes CI becomes a tagged GitHub Release with full multi-platform
artifacts.  There is no separate release branch, no manual tagging, and no
pre-flight checklist beyond the standard CI green-light.

The full pipeline lives in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Versioning: YY.N rolling

```
YY  = two-digit UTC year         (e.g. 26 for 2026)
N   = monotonic counter, resets  (first release of the year is N=1)
Tag = v<YY>.<N>                  (e.g. v26.1, v26.2, ..., v26.99, v26.314)
```

- The counter resets to `1` at the first release after the UTC year rolls
  over. If the previous release was `v26.314` on 2026-12-31, the next
  release on or after 2027-01-01 UTC will be `v27.1`.
- Tags are **immutable**. If a release has a bad artifact, do not retag —
  cut a follow-up release with the fix (see "Rolling back" below).
- The workspace `version` field in the root `Cargo.toml` always reflects
  the *currently released* version. The line is marked with a
  `# rolling` trailer so the bump script can find and update it
  in-place:

  ```toml
  [workspace.package]
  version = "26.1"  # rolling
  ```

  See [`contributing.md`](contributing.md) for why the marker matters.

## How a release happens

1. A commit lands on `main` (push or PR-merge).
2. The standard `fmt → clippy → test (×6) → build (×6)` pipeline runs.
   `security` (cargo-deny + RustSec audit) runs in parallel.
3. The `release` job:
   1. downloads all six platform artifacts,
   2. runs [`scripts/release/bump-version.sh`](scripts/release/bump-version.sh)
      to compute `vYY.N`,
   3. refuses to proceed if `vYY.N` already exists on the remote
      (printing `::error::v<YY.N> already exists`),
   4. generates `dist/<tag>/CHANGELOG-fragment.md`, checksums, optional
      minisign signatures, SBOM, and the release manifest,
   5. commits the `Cargo.toml` bump and pushes the annotated tag,
   6. creates the GitHub Release with `gh release create --target main`,
   7. multi-arch `docker buildx push`es `ghcr.io/<owner>/spt:<YY.N>` and
      `:latest`.

The whole thing is unattended.

## Opting out of a release

If a particular `main` commit should **not** trigger a release:

- include `[skip release]` anywhere in the commit message, **or**
- title the commit exactly `release: skip` (e.g. for an empty commit
  pushed solely to skip).

The `release` job's `if:` guard reads the head-commit message and skips
when either token is present. The rest of the pipeline still runs.

## Pre-releases from staging branches

Branches matching `release-staging/*` produce **pre-releases**.  The
version stamp is `<YY.N>-rc.<M>`, where:

- `YY.N` is the next non-released rolling version (i.e. what the next
  release on `main` would be),
- `M` is a monotonic RC counter within that `YY.N` slot.

GitHub Release is marked `prerelease`, no Docker `:latest` push, no
overwriting of the `latest` channel. Use these to validate a packaging
or codesigning change end-to-end before merging to `main`.

## Inspecting / dry-running the next version

```sh
bash scripts/release/bump-version.sh --dry-run
```

prints the version and tag that would be produced *right now*, without
editing `Cargo.toml`, committing, or tagging.  Useful when:

- you want to know which version a PR will become, post-merge,
- you're debugging a year-rollover edge case (set `TZ=UTC` and
  `faketime` to simulate),
- you're verifying that an out-of-band manual release didn't leave the
  counter in an unexpected state.

## Rolling back

Tags are immutable. If `v26.7` shipped with a regression:

1. **Do not** delete or move the tag.
2. Land a fix on `main`. The next push produces `v26.8` automatically.
3. (Optional) Yank Docker by re-pointing `:latest` to the prior good
   tag: `docker buildx imagetools create -t ghcr.io/<owner>/spt:latest \
   ghcr.io/<owner>/spt:26.6` and announce the rollback in the release
   notes for `v26.8`.

## Signing setup (one-time per maintainer)

The `release` job is gated on the presence of the relevant secrets and
no-ops the signing step if they are absent.

- **Minisign** — `MINISIGN_SECRET_KEY` + `MINISIGN_PASSWORD`. Public key
  lives at `packaging/keys/spt-release.pub`. Every artifact is signed
  when the secret is set.
- **macOS notarization** — `MACOS_SIGNING_IDENTITY`, `MACOS_NOTARY_USER`,
  `MACOS_NOTARY_PASSWORD`. The `.pkg` is signed with a Developer ID
  Installer certificate and notarized via `notarytool`.
- **Windows Authenticode** — `WINDOWS_SIGNING_CERT_BASE64` +
  `WINDOWS_SIGNING_PASSWORD`. The `.msi` is signed with an EV
  code-signing certificate (HSM-backed; the PFX is a thin wrapper).
- **Linux GPG** — `LINUX_GPG_KEY` for `.deb` / `.rpm` repository
  signatures, applied by `scripts/sign/checksum-all.sh`.

Rotate every 24 months or on suspected compromise; see the keys vault
README for the rotation procedure.

## Operator dispatch (optional pipelines)

The consolidated `ci.yml` also exposes four `workflow_dispatch.kind`
options, each running exclusively (not as part of the standard
fmt→clippy→test→build pipeline):

| `kind`              | Replaces                | What it does                                                |
|---------------------|-------------------------|-------------------------------------------------------------|
| `full` (default)    | n/a                     | The standard pipeline (also runs on every push and PR).     |
| `coverage`          | `coverage.yml`          | `cargo llvm-cov` + Codecov upload.                          |
| `fuzz`              | `fuzz.yml`              | All 10 cargo-fuzz targets, 60 s each, in parallel.          |
| `openssh-interop`   | `openssh-interop.yml`   | docker-compose interop fixture against the standalone crate.|
| `bench-regression`  | `bench-regression.yml`  | Criterion compare against `main` baseline.                  |

Trigger from the Actions tab or with `gh workflow run ci.yml -f kind=fuzz`.
