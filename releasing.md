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
Tag = <YY>.<N>                   (bare, no `v` prefix — e.g. 26.1, 26.2, ..., 26.99, 26.314)
```

- The counter resets to `1` at the first release after the UTC year rolls
  over. If the previous release was `26.314` on 2026-12-31, the next
  release on or after 2027-01-01 UTC will be `27.1`.
- Tags are **immutable**. If a release has a bad artifact, do not retag —
  cut a follow-up release with the fix (see "Rolling back" below).
- The workspace `version` field in the root `Cargo.toml` always reflects
  the *currently released* version, encoded as `0.<YY>.<N>` because Cargo's
  TOML parser rejects the bare `YY.N` shape. The line is marked with a
  `# rolling` trailer so the bump script can find and update it in-place:

  ```toml
  [workspace.package]
  version = "0.26.1"  # rolling
  ```

  The bare `YY.N` form (`26.1`) is the user-facing tag / release title /
  docker tag; the manifest carries the `0.`-prefixed SemVer encoding only.
  See [`contributing.md`](contributing.md) for why the marker matters.

## How a release happens

1. A commit lands on `main` (push or PR-merge).
2. The standard `fmt → clippy → test → build` pipeline runs across the
   5-target matrix (see [`contributing.md`](contributing.md) for the target
   list). There is no separate `security` / cargo-deny gate in CI; advisory
   scanning runs out-of-band in the non-gating scheduled `audit.yml` workflow.
3. The `release` job (`needs: [package, prepare-release]`):
   1. downloads all platform artifacts,
   2. runs [`scripts/release/bump-version.sh`](scripts/release/bump-version.sh)
      to compute the bare `YY.N` tag,
   3. refuses to proceed if `YY.N` already exists on the remote
      (printing `::error::<YY.N> already exists`),
   4. generates `dist/<tag>/CHANGELOG-fragment.md`, checksums, optional
      minisign signatures, SBOM, and the release manifest,
   5. commits the `Cargo.toml` bump and pushes the bare annotated tag,
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

## Pre-releases

There is **no** pre-release / RC channel. CI triggers only on `main`, and
`bump-version.sh` has no `release-staging/*` or `-rc.<M>` logic. Every
release is a final `YY.N` cut from `main`. To validate a packaging or
codesigning change end-to-end, run the relevant `scripts/package/*` or
`scripts/build/*` script locally, or exercise the `workflow_dispatch`
path (`kind: full`).

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

Tags are immutable. If `26.7` shipped with a regression:

1. **Do not** delete or move the tag.
2. Land a fix on `main`. The next push produces `26.8` automatically.
3. (Optional) Yank Docker by re-pointing `:latest` to the prior good
   tag: `docker buildx imagetools create -t ghcr.io/<owner>/spt:latest \
   ghcr.io/<owner>/spt:26.6` and announce the rollback in the release
   notes for `26.8`.

## Signing (current status: NOT wired into CI)

> **Release artifacts are currently UNSIGNED.** The signing scripts
> (`scripts/sign/sign-macos.sh`, `scripts/sign/sign-windows.ps1`) exist
> but **no CI job invokes them** — the release/package jobs run only
> `checksum-all.sh`, the gated `minisign-all.sh`, `gen-sbom.sh`, and
> `manifest.sh`. macOS `.pkg` notarization and Windows Authenticode
> signing do **not** happen automatically; users may see Gatekeeper /
> SmartScreen warnings. Wiring the sign scripts into the package job
> behind the secret gates below is a planned/manual step.

The checksum + minisign step *is* wired (gated on the minisign secret):

- **Minisign** — `MINISIGN_SECRET_KEY` + `MINISIGN_PASSWORD`. The public
  verification key lives at **`packaging/minisign.pub`**. When the secret
  is set, `minisign-all.sh` signs each artifact's checksum file.

The following are **scripts-only, not yet invoked by CI** (manual /
planned). The secret names below are the intended gates once wired:

- **macOS notarization** — `MACOS_SIGNING_IDENTITY`, `MACOS_NOTARY_USER`,
  `MACOS_NOTARY_PASSWORD`. Intended: sign the `.pkg` with a Developer ID
  Installer certificate and notarize via `notarytool`. Not yet wired.
- **Windows Authenticode** — `WINDOWS_SIGNING_CERT_BASE64` +
  `WINDOWS_SIGNING_PASSWORD`. Intended: sign the `.msi` with an EV
  code-signing certificate. Not yet wired.
- **Linux GPG** — `LINUX_GPG_KEY` for `.deb` / `.rpm` repository
  signatures. Not yet wired.

Rotate every 24 months or on suspected compromise; see the keys vault
README for the rotation procedure.

## Operator dispatch (optional pipelines)

The consolidated `ci.yml` also exposes four `workflow_dispatch.kind`
options, each running exclusively (not as part of the standard
fmt→clippy→test→build pipeline):

Only `full` remains (it's the default and just runs the standard pipeline).
The previous dispatch-only kinds (`coverage`, `fuzz`, `openssh-interop`,
`bench-regression`) were removed along with their jobs.
