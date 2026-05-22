# Release notes

`spt` ships on a **rolling release** model. Every commit landed on
`main` that passes the full CI pipeline becomes a tagged GitHub
Release with multi-platform artifacts. There is no separate release
branch, no manual tagging, and no pre-flight checklist beyond a green
CI run.

## Versioning: `YY.N` (rolling)

```
YY  = two-digit UTC year         (e.g. 26 for 2026)
N   = monotonic counter, resets  (first release of the year is N=1)
Tag = v<YY>.<N>                  (e.g. v26.1, v26.2, ..., v26.314)
```

Cargo encoding: the workspace manifest field carries the SemVer-
compatible form `0.<YY>.<N>` (e.g. `0.26.1`) because Cargo's TOML
parser rejects the bare `YY.N` shape (`unexpected end of input while
parsing minor version number`). The user-facing tag, release title,
docker image tag, and packaging recipes drop the leading `0.`.

- The counter resets to `1` at the first release after the UTC year
  rolls over. If the previous release was `v26.314` on 2026-12-31,
  the next release on or after 2027-01-01 UTC will be `v27.1`.
- Tags are **immutable**. A bad artifact is fixed by cutting a follow-
  up release, not by retagging.
- The CI release job (`.github/workflows/ci.yml`, job `release`) gates
  on `needs: [build, security]`, so a release only happens when the
  full multi-platform matrix is green AND `cargo-deny` + RustSec
  audit are green.
- Bypass for a single push: include `[skip release]` anywhere in the
  commit message, or title the commit `release: skip`.

See [`../releasing.md`](../../releasing.md) for the full automation
walkthrough including pre-releases, rollbacks, and signing setup.

## Per-release notes

Each release gets its own file in this directory, named `<YY>.<N>.md`:

| Release | File           | Date       |
|---------|----------------|------------|
| `v26.1` | [`26.1.md`](26.1.md) | 2026-05-22 |

When the `release` CI job runs, it consults this directory for a
matching `<version>.md`. If one exists (curated by the human author
of the close-out commit), it is used verbatim as the GitHub Release
body. If not, the job synthesises a fragment from the `git log` since
the previous tag — see `bump-version.sh` and `manifest.sh` for the
fallback path.

## Authoring a release-notes file

For an in-progress version (i.e. you're about to land the commit that
flips CI green), drop a `docs/releases/<next-version>.md` in the same
commit. The next-version string can be computed with:

```sh
bash scripts/release/bump-version.sh --dry-run
```

Conventions:

- Open with a one-paragraph framing (what this release is, what
  milestones / themes it covers).
- Use `## Highlights`, `## Migration notes`, `## Known issues`, and
  `## Verification` headings to match `26.1.md`.
- Migration sections only need to mention deltas since the *previous*
  release (`vYY.N-1`), not since `0.1.0` — the rolling model assumes
  users update continuously.
- Avoid promising future timelines. Use phrasing like "queued for a
  future rolling release" instead of "post-1.0" or "next major".
