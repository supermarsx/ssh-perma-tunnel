# Versioning

`spt` ships on a **rolling release** model rather than classic SemVer.

## Version shape

Versions take the form `YY.N`:

- `YY` — two-digit UTC year (e.g. `26` for 2026).
- `N` — a monotonic counter that **resets to 1 each January 1st (UTC)**.

So releases run `26.1`, `26.2`, `26.3`, … and roll into `27.1` when the year
ticks over. The current release is `26.1`.

There is no separate major/minor/patch semantics: each `YY.N` is a complete,
shippable build. Breaking changes are called out in the per-release notes
under [`docs/releases/`](releases/), not encoded in the version number.

## Cargo encoding (`0.YY.N`)

Cargo's manifest parser rejects the bare `YY.N` shape (it isn't valid SemVer),
so the workspace `Cargo.toml` carries the encoding **`0.YY.N`** — e.g. `0.26.1`
for release `26.1`. The leading `0.` is an implementation detail of the Cargo
manifest only.

User-facing surfaces drop the `0.`. Tags are **bare** (`26.1`), not
`v`-prefixed:

- git tags and GitHub release titles (`26.1`)
- Docker image tags (`ghcr.io/supermarsx/spt:26.1`)
- packaging recipes (deb/rpm/pkg/msi/scoop/choco/winget/…)

## Release automation

A new release is cut automatically by `.github/workflows/ci.yml` on a push to
`main` once the gating jobs are green (fmt, clippy, typecheck, the test and
build matrices). The `release` job computes the next `YY.N`, tags it, builds
the per-platform artifacts via the `package` job, and publishes the GitHub
release.

To land a change on `main` **without** cutting a release, include
`[skip release]` (or `release: skip`) in the commit message.

See [`releasing.md`](../releasing.md) for the end-to-end automation and
[`docs/releases/`](releases/) for per-release notes.
