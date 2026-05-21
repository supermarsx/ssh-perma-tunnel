# Contributing to `spt`

Thanks for your interest in `ssh-perma-tunnel` (`spt`). This document
covers everything you need to send a useful pull request.

## Project mission

`spt` is a single, batteries-included Rust CLI that establishes and
maintains **permanent SSH tunnels** — local and reverse forwards that
survive network drops, host restarts, service restarts, DNS changes,
and normal operational drift. It is **client-only**: it talks to
existing SSH/SSH3 servers and never opens a server role itself.

The project optimises for: predictable behaviour over clever shortcuts,
explicit failure modes over silent retry loops, and a redaction-first
posture wherever data crosses a process boundary.

## Development setup

`spt` targets **Rust 1.83**, pinned by [`rust-toolchain.toml`](rust-toolchain.toml).
`rustup` will install the right toolchain on first invocation; you do
not need to manage it yourself.

The day-to-day commands are:

```sh
cargo build --workspace --locked
cargo test  --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI runs the same set plus a cross-build matrix and `cargo-deny`.

### Do not run `cargo update`

The lockfile is **intentionally pinned for MSRV reasons** — see
[Why the lockfile is pinned](#why-the-lockfile-is-pinned) below.
Dependabot opens upgrade PRs for review; humans then verify the result
still builds on Rust 1.83 before merging. Running `cargo update`
locally and committing the result will almost always fail CI.

If you need to add a dependency, add it with the minimum version that
satisfies your needs and let `cargo` resolve the rest against the
existing lockfile.

#### Why the lockfile is pinned

Several transitive dependencies in the ecosystem regularly bump their
own MSRV ahead of ours. Letting `cargo update` run unconstrained will
silently pull in versions that require Rust 1.86+ — and that breakage
only shows up after the fact, often on a contributor's machine that
happens to ship a newer toolchain. Pinning the lockfile keeps the
"works on every supported toolchain" property checkable in one place.

## Code style

- **`rustfmt`** is mandatory. CI fails on any unformatted code.
- **Clippy pedantic** is on workspace-wide via `[lints]`. Warnings are
  errors in CI; either fix the lint or, if it's a genuine
  false-positive, add a narrowly-scoped `#[allow(...)]` with a comment.
- New **public items** require a rustdoc comment, and **at least one
  doc-test where practical** (think: parsers, builders, anything with
  invariants worth pinning down). Private items don't need rustdoc but
  benefit from one.
- Prefer `tracing` over `println!`/`eprintln!` for anything that might
  end up in a release build.

## Testing conventions

Each library crate exposes a `testing` Cargo feature that publishes
fixtures, builders, and mock implementations for sibling-crate use.
The pattern is:

```toml
[features]
testing = []
```

with a `pub mod testing { ... }` gated by `#[cfg(any(test, feature = "testing"))]`.

If you add a new crate to the workspace, **add the `testing` feature**
even if it's empty initially — downstream crates expect to be able to
turn it on.

Tests live where they belong:

- Unit tests inline (`#[cfg(test)] mod tests { ... }`).
- Integration tests under `tests/` for crates with a meaningful public
  surface.
- `spt-bin` carries end-to-end CLI tests that exercise the binary
  directly.

## Pull request process

1. Branch from `main` (no other long-lived branches exist).
2. Keep the PR focused — one concern per PR is much easier to review.
3. Conventional-commit-style bodies are welcome (`feat:`, `fix:`,
   `docs:`, …) but **not required**. A clear human-readable subject
   line is the only hard rule.
4. Update [`CHANGELOG.md`](CHANGELOG.md) under `## [Unreleased]` if
   your change is user-visible.
5. Link spec sections (`spec.md` §N) when your change implements or
   alters specified behaviour.
6. CI must be green before merge:
   - `cargo fmt --check`
   - `cargo clippy -- -D warnings`
   - `cargo test --workspace --locked`
   - cross-build matrix (8 targets)
   - `cargo deny check`

Maintainers may squash on merge; write your PR description as if it
will become the squashed commit message.

## Release process

Releases follow the runbook in [`RELEASING.md`](RELEASING.md). If your
change is user-visible, please add a `## [Unreleased]` entry to the
changelog so the release engineer doesn't have to reconstruct it later.

## Reporting security issues

Please **do not** open a public issue for security vulnerabilities.
Follow the process in [`SECURITY.md`](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
By participating you agree to uphold it.
