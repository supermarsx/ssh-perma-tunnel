<!--
Thanks for sending a PR! Fill in the sections below. Delete any that
genuinely don't apply, but prefer keeping a short "n/a" over deleting
silently — reviewers use these headings as a checklist.
-->

## Summary

<!-- One or two sentences describing the change at a human level. -->

## What changed

<!-- Bullet list of the concrete changes. Group by crate/module if it
helps. Reviewers should be able to skim this and know what to look at. -->

-

## Why

<!-- Motivation. Bug report? Spec gap? User request? Performance
regression? Link the issue if there is one. -->

## Spec section refs

<!-- If this PR implements or alters specified behaviour, list the
spec.md sections it touches (e.g. `spec.md §11.4`, `spec.md §17.4.2`).
Use "n/a" if the change is purely internal. -->

## Testing notes

<!-- How did you verify this works? Unit tests? Integration tests?
Manual smoke against a real SSH server? Mention any environment-
specific testing the reviewer should reproduce. -->

## Checklist

- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [ ] `cargo test --workspace --locked` passes.
- [ ] New public items have rustdoc, with a doc-test where practical.
- [ ] `changelog.md` updated under `## [Unreleased]` if user-visible.
- [ ] No `cargo update` was run (lockfile pinned for MSRV — see
      [contributing.md](../contributing.md#why-the-lockfile-is-pinned)).
- [ ] If a new crate was added, it exposes a `testing` Cargo feature.
- [ ] If touching secrets/redaction/listening sockets, security
      implications considered and called out above.
