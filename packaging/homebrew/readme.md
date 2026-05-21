# Homebrew packaging for `spt`

This directory holds the Homebrew formula (`spt.rb`) plus the maintainer
workflow for shipping a new release to Homebrew users via three
delivery channels:

1. **Local install** — for contributors testing the formula in-tree.
2. **Personal/organisation tap** (`mariana/spt`) — the default end-user
   channel today.
3. **homebrew-core** — the long-term goal, once the project clears the
   acceptable-formula bar.

The formula is a template: it contains five placeholders that the
release script (`scripts/release/bump-homebrew.sh`) substitutes after a
tagged release has uploaded its tarballs to GitHub Releases.

---

## Quick reference

| Channel               | Command                                                              |
|-----------------------|----------------------------------------------------------------------|
| In-tree (stable)      | `brew install --build-from-source ./packaging/homebrew/spt.rb`       |
| In-tree (HEAD)        | `brew install --HEAD --build-from-source ./packaging/homebrew/spt.rb`|
| Tap                   | `brew tap mariana/spt && brew install spt`                           |
| homebrew-core (later) | `brew install spt`                                                   |

---

## 1. Local install

Once `scripts/release/bump-homebrew.sh` has filled in the placeholders
(or the formula has been pulled from a tap), contributors can install
straight from the working tree:

```bash
brew install --build-from-source ./packaging/homebrew/spt.rb
```

To build from the `main` branch instead of the published tarballs:

```bash
brew install --HEAD --build-from-source ./packaging/homebrew/spt.rb
```

The `head do` block in the formula pulls `https://github.com/Mariana/ssh-perma-tunnel.git`
and runs `cargo install` against `crates/spt-bin`. That path requires a
Rust toolchain (`depends_on "rust" => :build`); Homebrew will install one
automatically if needed.

After install, exercise the `brew test` block (the same block CI runs on
every formula PR):

```bash
brew test spt
```

It checks `spt --version` and runs `spt config validate` against an
inlined minimal TOML config.

---

## 2. Personal tap (`mariana/spt`)

This is the default end-user channel until the formula lands in
homebrew-core.

### One-time tap setup (operator)

1. Create a public GitHub repository named `homebrew-spt` under the
   `mariana` org/user account. Homebrew taps must be named
   `homebrew-<name>`.
2. Copy the rendered `spt.rb` into `Formula/spt.rb` of that repo.
3. Push to `main`.

### Per-release tap update (operator)

After each tagged release on `Mariana/ssh-perma-tunnel`:

1. Compute the four release-artifact SHAs (see *Placeholder substitution*
   below).
2. Run the bump script to rewrite the in-tree template:

   ```bash
   scripts/release/bump-homebrew.sh \
       0.1.0 \
       <sha_macos_arm> \
       <sha_macos_intel> \
       <sha_linux_arm> \
       <sha_linux_intel>
   ```
3. Copy the rewritten `packaging/homebrew/spt.rb` into the tap repo's
   `Formula/spt.rb`, commit, push.
4. End users `brew update && brew upgrade spt`.

### End-user install from the tap

```bash
brew tap mariana/spt
brew install spt
```

---

## 3. Submission to homebrew-core

Once the project meets [Homebrew's acceptable-formulae criteria](https://docs.brew.sh/Acceptable-Formulae)
(notable, stable, ≥30 days since the first release, no
license/distribution problems), open a PR against
[`Homebrew/homebrew-core`](https://github.com/Homebrew/homebrew-core).

### One-time PR (operator)

1. Fork `Homebrew/homebrew-core`.
2. Run the bump script to render the formula:

   ```bash
   scripts/release/bump-homebrew.sh <version> <sha_macos_arm> <sha_macos_intel> <sha_linux_arm> <sha_linux_intel>
   ```
3. Place the rendered file at:

   ```
   Formula/s/spt.rb
   ```

   (homebrew-core shards formulae by first letter of the name.)
4. Validate locally with the Homebrew QA tooling:

   ```bash
   brew style Formula/s/spt.rb
   brew audit --new --strict --online Formula/s/spt.rb
   brew install --build-from-source Formula/s/spt.rb
   brew test spt
   ```
5. Commit with the title `spt <version> (new formula)` and open a PR
   following the [`homebrew-core` contributing guide](https://github.com/Homebrew/homebrew-core/blob/master/CONTRIBUTING.md).

Once merged, Homebrew's CI builds and uploads bottles automatically;
remove the `head do` block from the in-tree template only if upstream
asks you to (it is allowed in homebrew-core formulae).

### Per-release update PR

After homebrew-core has accepted the formula, each release is a small PR
to `Formula/s/spt.rb` that updates `version`, the four `sha256` lines,
and the `url` strings. The bump script produces exactly this diff;
maintainers can either copy the file by hand or use `brew bump-formula-pr`:

```bash
brew bump-formula-pr \
    --url https://github.com/Mariana/ssh-perma-tunnel/releases/download/v<version>/spt-<version>-x86_64-apple-darwin.tar.gz \
    --sha256 <sha_macos_intel> \
    spt
```

The `livecheck` block in the formula lets `brew livecheck spt` discover
new releases automatically by polling GitHub's latest-release endpoint.

---

## 4. Placeholder substitution

The committed `spt.rb` keeps five literal placeholder tokens so the
template is reviewable and validated by `brew style` even before any
release exists. The bump script replaces them in a single pass.

| Token                    | Where it lives                                                | How to compute                                                              |
|--------------------------|---------------------------------------------------------------|-----------------------------------------------------------------------------|
| `<VERSION>`              | `version` line                                                | release tag without the leading `v` (e.g. `0.1.0`)                          |
| `<SHA256_MACOS_ARM64>`   | `on_macos` / `on_arm` block                                   | `shasum -a 256 spt-<VERSION>-aarch64-apple-darwin.tar.gz`                   |
| `<SHA256_MACOS_AMD64>`   | `on_macos` / `on_intel` block                                 | `shasum -a 256 spt-<VERSION>-x86_64-apple-darwin.tar.gz`                    |
| `<SHA256_LINUX_ARM64>`   | `on_linux` / `on_arm` block                                   | `sha256sum spt-<VERSION>-aarch64-unknown-linux-gnu.tar.gz`                  |
| `<SHA256_LINUX_AMD64>`   | `on_linux` / `on_intel` block                                 | `sha256sum spt-<VERSION>-x86_64-unknown-linux-gnu.tar.gz`                   |

The SHAs are pre-computed by CI and published in the release's
`SHA256SUMS` file. Convenience snippet:

```bash
VERSION=0.1.0
BASE=https://github.com/Mariana/ssh-perma-tunnel/releases/download/v${VERSION}
curl -fsSL "$BASE/SHA256SUMS" | awk '
  /aarch64-apple-darwin\.tar\.gz$/        { print "macos_arm   = " $1 }
  /x86_64-apple-darwin\.tar\.gz$/         { print "macos_intel = " $1 }
  /aarch64-unknown-linux-gnu\.tar\.gz$/   { print "linux_arm   = " $1 }
  /x86_64-unknown-linux-gnu\.tar\.gz$/    { print "linux_intel = " $1 }
'
```

To re-run `bump-homebrew.sh` against an already-bumped formula, restore
the placeholders first:

```bash
git checkout packaging/homebrew/spt.rb
```

---

## 5. Files in this directory

```
packaging/homebrew/
├── spt.rb       Homebrew formula (template; bumped in place by the script)
└── readme.md    this file
```
