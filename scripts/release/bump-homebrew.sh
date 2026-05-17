#!/usr/bin/env bash
# bump-homebrew.sh - rewrite packaging/homebrew/spt.rb for a new release.
#
# Usage:
#   scripts/release/bump-homebrew.sh \
#       <version> \
#       <sha256_macos_arm> \
#       <sha256_macos_intel> \
#       <sha256_linux_arm> \
#       <sha256_linux_intel>
#
# All five arguments are required. <version> is the release version with no
# leading "v" (e.g. "0.1.0"). Each SHA must be a 64-character lowercase hex
# string (the output of `sha256sum` / `shasum -a 256`).
#
# The rewrite is atomic: we write to a tempfile in the same directory and
# then `mv` it over the original.

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: bump-homebrew.sh <version> <sha_macos_arm> <sha_macos_intel> \
                       <sha_linux_arm> <sha_linux_intel>

  version           Release version without leading "v" (e.g. 0.1.0).
  sha_macos_arm     sha256 of spt-<version>-aarch64-apple-darwin.tar.gz
  sha_macos_intel   sha256 of spt-<version>-x86_64-apple-darwin.tar.gz
  sha_linux_arm     sha256 of spt-<version>-aarch64-unknown-linux-gnu.tar.gz
  sha_linux_intel   sha256 of spt-<version>-x86_64-unknown-linux-gnu.tar.gz

Each SHA must be 64 lowercase hex characters.
EOF
}

die() {
  printf 'bump-homebrew.sh: error: %s\n' "$*" >&2
  exit 2
}

if [[ $# -eq 1 && ( $1 == "-h" || $1 == "--help" ) ]]; then
  usage
  exit 0
fi

if [[ $# -ne 5 ]]; then
  usage
  exit 2
fi

version=$1
sha_macos_arm=$2
sha_macos_intel=$3
sha_linux_arm=$4
sha_linux_intel=$5

# Validate version: digits/dots/dashes/alnum (semver-ish, no leading v).
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  die "version '$version' is not semver-shaped (expected e.g. 0.1.0)"
fi

# Validate every SHA: exactly 64 lowercase hex characters.
validate_sha() {
  local label=$1 value=$2
  if [[ ! $value =~ ^[0-9a-f]{64}$ ]]; then
    die "$label is not a 64-char lowercase hex sha256: '$value'"
  fi
}
validate_sha "sha_macos_arm"   "$sha_macos_arm"
validate_sha "sha_macos_intel" "$sha_macos_intel"
validate_sha "sha_linux_arm"   "$sha_linux_arm"
validate_sha "sha_linux_intel" "$sha_linux_intel"

# Resolve the formula path relative to this script.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
formula="$script_dir/../../packaging/homebrew/spt.rb"
if [[ ! -f $formula ]]; then
  die "formula not found at $formula"
fi
formula_dir=$(cd -- "$(dirname -- "$formula")" && pwd)
formula_name=$(basename -- "$formula")
formula_abs="$formula_dir/$formula_name"

tmp="$formula_abs.tmp.$$"
# shellcheck disable=SC2064  # we want $tmp captured at trap-set time.
trap "rm -f -- '$tmp'" EXIT

# Use a single awk/sed pipeline so the order of substitutions does not
# matter and so that already-substituted SHAs in the file (re-runs against
# a previously-bumped formula) are also updated, by anchoring on the
# version-bearing url line above each sha256.
#
# Strategy: replace the literal placeholder tokens. The bump script is
# the only sanctioned way to mutate the formula between releases, so the
# placeholders must be restored before re-running. For idempotent re-bumps
# the maintainer should `git checkout packaging/homebrew/spt.rb` first.

sed \
  -e "s|<VERSION>|${version}|g" \
  -e "s|<SHA256_MACOS_ARM64>|${sha_macos_arm}|g" \
  -e "s|<SHA256_MACOS_AMD64>|${sha_macos_intel}|g" \
  -e "s|<SHA256_LINUX_ARM64>|${sha_linux_arm}|g" \
  -e "s|<SHA256_LINUX_AMD64>|${sha_linux_intel}|g" \
  -- "$formula_abs" > "$tmp"

# Sanity-check: the substituted file must no longer contain any of the
# placeholder tokens (otherwise our sed missed something).
if grep -q '<VERSION>\|<SHA256_MACOS_ARM64>\|<SHA256_MACOS_AMD64>\|<SHA256_LINUX_ARM64>\|<SHA256_LINUX_AMD64>' "$tmp"; then
  die "post-substitution file still contains placeholders; aborting"
fi

mv -f -- "$tmp" "$formula_abs"
trap - EXIT

printf 'bump-homebrew.sh: %s rewritten for version %s\n' "$formula_abs" "$version"
