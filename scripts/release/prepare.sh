#!/usr/bin/env bash
# prepare.sh — sanity-check the working tree before a release run.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/release/prepare.sh [--allow-dirty]

Validates the working tree before a local release run:
  * git working tree is clean (override with --allow-dirty)
  * current branch is 'main' (warn only)
  * if HEAD is tagged, tag matches Cargo.toml workspace version
  * dist/<version>/ exists (creates it)

Exits 0 on success.
EOF
  print_help_footer
}

allow_dirty=0
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --allow-dirty) allow_dirty=1; shift ;;
    *) die "unknown flag: $1" ;;
  esac
done

root=$(repo_root)
cd "$root"

if (( allow_dirty == 0 )); then
  if ! git diff --quiet || ! git diff --cached --quiet; then
    die "working tree is dirty (use --allow-dirty to override)"
  fi
fi

branch=$(git rev-parse --abbrev-ref HEAD)
if [[ "$branch" != "main" ]]; then
  warn "current branch is '$branch', not 'main'"
fi

version=$(version_from_cargo)
[[ -n "$version" ]] || die "could not parse version from Cargo.toml"

# If HEAD is tagged with v* exact match, verify it matches Cargo.toml.
tag=$(git tag --points-at HEAD | grep -E '^v' | head -n1 || true)
if [[ -n "$tag" ]]; then
  if [[ "$tag" != "v$version" && "$tag" != "$version" ]]; then
    die "HEAD tag '$tag' does not match Cargo.toml version '$version'"
  fi
  info "HEAD tag '$tag' matches version '$version'"
fi

dist=$(ensure_dist_dir)
info "dist dir ready: $dist"
info "version: $version"
info "git: $(git_short_sha) on $branch"
