#!/usr/bin/env bash
# publish.sh — create a draft GitHub Release and upload dist/<version>/*.
#
# CI normally calls this; locally it's a manual entry point for sanity runs.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/release/publish.sh [--tag <tag>] [--notes-file <path>] [--dry-run]
                                  [--draft|--no-draft] [--prerelease]

Creates (or updates) a GitHub Release and uploads every artifact under
dist/<version>/.

Defaults:
  --tag         v<workspace.package.version>
  --notes-file  CHANGELOG-fragment.md  (optional; auto-generated stub if absent)
  --draft       on
  --prerelease  off

Requires \`gh\` (GitHub CLI) authenticated against the repo.
EOF
  print_help_footer
}

tag=
notes=
draft=1
prerelease=0
dry_run=0

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --tag) tag=$2; shift 2 ;;
    --tag=*) tag=${1#*=}; shift ;;
    --notes-file) notes=$2; shift 2 ;;
    --notes-file=*) notes=${1#*=}; shift ;;
    --draft) draft=1; shift ;;
    --no-draft) draft=0; shift ;;
    --prerelease) prerelease=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    *) die "unknown flag: $1" ;;
  esac
done

have_cmd gh || die "gh (GitHub CLI) not on PATH"

version=$(version_from_cargo)
[[ -n "$tag" ]] || tag="v$version"
dist=$(dist_dir)
[[ -d "$dist" ]] || die "dist dir missing: $dist"

if [[ -z "$notes" ]]; then
  notes="$(repo_root)/CHANGELOG-fragment.md"
  if [[ ! -f "$notes" ]]; then
    info "no CHANGELOG-fragment.md; generating stub"
    notes=$(mktemp -t spt-release-notes.XXXXXX)
    cat >"$notes" <<EOF
# spt $version

Automated release of spt $version.

git: $(git_short_sha)
EOF
  fi
fi

shopt -s nullglob
files=("$dist"/*)
(( ${#files[@]} > 0 )) || die "no artifacts in $dist"

cmd=(gh release create "$tag"
     --title "spt $version"
     --notes-file "$notes")
(( draft ))      && cmd+=(--draft)
(( prerelease )) && cmd+=(--prerelease)
cmd+=("${files[@]}")

info "command: ${cmd[*]}"
if (( dry_run )); then exit 0; fi

# If the release already exists, upload via `gh release upload` instead.
if gh release view "$tag" >/dev/null 2>&1; then
  warn "release $tag already exists; uploading assets with --clobber"
  gh release upload "$tag" --clobber "${files[@]}"
else
  "${cmd[@]}"
fi

info "release $tag published (draft=$draft)"
