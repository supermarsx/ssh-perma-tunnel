#!/usr/bin/env bash
# Remove generated Rust target directories from this repository.
#
# Usage:
#   scripts/clean-targets.sh [--dry-run]

set -euo pipefail

usage() {
  sed -n '2,6p' "$0" >&2
}

die() {
  echo "clean-targets: error: $*" >&2
  exit 1
}

dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run|-n)
      dry_run=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage
      die "unknown argument: $1"
      ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"

targets=()
while IFS= read -r -d '' target; do
  targets+=("$target")
done < <(
  find "$repo_root" \
    \( -path "$repo_root/.git" -o -path "$repo_root/.docker-tmp" \) -prune -o \
    -type d -name target -print0 -prune
)

if [[ ${#targets[@]} -eq 0 ]]; then
  echo "clean-targets: no target directories found under $repo_root"
  exit 0
fi

echo "clean-targets: found ${#targets[@]} target directories under $repo_root"

removed=0
for target in "${targets[@]}"; do
  [[ "$(basename "$target")" == "target" ]] || die "refusing to remove non-target path: $target"

  # Resolve parent symlinks while keeping the final target directory itself as
  # the object to delete. find -type d does not follow symlinked directories.
  resolved_parent="$(cd "$(dirname "$target")" && pwd -P)"
  resolved="$resolved_parent/$(basename "$target")"

  case "$resolved/" in
    "$repo_root"/*) ;;
    *) die "refusing to remove path outside repo root: $resolved" ;;
  esac

  if [[ $dry_run -eq 1 ]]; then
    echo "would remove $resolved"
    continue
  fi

  echo "removing $resolved"
  rm -rf -- "$resolved"
  removed=$((removed + 1))
done

if [[ $dry_run -eq 1 ]]; then
  echo "clean-targets: dry run complete; removed 0 directories"
else
  echo "clean-targets: removed $removed target directories"
fi
