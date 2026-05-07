#!/usr/bin/env bash
# manifest.sh — emit dist/<version>/release-manifest.json.
#
# Walks every artifact under dist/<version>/ (excluding the manifest itself)
# and records: name, sha256, size, minisign-sig-path-if-present.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/release/manifest.sh

Produces dist/<version>/release-manifest.json:

  {
    "version": "<workspace.package.version>",
    "git_sha": "<short>",
    "build_date": "<ISO 8601 UTC>",
    "artifacts": [
      { "name": "...", "sha256": "...", "size": 1234, "minisign": "..." | null },
      ...
    ]
  }

The output JSON is sorted lexicographically by artifact name.
EOF
  print_help_footer
}

case "${1:-}" in -h|--help) usage; exit 0 ;; esac

dist=$(dist_dir)
[[ -d "$dist" ]] || die "dist dir missing: $dist"

version=$(version_from_cargo)
sha=$(git_short_sha)
date_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
manifest="$dist/release-manifest.json"

# JSON-escape a string. Limited subset: backslash + dquote + control chars.
json_escape() {
  python3 -c 'import json,sys;sys.stdout.write(json.dumps(sys.stdin.read()))' <<<"$1" 2>/dev/null \
    || printf '"%s"' "${1//\"/\\\"}"
}

shopt -s nullglob
cd "$dist"
mapfile -t files < <(
  for f in *; do
    [[ -f "$f" ]] || continue
    case "$f" in
      release-manifest.json) continue ;;
      *.minisig) continue ;;
    esac
    printf '%s\n' "$f"
  done | sort
)

{
  printf '{\n'
  printf '  "version": %s,\n' "$(json_escape "$version")"
  printf '  "git_sha": %s,\n' "$(json_escape "$sha")"
  printf '  "build_date": %s,\n' "$(json_escape "$date_iso")"
  printf '  "artifacts": [\n'
  count=${#files[@]}
  i=0
  for f in "${files[@]}"; do
    i=$((i + 1))
    if have_cmd sha256sum; then
      hash=$(sha256sum "$f" | awk '{print $1}')
    else
      hash=$(shasum -a 256 "$f" | awk '{print $1}')
    fi
    if have_cmd stat; then
      size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
    else
      size=$(wc -c <"$f" | tr -d ' ')
    fi
    sig="null"
    [[ -f "$f.minisig" ]] && sig=$(json_escape "$f.minisig")
    sep=","
    (( i == count )) && sep=""
    printf '    { "name": %s, "sha256": %s, "size": %s, "minisign": %s }%s\n' \
      "$(json_escape "$f")" "$(json_escape "$hash")" "$size" "$sig" "$sep"
  done
  printf '  ]\n}\n'
} > "$manifest"

info "wrote $manifest (${#files[@]} artifacts)"
