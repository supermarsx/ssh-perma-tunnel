#!/usr/bin/env bash
# collect-artifacts.sh — flatten artifacts from a directory tree into dist/<version>/.
#
# Intended for CI: after `actions/download-artifact` lands every uploaded
# bundle under a per-job subdirectory, this walks the tree and moves every
# spt-* / SHA*SUMS / sbom.* / *.minisig / *.asc into dist/<version>/.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/release/collect-artifacts.sh <input-dir> [--dry-run]

Recursively walks <input-dir> and copies every release artifact into
dist/<version>/. Files matched:

  spt-*.tar.gz, spt-*.zip, spt-*.deb, spt-*.rpm, spt-*.pkg, spt-*.msi
  SHA256SUMS*, SHA512SUMS*, B3SUMS*
  sbom.json, sbom.xml
  *.minisig, *.asc

Subsequent files with the same name are skipped (first wins).
EOF
  print_help_footer
}

input=
dry_run=0
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --dry-run) dry_run=1; shift ;;
    -*) die "unknown flag: $1" ;;
    *) [[ -z "$input" ]] || die "extra positional: $1"; input=$1; shift ;;
  esac
done

[[ -n "$input" ]] || { usage >&2; die "missing <input-dir>"; }
[[ -d "$input" ]] || die "not a directory: $input"

dist=$(ensure_dist_dir)

# Use find to enumerate; filter via case below.
while IFS= read -r -d '' f; do
  base=$(basename "$f")
  case "$base" in
    spt-*.tar.gz|spt-*.zip|spt-*.deb|spt-*.rpm|spt-*.pkg|spt-*.msi) ;;
    SHA256SUMS*|SHA512SUMS*|B3SUMS*) ;;
    sbom.json|sbom.xml) ;;
    *.minisig|*.asc) ;;
    *) continue ;;
  esac
  dest="$dist/$base"
  if [[ -e "$dest" ]]; then
    info "skip (exists): $base"
    continue
  fi
  if (( dry_run )); then
    info "would copy: $f -> $dest"
  else
    cp "$f" "$dest"
    info "copied: $base"
  fi
done < <(find "$input" -type f -print0)

info "collect-artifacts done -> $dist"
