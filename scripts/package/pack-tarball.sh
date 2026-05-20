#!/usr/bin/env bash
# pack-tarball.sh — produce a reproducible .tar.gz for one target.
#
# Layout inside the archive:
#   spt-<version>-<target>/
#     spt[.exe]
#     LICENSE
#     README.md
#     docs/...
#     share/man/man1/spt*.1
#     share/bash-completion/completions/spt
#     share/zsh/site-functions/_spt
#     share/fish/vendor_completions.d/spt.fish
#     share/powershell/Modules/spt/spt.psm1
#     share/elvish/lib/spt.elv
#
# Output: dist/<version>/spt-<version>-<target>.tar.gz

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/package/pack-tarball.sh <target> [--dry-run]

Packs the already-built binary at target/<target>/release/spt[.exe] into a
reproducible gzipped tarball under dist/<version>/.

Options:
  --dry-run   show what would be packed and exit
  -h, --help  show this help
EOF
  print_help_footer
}

target=
dry_run=0
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --dry-run) dry_run=1; shift ;;
    -*) die "unknown flag: $1" ;;
    *) [[ -z "$target" ]] || die "extra positional: $1"; target=$1; shift ;;
  esac
done

[[ -n "$target" ]] || { usage >&2; die "missing <target>"; }
is_target_eligible "$target" || die "unknown target: $target"

root=$(repo_root)
version=$(version_from_cargo)
bin=$(binary_for_target "$target")
[[ -f "$bin" ]] || die "binary missing: $bin (run build-target.sh $target first)"

epoch=${SOURCE_DATE_EPOCH:-$(source_date_epoch)}
export SOURCE_DATE_EPOCH=$epoch

dist=$(ensure_dist_dir)
stage="${TMPDIR:-/tmp}/spt-tarball-$$"
name="spt-$version-$target"
staged="$stage/$name"
trap 'rm -rf "$stage"' EXIT

mkdir -p \
  "$staged" \
  "$staged/docs" \
  "$staged/share/man/man1" \
  "$staged/share/bash-completion/completions" \
  "$staged/share/zsh/site-functions" \
  "$staged/share/fish/vendor_completions.d" \
  "$staged/share/powershell/Modules/spt" \
  "$staged/share/elvish/lib"

# Binary (preserve .exe suffix on windows targets).
case "$target" in
  *-pc-windows-*) cp "$bin" "$staged/spt.exe" ;;
  *)              cp "$bin" "$staged/spt"; chmod 0755 "$staged/spt" ;;
esac

# License + README at archive root with conventional names.
[[ -f "$root/license.md" ]] && cp "$root/license.md" "$staged/LICENSE"
[[ -f "$root/readme.md"  ]] && cp "$root/readme.md"  "$staged/README.md"

# Bundle the docs/ tree (markdown only, no nested target/ artefacts).
if [[ -d "$root/docs" ]]; then
  (cd "$root" && find docs -type f \( -name '*.md' -o -name '*.txt' \) -print0) \
    | while IFS= read -r -d '' f; do
        mkdir -p "$staged/$(dirname "$f")"
        cp "$root/$f" "$staged/$f"
      done
fi

# Man pages.
if [[ -d "$root/packaging/man" ]]; then
  cp "$root"/packaging/man/spt*.1 "$staged/share/man/man1/" 2>/dev/null || true
fi

# Shell completions generated from the live Clap command tree and committed
# under packaging/completions/.
completion_root="$root/packaging/completions"
if [[ -d "$completion_root" ]]; then
  cp "$completion_root/bash/spt" "$staged/share/bash-completion/completions/spt" 2>/dev/null || true
  cp "$completion_root/zsh/_spt" "$staged/share/zsh/site-functions/_spt" 2>/dev/null || true
  cp "$completion_root/fish/spt.fish" "$staged/share/fish/vendor_completions.d/spt.fish" 2>/dev/null || true
  cp "$completion_root/powershell/spt.psm1" "$staged/share/powershell/Modules/spt/spt.psm1" 2>/dev/null || true
  cp "$completion_root/powershell/spt.ps1" "$staged/share/powershell/Modules/spt/spt.ps1" 2>/dev/null || true
  cp "$completion_root/elvish/spt.elv" "$staged/share/elvish/lib/spt.elv" 2>/dev/null || true
fi

archive="$dist/$name.tar.gz"

if (( dry_run )); then
  info "would pack -> $archive"
  (cd "$stage" && find "$name" -type f | sort)
  exit 0
fi

# Reproducible tar: GNU tar with --sort, fixed owner/group, mtime from epoch.
# BSD tar (macOS) supports --uid 0 --gid 0 --mtime instead; auto-detect.
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  tar --sort=name \
      --owner=0 --group=0 --numeric-owner \
      --mtime="@$epoch" \
      -C "$stage" -cf - "$name" \
    | gzip -n -9 > "$archive"
elif tar --version 2>/dev/null | grep -qi 'bsdtar'; then
  iso=$(date -u -r "$epoch" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null \
        || date -u -d "@$epoch" +"%Y-%m-%dT%H:%M:%SZ")
  tar --uid 0 --gid 0 --numeric-owner \
      --mtime "$iso" \
      -C "$stage" -cf - "$name" \
    | gzip -n -9 > "$archive"
else
  warn "unknown tar implementation; archive will not be byte-reproducible"
  tar -C "$stage" -czf "$archive" "$name"
fi

info "packed: $archive"
echo "$archive"
