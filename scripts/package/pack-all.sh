#!/usr/bin/env bash
# pack-all.sh — iterate every per-target binary in target/ and package it.
#
# Skips anything that isn't built yet. Writes everything into dist/<version>/.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/package/pack-all.sh [--dry-run]

Iterates every supported target and produces:
  - tarball (always)
  - .deb (Linux glibc only, if cargo-deb installed)
  - .rpm (Linux glibc only, if cargo-generate-rpm installed)
  - macOS .pkg (if both x86_64 + aarch64 macOS binaries exist; runs lipo)
  - .msi for Windows targets is built via pack-msi-windows.ps1, not here.

Skips any target whose binary isn't present in target/.
EOF
  print_help_footer
}

dry_run=0
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --dry-run) dry_run=1; shift ;;
    *) die "unknown flag: $1" ;;
  esac
done

root=$(repo_root)
ensure_dist_dir >/dev/null

dry_flag=()
(( dry_run )) && dry_flag=(--dry-run)

for t in "${ALLOWED_TARGETS[@]}"; do
  bin=$(binary_for_target "$t")
  if [[ ! -f "$bin" ]]; then
    info "skip $t (no binary at $bin)"
    continue
  fi

  case "$t" in
    *-pc-windows-*)
      info "windows target $t — use pack-zip.ps1 + pack-msi-windows.ps1 from PowerShell; skipping here"
      ;;
    *)
      "$root/scripts/package/pack-tarball.sh" "$t" "${dry_flag[@]}" || warn "pack-tarball failed for $t"
      ;;
  esac

  if is_deb_eligible "$t"; then
    "$root/scripts/package/pack-deb.sh" "$t" "${dry_flag[@]}" || warn "pack-deb failed for $t"
  fi
  if is_rpm_eligible "$t"; then
    "$root/scripts/package/pack-rpm.sh" "$t" "${dry_flag[@]}" || warn "pack-rpm failed for $t"
  fi
done

intel="$root/target/x86_64-apple-darwin/release/spt"
arm="$root/target/aarch64-apple-darwin/release/spt"
if [[ -f "$intel" && -f "$arm" ]]; then
  info "both macOS arches present — running lipo + pack-pkg"
  if (( dry_run )); then
    info "dry-run: would lipo + pack-pkg-macos"
  else
    "$root/scripts/build/lipo-macos.sh" || warn "lipo failed"
    "$root/scripts/package/pack-pkg-macos.sh" || warn "pack-pkg-macos failed"
  fi
fi

info "pack-all done; artifacts in $(dist_dir)"
