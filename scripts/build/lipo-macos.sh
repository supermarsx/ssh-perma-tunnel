#!/usr/bin/env bash
# lipo-macos.sh — merge the two macOS per-arch binaries into a universal one.
#
# Inputs:  target/x86_64-apple-darwin/release/spt
#          target/aarch64-apple-darwin/release/spt
# Output:  target/universal-apple-darwin/release/spt

set -euo pipefail

# shellcheck source=_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/build/lipo-macos.sh

Combines the x86_64 and aarch64 macOS release binaries (already built and
stripped) into a single universal binary at:

    target/universal-apple-darwin/release/spt

Requires \`lipo\` (part of Apple's Command Line Tools).
EOF
  print_help_footer
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") ;;
  *) die "unexpected argument: $1" ;;
esac

have_cmd lipo || die "lipo not found (needs Apple Command Line Tools / macOS)"

root=$(repo_root)
intel="$root/target/x86_64-apple-darwin/release/spt"
arm="$root/target/aarch64-apple-darwin/release/spt"
out_dir="$root/target/universal-apple-darwin/release"
out="$out_dir/spt"

[[ -f "$intel" ]] || die "missing $intel — build x86_64-apple-darwin first"
[[ -f "$arm"   ]] || die "missing $arm   — build aarch64-apple-darwin first"

mkdir -p "$out_dir"
lipo -create -output "$out" "$intel" "$arm"
chmod +x "$out"

info "universal binary: $out"
lipo -info "$out"
echo "$out"
