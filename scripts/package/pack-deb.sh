#!/usr/bin/env bash
# pack-deb.sh — wrap `cargo deb` for a glibc Linux target.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/package/pack-deb.sh <target> [--dry-run]

Builds a Debian package for <target> using \`cargo deb\` against the existing
[package.metadata.deb] block in crates/spt-bin/Cargo.toml.

Eligible targets (glibc only):
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu

The binary must already be built and stripped — this script passes
--no-build --no-strip to cargo deb.

Outputs to dist/<version>/.
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
is_deb_eligible    "$target" || { warn "$target not deb-eligible (glibc only); skipping"; exit 0; }

if ! have_cmd cargo-deb && ! cargo deb --help >/dev/null 2>&1; then
  warn "cargo-deb not installed; skipping. Install with: cargo install cargo-deb --locked"
  exit 0
fi

bin=$(binary_for_target "$target")
[[ -f "$bin" ]] || die "binary missing: $bin (run build-target.sh $target first)"

root=$(repo_root)
dist=$(ensure_dist_dir)

cmd=(cargo deb --locked --no-build --no-strip
     --target "$target"
     -p spt-bin
     --output "$dist/")

info "command: ${cmd[*]}"
if (( dry_run )); then exit 0; fi

(cd "$root" && "${cmd[@]}")

# Surface any newly-created .deb under dist/.
ls -1 "$dist"/*.deb 2>/dev/null | while read -r f; do info "produced: $f"; done
