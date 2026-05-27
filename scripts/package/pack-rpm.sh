#!/usr/bin/env bash
# pack-rpm.sh — wrap `cargo generate-rpm` for a glibc Linux target.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/package/pack-rpm.sh <target> [--dry-run]

Builds an RPM for <target> using \`cargo generate-rpm\` against the existing
[package.metadata.generate-rpm] block in crates/spt-bin/Cargo.toml.

Eligible targets (glibc only):
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu

The binary must already be built and stripped.

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
is_rpm_eligible    "$target" || { warn "$target not rpm-eligible (glibc only); skipping"; exit 0; }

if ! have_cmd cargo-generate-rpm && ! cargo generate-rpm --help >/dev/null 2>&1; then
  warn "cargo-generate-rpm not installed; skipping. Install with: cargo install cargo-generate-rpm --locked"
  exit 0
fi

bin=$(binary_for_target "$target")
[[ -f "$bin" ]] || die "binary missing: $bin (run build-target.sh $target first)"

root=$(repo_root)
dist=$(ensure_dist_dir)

# cargo-generate-rpm's -p/--package is the package *directory* (it reads
# <dir>/Cargo.toml), not a cargo package name — so it must be the real path.
cmd=(cargo generate-rpm --target "$target" -p crates/spt-bin --output "$dist/")

info "command: ${cmd[*]}"
if (( dry_run )); then exit 0; fi

(cd "$root" && "${cmd[@]}")

ls -1 "$dist"/*.rpm 2>/dev/null | while read -r f; do info "produced: $f"; done
