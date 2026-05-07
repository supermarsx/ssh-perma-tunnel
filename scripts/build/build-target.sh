#!/usr/bin/env bash
# build-target.sh — build the spt binary for one target triple.
#
# Usage: scripts/build/build-target.sh <target> [--profile=release] [--dry-run]
#
# Decides between native `cargo build` and `cross build` based on host vs
# target. Sets SOURCE_DATE_EPOCH for reproducibility, then strips the binary.
# Echoes the final binary path on success.

set -euo pipefail

# shellcheck source=_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/build/build-target.sh <target> [--profile=release] [--dry-run]

Builds a single spt release binary for <target> from one of:
  ${ALLOWED_TARGETS[*]}

Options:
  --profile=<name>   cargo profile (default: release)
  --dry-run          print the chosen toolchain + command and exit 0
  -h, --help         show this help

The script always passes --locked. Never run \`cargo update\` from here.
EOF
  print_help_footer
}

profile=release
dry_run=0
target=

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --dry-run) dry_run=1; shift ;;
    --profile=*) profile=${1#*=}; shift ;;
    --) shift; break ;;
    -*) die "unknown flag: $1" ;;
    *) [[ -z "$target" ]] || die "extra positional: $1"; target=$1; shift ;;
  esac
done

[[ -n "$target" ]] || { usage >&2; die "missing <target>"; }
is_target_eligible "$target" || die "target not in allow-list: $target"

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(source_date_epoch)}
export CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-0}

cargo_bin=${CARGO:-cargo}
cross_bin=${CROSS:-cross}

if host_can_build_native "$target"; then
  tool="$cargo_bin"
  reason="native (host=$(host_triple))"
else
  if ! have_cmd "$cross_bin"; then
    die "cross required for $target but '$cross_bin' is not on PATH (cargo install cross --locked)"
  fi
  tool="$cross_bin"
  reason="cross-rs (host=$(host_triple))"
fi

cmd=("$tool" build "--profile=$profile" --locked --target "$target" -p spt-bin)

info "building spt for $target via $reason"
info "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
info "command: ${cmd[*]}"

if (( dry_run )); then
  exit 0
fi

(cd "$(repo_root)" && "${cmd[@]}")

# Run platform-aware strip.
"$(repo_root)/scripts/build/strip-binary.sh" "$target"

bin=$(binary_for_target "$target")
[[ -f "$bin" ]] || die "expected binary not found at $bin"

info "built: $bin"
echo "$bin"
