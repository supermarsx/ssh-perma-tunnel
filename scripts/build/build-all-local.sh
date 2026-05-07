#!/usr/bin/env bash
# build-all-local.sh — build every target reachable from this host.
#
# Iterates ALLOWED_TARGETS, attempting each in turn. Targets requiring `cross`
# without Docker available are skipped with a warn line. Always exits 0 if at
# least one target succeeded; 1 if every attempted target failed.

set -euo pipefail

# shellcheck source=_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/build/build-all-local.sh [--dry-run] [--continue-on-error]

Builds every target in the allow-list reachable from this host. Targets that
require cross-rs + Docker are silently skipped if Docker isn't available.

Options:
  --dry-run             list per-target plan and exit
  --continue-on-error   keep going if a target fails (default)
  --fail-fast           stop on the first failure
  -h, --help            show this help
EOF
  print_help_footer
}

dry_run=0
fail_fast=0

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --dry-run) dry_run=1; shift ;;
    --continue-on-error) fail_fast=0; shift ;;
    --fail-fast) fail_fast=1; shift ;;
    *) die "unknown flag: $1" ;;
  esac
done

host=$(host_triple)
info "host triple: $host"

declare -a results=()
have_docker=1
have_cmd docker || have_docker=0
have_cross=1
have_cmd cross || have_cross=0

attempted=0
succeeded=0

for t in "${ALLOWED_TARGETS[@]}"; do
  reason=
  if host_can_build_native "$t"; then
    plan="native"
  else
    if (( have_cross == 0 )); then
      results+=("SKIP $t (cross not installed)")
      continue
    fi
    if (( have_docker == 0 )); then
      results+=("SKIP $t (docker not available; cross needs it)")
      continue
    fi
    plan="cross"
  fi

  attempted=$((attempted + 1))
  if (( dry_run )); then
    results+=("PLAN $t ($plan)")
    continue
  fi

  if "$(repo_root)/scripts/build/build-target.sh" "$t"; then
    results+=("OK   $t ($plan)")
    succeeded=$((succeeded + 1))
  else
    results+=("FAIL $t ($plan)")
    if (( fail_fast )); then
      printf '%s\n' "${results[@]}"
      die "fail-fast: stopping after $t"
    fi
  fi
done

echo
echo "===== build-all-local summary ====="
printf '%s\n' "${results[@]}"
echo "==================================="

if (( dry_run )); then exit 0; fi
if (( attempted == 0 )); then
  warn "no buildable targets from this host"
  exit 0
fi
if (( succeeded == 0 )); then
  die "every attempted target failed"
fi
