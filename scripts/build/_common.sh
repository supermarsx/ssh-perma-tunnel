#!/usr/bin/env bash
# scripts/build/_common.sh — shared helpers for the spt build/release scripts.
#
# Source this file from every other shell script:
#   source "$(dirname "$0")/_common.sh"   # when in scripts/build/
#   source "$(repo_root)/scripts/build/_common.sh"
#
# All helpers are idempotent. None of them call exit on their own except die().

# shellcheck shell=bash

# ---- pretty printers --------------------------------------------------------

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36minfo:\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarn:\033[0m %s\n' "$*" >&2; }

# ---- repo introspection -----------------------------------------------------

repo_root() { git rev-parse --show-toplevel; }

# Read the workspace.package version from the top-level Cargo.toml.
version_from_cargo() {
  awk -F'"' '
    /^\[workspace\.package\]/ { p = 1; next }
    /^\[/ && p { p = 0 }
    p && /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }
  ' "$(repo_root)/Cargo.toml"
}

git_short_sha() { git rev-parse --short=12 HEAD; }

# Source date epoch (the HEAD commit's UNIX timestamp). Used for
# reproducible-ish artifact builds. Echoes the value; callers can also
# `export SOURCE_DATE_EPOCH="$(source_date_epoch)"`.
source_date_epoch() { git log -1 --format=%ct; }

host_triple() { rustc -vV | awk '/^host:/{print $2}'; }

# ---- target matrix ----------------------------------------------------------

# The eight officially-supported release targets. Order matters for output
# consistency only.
ALLOWED_TARGETS=(
  x86_64-unknown-linux-gnu
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-gnu
  aarch64-unknown-linux-musl
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-pc-windows-msvc
  aarch64-pc-windows-msvc
)

is_target_eligible() {
  local t=${1:-}
  [[ -n "$t" ]] || return 1
  local x
  for x in "${ALLOWED_TARGETS[@]}"; do
    [[ "$x" == "$t" ]] && return 0
  done
  return 1
}

# Targets that may produce a .deb (cargo-deb) — glibc Linux only.
is_deb_eligible() {
  case "${1:-}" in
    *-unknown-linux-gnu) return 0 ;;
    *) return 1 ;;
  esac
}

# Targets that may produce an .rpm — glibc Linux only.
is_rpm_eligible() {
  case "${1:-}" in
    *-unknown-linux-gnu) return 0 ;;
    *) return 1 ;;
  esac
}

# ---- paths ------------------------------------------------------------------

dist_dir() {
  local v
  v=$(version_from_cargo)
  echo "$(repo_root)/dist/$v"
}

ensure_dist_dir() {
  local d
  d=$(dist_dir)
  mkdir -p "$d"
  echo "$d"
}

# Path to a built binary for a given target. .exe suffix on windows-msvc.
binary_for_target() {
  local t=${1:?target required}
  local root
  root=$(repo_root)
  case "$t" in
    *-pc-windows-*) echo "$root/target/$t/release/spt.exe" ;;
    *)              echo "$root/target/$t/release/spt" ;;
  esac
}

# Whether the current host can build the target without `cross` / Docker.
# Returns 0 (true) if cargo can do it natively (or via msvc/apple toolchains
# already on the host).
host_can_build_native() {
  local target=${1:?target required}
  local host
  host=$(host_triple) || return 1
  if [[ "$host" == "$target" ]]; then return 0; fi
  case "$host:$target" in
    x86_64-apple-darwin:aarch64-apple-darwin) return 0 ;;
    aarch64-apple-darwin:x86_64-apple-darwin) return 0 ;;
    *-pc-windows-msvc:x86_64-pc-windows-msvc) return 0 ;;
    *-pc-windows-msvc:aarch64-pc-windows-msvc) return 0 ;;
  esac
  return 1
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Print a standard --help epilogue.
print_help_footer() {
  cat <<'EOF'

Environment overrides:
  CARGO       (default: cargo)
  CROSS       (default: cross)
  SOURCE_DATE_EPOCH  (default: HEAD commit timestamp)

Run from any directory; scripts resolve paths from `git rev-parse --show-toplevel`.
EOF
}
