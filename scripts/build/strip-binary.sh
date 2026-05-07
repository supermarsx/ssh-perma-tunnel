#!/usr/bin/env bash
# strip-binary.sh — platform-aware strip for a built spt binary.
#
# Usage: scripts/build/strip-binary.sh <target>
#
# Strips the binary at target/<target>/release/spt[.exe]. No-op on Windows
# (rust already strips with `-C strip=symbols`). Idempotent.

set -euo pipefail

# shellcheck source=_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/build/strip-binary.sh <target>

Strips debug symbols from the unsigned release binary for <target>.

Behaviour:
  *-linux-*    : strip --strip-unneeded (or llvm-strip if cross-target)
  *-apple-*    : strip -x   (preserves global symbols required by codesign)
  *-windows-*  : no-op (Rust strips natively at link time via codegen profile)
EOF
  print_help_footer
}

case "${1:-}" in
  -h|--help|"") usage; [[ -z "${1:-}" ]] && exit 1 || exit 0 ;;
esac

target=$1
is_target_eligible "$target" || die "unknown target: $target"

bin=$(binary_for_target "$target")
[[ -f "$bin" ]] || die "binary not found: $bin (run build-target.sh first)"

case "$target" in
  *-pc-windows-*)
    info "windows target — skipping strip (rustc already stripped)"
    ;;
  *-apple-darwin)
    if have_cmd strip; then
      strip -x "$bin"
      info "stripped (apple): $bin"
    else
      warn "strip not available; skipping"
    fi
    ;;
  *-unknown-linux-*)
    # Pick the toolchain-appropriate strip when cross-compiling.
    host=$(host_triple)
    stripcmd=strip
    if [[ "$host" != "$target" ]]; then
      case "$target" in
        aarch64-unknown-linux-gnu)  have_cmd aarch64-linux-gnu-strip  && stripcmd=aarch64-linux-gnu-strip ;;
        aarch64-unknown-linux-musl) have_cmd aarch64-linux-musl-strip && stripcmd=aarch64-linux-musl-strip ;;
        x86_64-unknown-linux-musl)  have_cmd x86_64-linux-musl-strip  && stripcmd=x86_64-linux-musl-strip ;;
      esac
      # Fall back to llvm-strip (architecture-agnostic) if no specific tool.
      if [[ "$stripcmd" == "strip" ]] && have_cmd llvm-strip; then
        stripcmd=llvm-strip
      fi
    fi
    if have_cmd "$stripcmd"; then
      "$stripcmd" --strip-unneeded "$bin"
      info "stripped ($stripcmd): $bin"
    else
      warn "$stripcmd not found; skipping strip"
    fi
    ;;
  *)
    warn "unknown OS family for $target; skipping strip"
    ;;
esac
