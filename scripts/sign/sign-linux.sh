#!/usr/bin/env bash
# sign-linux.sh — GPG detach-sign every artifact under dist/<version>/.
#
# Optional. Requires LINUX_GPG_KEY (key id or fingerprint). Without it, the
# script logs a warn line and exits 0.
#
# This is the per-artifact GPG complement to checksum-all.sh's optional
# detach-signature on SHA256SUMS.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/sign/sign-linux.sh

Detach-signs every release artifact in dist/<version>/ with the GPG key
identified by \$LINUX_GPG_KEY. Each <file> gets a sibling <file>.asc.

Required env:
  LINUX_GPG_KEY    GPG key id or fingerprint (e.g. 0xDEADBEEF)
EOF
  print_help_footer
}

case "${1:-}" in -h|--help) usage; exit 0 ;; esac

if [[ -z "${LINUX_GPG_KEY:-}" ]]; then
  warn "LINUX_GPG_KEY unset; skipping GPG signing"
  exit 0
fi

if ! have_cmd gpg; then
  warn "gpg not on PATH; skipping"
  exit 0
fi

dist=$(dist_dir)
[[ -d "$dist" ]] || die "dist dir missing: $dist"

shopt -s nullglob
cd "$dist"
for f in *; do
  [[ -f "$f" ]] || continue
  case "$f" in
    *.asc|*.minisig|*.sig) continue ;;
  esac
  info "gpg --detach-sign $f"
  gpg --batch --yes --local-user "$LINUX_GPG_KEY" --armor --detach-sign --output "$f.asc" "$f"
done

info "GPG sign run complete"
