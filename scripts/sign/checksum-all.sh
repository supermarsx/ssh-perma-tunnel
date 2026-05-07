#!/usr/bin/env bash
# checksum-all.sh — produce SHA256SUMS / SHA512SUMS / B3SUMS over dist/<version>/.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/sign/checksum-all.sh

Walks every artifact under dist/<version>/ and writes:
  SHA256SUMS
  SHA512SUMS
  B3SUMS       (only if b3sum is on PATH)

If LINUX_GPG_KEY (key id) is set, also produces SHA256SUMS.asc by detach-signing.
Otherwise GPG signing is skipped with a warn line.

Idempotent — overwrites existing checksum files.
EOF
  print_help_footer
}

case "${1:-}" in -h|--help) usage; exit 0 ;; esac

dist=$(dist_dir)
[[ -d "$dist" ]] || die "dist dir missing: $dist"

cd "$dist"

# Collect every regular file except previous checksum/sig outputs.
# Portable: we cd'd into dist/ above, so `find -maxdepth 1` yields ./<name>;
# strip the leading ./ via parameter expansion below.
shopt -s nullglob
files=()
for f in *; do
  [[ -f "$f" ]] || continue
  case "$f" in
    SHA256SUMS*|SHA512SUMS*|B3SUMS*|*.minisig|*.sig|*.asc) continue ;;
  esac
  files+=("$f")
done
IFS=$'\n' files=($(printf '%s\n' "${files[@]}" | sort)); unset IFS

if (( ${#files[@]} == 0 )); then
  warn "no artifacts under $dist; nothing to checksum"
  exit 0
fi

: > SHA256SUMS
: > SHA512SUMS
have_b3=0
have_cmd b3sum && have_b3=1
(( have_b3 )) && : > B3SUMS

for f in "${files[@]}"; do
  if have_cmd sha256sum; then
    sha256sum "$f" >> SHA256SUMS
  elif have_cmd shasum; then
    shasum -a 256 "$f" >> SHA256SUMS
  else
    die "no sha256sum/shasum on PATH"
  fi

  if have_cmd sha512sum; then
    sha512sum "$f" >> SHA512SUMS
  elif have_cmd shasum; then
    shasum -a 512 "$f" >> SHA512SUMS
  fi

  if (( have_b3 )); then
    b3sum "$f" >> B3SUMS
  fi
done

info "wrote SHA256SUMS / SHA512SUMS$( (( have_b3 )) && echo ' / B3SUMS' )"

if [[ -n "${LINUX_GPG_KEY:-}" ]]; then
  if have_cmd gpg; then
    info "gpg detach-signing SHA256SUMS as $LINUX_GPG_KEY"
    gpg --batch --yes --local-user "$LINUX_GPG_KEY" --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
  else
    warn "LINUX_GPG_KEY set but gpg not on PATH; skipping detach-sign"
  fi
else
  warn "LINUX_GPG_KEY unset; skipping GPG detach-signature on SHA256SUMS"
fi
