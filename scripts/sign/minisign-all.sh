#!/usr/bin/env bash
# minisign-all.sh — minisign every artifact under dist/<version>/.
#
# Reads the secret key from $MINISIGN_SECRET_KEY (whole file contents, not a
# path). Optional password from $MINISIGN_PASSWORD (passed via -W env entry).
# Skips with a warn line if MINISIGN_SECRET_KEY is unset.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/sign/minisign-all.sh

Signs every file under dist/<version>/ with minisign, emitting <file>.minisig
alongside it. Idempotent — re-running re-signs files (overwriting prior sigs).

Required env:
  MINISIGN_SECRET_KEY   raw contents of the secret key file (multi-line OK)
Optional env:
  MINISIGN_PASSWORD     password for the key (uses minisign -W <file>)
EOF
  print_help_footer
}

case "${1:-}" in -h|--help) usage; exit 0 ;; esac

if [[ -z "${MINISIGN_SECRET_KEY:-}" ]]; then
  warn "MINISIGN_SECRET_KEY unset; skipping minisign"
  exit 0
fi

if ! have_cmd minisign; then
  warn "minisign not on PATH; skipping. Install: https://jedisct1.github.io/minisign/"
  exit 0
fi

dist=$(dist_dir)
[[ -d "$dist" ]] || die "dist dir missing: $dist"

# Stage the secret key in a tmp file with restrictive perms.
sk_file=$(mktemp -t spt-minisign-sk.XXXXXX)
chmod 600 "$sk_file"
printf '%s\n' "$MINISIGN_SECRET_KEY" > "$sk_file"

# Optional password file.
pw_file=
if [[ -n "${MINISIGN_PASSWORD:-}" ]]; then
  pw_file=$(mktemp -t spt-minisign-pw.XXXXXX)
  chmod 600 "$pw_file"
  printf '%s' "$MINISIGN_PASSWORD" > "$pw_file"
fi

cleanup() {
  rm -f "$sk_file" ${pw_file:+"$pw_file"}
}
trap cleanup EXIT

shopt -s nullglob
cd "$dist"
for f in *; do
  [[ -f "$f" ]] || continue
  case "$f" in
    *.minisig|*.sig|*.asc) continue ;;
  esac
  args=(-Sm "$f" -s "$sk_file")
  if [[ -n "$pw_file" ]]; then
    # Newer minisign supports `-W` to skip interactive prompt for empty passwords;
    # for non-empty, pipe via stdin redirection.
    minisign "${args[@]}" < "$pw_file"
  else
    minisign -W "${args[@]}"
  fi
  info "signed: $f -> $f.minisig"
done

info "minisign run complete"
