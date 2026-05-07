#!/usr/bin/env bash
# sign-macos.sh — codesign + notarize the macOS .pkg under dist/<version>/.
#
# All signing/notarizing is optional. If env vars aren't set, this script
# logs a warn line and exits 0 — the .pkg is left unsigned.

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/sign/sign-macos.sh [--pkg <path>]

Codesigns and (optionally) notarizes a macOS .pkg.

Required env (signing):
  MACOS_SIGNING_IDENTITY     "Developer ID Installer: ..." identity name

Optional env (notarization, all required together):
  MACOS_NOTARY_USER          Apple ID
  MACOS_NOTARY_PASSWORD      app-specific password
  MACOS_NOTARY_TEAM_ID       team id
  -- OR --
  MACOS_NOTARY_KEY_PATH      App Store Connect API key (.p8)
  MACOS_NOTARY_KEY_ID        key id
  MACOS_NOTARY_ISSUER        issuer id

Without signing identity: warn and exit 0 (unsigned ship).
With signing but no notary creds: signed but not notarized.
EOF
  print_help_footer
}

pkg=
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --pkg) pkg=$2; shift 2 ;;
    --pkg=*) pkg=${1#*=}; shift ;;
    *) die "unknown flag: $1" ;;
  esac
done

if [[ -z "${MACOS_SIGNING_IDENTITY:-}" ]]; then
  warn "MACOS_SIGNING_IDENTITY unset; leaving .pkg unsigned"
  exit 0
fi

if ! have_cmd productsign; then
  warn "productsign not available (not on macOS); skipping"
  exit 0
fi

dist=$(dist_dir)
if [[ -z "$pkg" ]]; then
  pkg=$(ls "$dist"/*.pkg 2>/dev/null | head -n1 || true)
  [[ -n "$pkg" ]] || { warn "no .pkg found in $dist; nothing to sign"; exit 0; }
fi
[[ -f "$pkg" ]] || die "pkg not found: $pkg"

signed="${pkg%.pkg}-signed.pkg"
info "productsign $pkg -> $signed"
productsign --sign "$MACOS_SIGNING_IDENTITY" "$pkg" "$signed"
mv "$signed" "$pkg"
info "signed: $pkg"

# Notarize if creds present.
if have_cmd xcrun; then
  if [[ -n "${MACOS_NOTARY_KEY_PATH:-}" && -n "${MACOS_NOTARY_KEY_ID:-}" && -n "${MACOS_NOTARY_ISSUER:-}" ]]; then
    info "notarytool submit (API key) $pkg"
    xcrun notarytool submit "$pkg" \
      --key "$MACOS_NOTARY_KEY_PATH" \
      --key-id "$MACOS_NOTARY_KEY_ID" \
      --issuer "$MACOS_NOTARY_ISSUER" \
      --wait
    xcrun stapler staple "$pkg"
    info "notarized + stapled: $pkg"
  elif [[ -n "${MACOS_NOTARY_USER:-}" && -n "${MACOS_NOTARY_PASSWORD:-}" && -n "${MACOS_NOTARY_TEAM_ID:-}" ]]; then
    info "notarytool submit (Apple ID) $pkg"
    xcrun notarytool submit "$pkg" \
      --apple-id "$MACOS_NOTARY_USER" \
      --password "$MACOS_NOTARY_PASSWORD" \
      --team-id  "$MACOS_NOTARY_TEAM_ID" \
      --wait
    xcrun stapler staple "$pkg"
    info "notarized + stapled: $pkg"
  else
    warn "notarization creds incomplete; signed but not notarized"
  fi
else
  warn "xcrun not available; cannot notarize"
fi
