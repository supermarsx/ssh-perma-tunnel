#!/usr/bin/env bash
# Smoke test for the two AUR PKGBUILDs (`spt` source build, `spt-bin` binary).
#
# Local mode: shellcheck the PKGBUILD as bash, plus a sanity scan for required
# pkg fields. We avoid `makepkg` here because it requires an Arch userspace.
#
# Release mode (SPT_PKG_RELEASE_MODE=1, on Arch Linux): runs `makepkg --nodeps
# --noconfirm -f` to confirm the recipes build end-to-end.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

check_pkgbuild() {
  local f="$1"
  [[ -f "${f}" ]] || { echo "ERROR: missing ${f}" >&2; exit 1; }
  # bash -n catches gross syntax errors; PKGBUILDs are valid bash.
  bash -n "${f}"
  for field in pkgname pkgver pkgdesc arch license source; do
    if ! grep -qE "^${field}=" "${f}"; then
      echo "ERROR: ${f} missing field ${field}" >&2
      exit 1
    fi
  done
  echo "PKGBUILD ok: ${f}"
}

check_pkgbuild "${ROOT}/packaging/aur/PKGBUILD"
check_pkgbuild "${ROOT}/packaging/aur/PKGBUILD-bin"

if [[ "${SPT_PKG_RELEASE_MODE:-0}" == "1" ]] && command -v makepkg >/dev/null 2>&1; then
  for f in "${ROOT}/packaging/aur/PKGBUILD" "${ROOT}/packaging/aur/PKGBUILD-bin"; do
    workdir="$(mktemp -d)"
    cp "${f}" "${workdir}/PKGBUILD"
    pushd "${workdir}" >/dev/null
    makepkg --nodeps --noconfirm -f
    popd >/dev/null
    rm -rf "${workdir}"
  done
fi

echo "OK: aur smoke (mode=${SPT_PKG_RELEASE_MODE:-local})"
