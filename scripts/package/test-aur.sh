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
  # PKGBUILDs ship <PLACEHOLDER> tokens (e.g. <VERSION>, <SHA256_*>) that the
  # release pipeline substitutes at tag time. A bare `pkgver=<VERSION>` is not
  # valid bash, so `bash -n` on the raw template is a guaranteed syntax error.
  # Substitute dummy-but-syntactically-valid values into a temp copy and run
  # `bash -n` on that to catch real syntax mistakes.
  local tmp
  tmp="$(mktemp)"
  sed -e 's|<VERSION>|0.0.0|g' \
      -e 's|<SHA256[A-Z0-9_]*>|0000000000000000000000000000000000000000000000000000000000000000|g' \
      "${f}" >"${tmp}"
  bash -n "${tmp}"
  rm -f "${tmp}"
  # Required metadata fields. `source` may be a plain array (`source=`) or
  # per-arch (`source_x86_64=` / `source_aarch64=` in the -bin recipe).
  for field in pkgname pkgver pkgdesc arch license; do
    if ! grep -qE "^${field}=" "${f}"; then
      echo "ERROR: ${f} missing field ${field}" >&2
      exit 1
    fi
  done
  if ! grep -qE "^source(_[a-z0-9_]+)?=" "${f}"; then
    echo "ERROR: ${f} missing field source" >&2
    exit 1
  fi
  # Placeholder-integrity check (mirrors test-homebrew.sh): every <PLACEHOLDER>
  # in the template must be one of the documented set, so a typo can't survive
  # into the release substitution step.
  local known_placeholders="<VERSION> <SHA256_SRC_TAR> <SHA256_LINUX_AMD64> <SHA256_LINUX_ARM64>"
  while IFS= read -r p; do
    case " ${known_placeholders} " in
      *" ${p} "*) ;;
      *) echo "ERROR: ${f} has unknown placeholder ${p}" >&2; exit 1 ;;
    esac
  done < <(grep -oE '<[A-Z0-9_]+>' "${f}" | sort -u)
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
