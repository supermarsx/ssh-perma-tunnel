#!/usr/bin/env bash
# Smoke test for the Homebrew formula.
#
# Local mode (no published release): validates that the Ruby formula parses
# and the placeholders are well-formed. We do NOT attempt `brew install`
# locally because the formula references release tarballs that only exist on
# tagged releases.
#
# Release mode: gated in CI behind `github.event_name == 'release'`; performs
# a full `brew tap` + `brew install` against the published artifact.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FORMULA="${ROOT}/packaging/homebrew/spt.rb"

if [[ ! -f "${FORMULA}" ]]; then
  echo "ERROR: missing ${FORMULA}" >&2
  exit 1
fi

# 1. Ruby syntax check (works on any runner with Ruby installed).
ruby -c "${FORMULA}" >/dev/null

# 2. Placeholder integrity check — every <PLACEHOLDER> must be one of the
#    documented set (avoid typos surviving into the release pipeline).
expected_placeholders=(
  "<VERSION>"
  "<SHA256_MACOS_ARM64>"
  "<SHA256_MACOS_AMD64>"
  "<SHA256_LINUX_ARM64>"
  "<SHA256_LINUX_AMD64>"
)
for p in "${expected_placeholders[@]}"; do
  if ! grep -qF "${p}" "${FORMULA}"; then
    echo "ERROR: formula is missing placeholder ${p}" >&2
    exit 1
  fi
done

# 3. Release-mode install (only when SPT_PKG_RELEASE_MODE=1 — typically set
#    by the CI workflow on a `release` event after artefacts are published).
if [[ "${SPT_PKG_RELEASE_MODE:-0}" == "1" ]]; then
  if ! command -v brew >/dev/null 2>&1; then
    echo "ERROR: brew not on PATH in release mode" >&2
    exit 1
  fi
  tap_root="$(brew --repository)/Library/Taps/local/homebrew-spt"
  mkdir -p "${tap_root}/Formula"
  cp "${FORMULA}" "${tap_root}/Formula/spt.rb"
  brew install --formula local/spt/spt
  spt --version
fi

echo "OK: homebrew smoke (mode=${SPT_PKG_RELEASE_MODE:-local})"
