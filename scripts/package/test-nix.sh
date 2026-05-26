#!/usr/bin/env bash
# Smoke test for the Nix derivation.
#
# Local mode (no Nix installed): grep-validate that default.nix contains the
# expected attributes (pname, version, src, cargoLock/cargoHash, meta).
#
# Release mode (Nix on PATH): run `nix-instantiate --eval` to confirm the
# derivation evaluates without errors; a full `nix-build` is gated behind
# SPT_PKG_RELEASE_MODE=1 since it pulls the full Rust toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NIXFILE="${ROOT}/packaging/nix/default.nix"

if [[ ! -f "${NIXFILE}" ]]; then
  echo "ERROR: missing ${NIXFILE}" >&2
  exit 1
fi

# 1. Required attributes.
for attr in pname version src meta; do
  if ! grep -qE "${attr}[[:space:]]*=" "${NIXFILE}"; then
    echo "ERROR: ${NIXFILE} missing attribute ${attr}" >&2
    exit 1
  fi
done

# 2. Either cargoLock or cargoHash must be present (rustPlatform requirement).
if ! grep -qE 'cargo(Lock|Hash)' "${NIXFILE}"; then
  echo "ERROR: ${NIXFILE} declares no cargoLock/cargoHash" >&2
  exit 1
fi

# 3. Nix eval (if available). default.nix is a callPackage-style derivation
#    (its argument set has no `...`), so it must be invoked via callPackage:
#    `import ${NIXFILE} (import <nixpkgs> {})` passes the whole nixpkgs set and
#    Nix rejects it with "called with unexpected argument". callPackage selects
#    only the matching args. `--eval` (lazy) avoids forcing the src fetch, so
#    the unresolved <NIX_HASH> placeholder does not error here.
if command -v nix-instantiate >/dev/null 2>&1; then
  nix-instantiate --eval --expr "(import <nixpkgs> {}).callPackage ${NIXFILE} {}" \
    >/dev/null
fi

# 4. Full build only in release mode + Nix installed. Same callPackage
#    requirement as the eval above (nix-build on the raw function would hit the
#    "called with unexpected argument" error).
if [[ "${SPT_PKG_RELEASE_MODE:-0}" == "1" ]] && command -v nix-build >/dev/null 2>&1; then
  nix-build -E "(import <nixpkgs> {}).callPackage ${NIXFILE} {}"
fi

echo "OK: nix smoke (mode=${SPT_PKG_RELEASE_MODE:-local})"
