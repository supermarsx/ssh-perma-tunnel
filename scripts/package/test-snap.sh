#!/usr/bin/env bash
# Smoke test for the Snap recipe.
#
# Local mode: validates that snapcraft.yaml parses as YAML and contains the
# required keys. Snap Store publishing requires snapcraft credentials we
# don't have in CI, so we stop short of an actual build.
#
# Release mode (SPT_PKG_RELEASE_MODE=1, runs only when snapcraft is on PATH):
# invokes `snapcraft pack --destructive-mode` to build the .snap artefact.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
YAML="${ROOT}/packaging/snap/snapcraft.yaml"

if [[ ! -f "${YAML}" ]]; then
  echo "ERROR: missing ${YAML}" >&2
  exit 1
fi

# 1. YAML parse — prefer python3 (always present on ubuntu-latest).
python3 - <<PY
import sys, yaml
with open("${YAML}", "r", encoding="utf-8") as fh:
    doc = yaml.safe_load(fh)
required = ["name", "summary", "description", "base", "parts", "apps"]
missing = [k for k in required if k not in doc]
if missing:
    print(f"ERROR: snapcraft.yaml missing keys: {missing}", file=sys.stderr)
    sys.exit(1)
if "spt" not in doc["apps"]:
    print("ERROR: snapcraft.yaml apps must include 'spt'", file=sys.stderr)
    sys.exit(1)
print("snapcraft.yaml: keys ok")
PY

if [[ "${SPT_PKG_RELEASE_MODE:-0}" == "1" ]] && command -v snapcraft >/dev/null 2>&1; then
  pushd "${ROOT}/packaging/snap" >/dev/null
  snapcraft pack --destructive-mode
  popd >/dev/null
fi

echo "OK: snap smoke (mode=${SPT_PKG_RELEASE_MODE:-local})"
