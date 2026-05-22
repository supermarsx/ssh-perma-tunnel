#!/usr/bin/env bash
# Smoke test for the Flatpak / Flathub manifest.
#
# Local mode: parses io.spt.spt.yaml and metainfo.xml; verifies required
# fields. Building a real Flatpak requires `flatpak-builder` plus a runtime
# download (~300MB); skipped unless SPT_PKG_RELEASE_MODE=1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MANIFEST="${ROOT}/packaging/flatpak/io.spt.spt.yaml"
METAINFO="${ROOT}/packaging/flatpak/io.spt.spt.metainfo.xml"

for f in "${MANIFEST}" "${METAINFO}"; do
  [[ -f "${f}" ]] || { echo "ERROR: missing ${f}" >&2; exit 1; }
done

# 1. YAML manifest sanity.
python3 - <<PY
import sys, yaml
with open("${MANIFEST}", "r", encoding="utf-8") as fh:
    doc = yaml.safe_load(fh)
required = ["app-id", "runtime", "runtime-version", "sdk", "command", "modules"]
missing = [k for k in required if k not in doc]
if missing:
    print(f"ERROR: flatpak manifest missing keys: {missing}", file=sys.stderr)
    sys.exit(1)
if doc.get("app-id") != "io.spt.spt":
    print(f"ERROR: app-id must be io.spt.spt, got {doc.get('app-id')!r}", file=sys.stderr)
    sys.exit(1)
print("flatpak manifest: keys ok")
PY

# 2. AppStream metainfo XML parse.
python3 - <<PY
import sys, xml.etree.ElementTree as ET
tree = ET.parse("${METAINFO}")
root = tree.getroot()
if root.tag != "component":
    print(f"ERROR: metainfo root must be <component>, got <{root.tag}>", file=sys.stderr)
    sys.exit(1)
print("flatpak metainfo: parsed ok")
PY

# 3. Optional real build.
if [[ "${SPT_PKG_RELEASE_MODE:-0}" == "1" ]] && command -v flatpak-builder >/dev/null 2>&1; then
  pushd "${ROOT}/packaging/flatpak" >/dev/null
  flatpak-builder --force-clean --user --install-deps-from=flathub \
    build-dir io.spt.spt.yaml
  popd >/dev/null
fi

echo "OK: flatpak smoke (mode=${SPT_PKG_RELEASE_MODE:-local})"
