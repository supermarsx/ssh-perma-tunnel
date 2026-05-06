#!/usr/bin/env bash
# Build a macOS `.pkg` installer for spt.
#
# Layout:
#   /usr/local/bin/spt
#   /Library/LaunchDaemons/com.mariana.spt.plist
#
# Run on a macOS host with the Apple developer tooling installed:
#
#   cargo build --release -p spt-bin
#   bash packaging/pkg/build.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${ROOT}/target/pkg-build"
PAYLOAD="${WORK}/payload"
VERSION="$(cargo pkgid -p spt-bin | sed 's/.*#//')"

rm -rf "${WORK}"
mkdir -p "${PAYLOAD}/usr/local/bin" "${PAYLOAD}/Library/LaunchDaemons"
install -m 0755 "${ROOT}/target/release/spt" "${PAYLOAD}/usr/local/bin/spt"
install -m 0644 "${ROOT}/packaging/pkg/com.mariana.spt.plist" \
    "${PAYLOAD}/Library/LaunchDaemons/com.mariana.spt.plist"

pkgbuild \
    --root "${PAYLOAD}" \
    --identifier com.mariana.spt \
    --version "${VERSION}" \
    --install-location / \
    "${WORK}/spt-${VERSION}-component.pkg"

productbuild \
    --package "${WORK}/spt-${VERSION}-component.pkg" \
    --identifier com.mariana.spt \
    --version "${VERSION}" \
    "${ROOT}/target/spt-${VERSION}.pkg"

echo "wrote ${ROOT}/target/spt-${VERSION}.pkg"
