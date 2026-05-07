#!/usr/bin/env bash
# pack-pkg-macos.sh — build a signed-or-unsigned macOS installer .pkg.
#
# Expects the universal binary at target/universal-apple-darwin/release/spt
# (run scripts/build/lipo-macos.sh first).
#
# Output: dist/<version>/spt-<version>-universal.pkg

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/package/pack-pkg-macos.sh [--dry-run]

Builds a macOS installer .pkg for the universal binary. Runs pkgbuild +
productbuild against packaging/pkg/Resources/ and packaging/pkg/distribution.xml
(stub files are created on first run if absent).

Requires macOS host with pkgbuild + productbuild available.
EOF
  print_help_footer
}

dry_run=0
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --dry-run) dry_run=1; shift ;;
    *) die "unknown flag: $1" ;;
  esac
done

if ! have_cmd pkgbuild || ! have_cmd productbuild; then
  warn "pkgbuild/productbuild not available (macOS only); skipping"
  exit 0
fi

root=$(repo_root)
version=$(version_from_cargo)
dist=$(ensure_dist_dir)

universal="$root/target/universal-apple-darwin/release/spt"
[[ -f "$universal" ]] || die "universal binary missing — run scripts/build/lipo-macos.sh first"

resources_dir="$root/packaging/pkg/Resources"
distribution_xml="$root/packaging/pkg/distribution.xml"

# Stub Resources/welcome.html on first run.
if [[ ! -d "$resources_dir" ]]; then
  info "creating stub $resources_dir"
  mkdir -p "$resources_dir"
  cat >"$resources_dir/welcome.html" <<'HTML'
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>spt</title></head>
<body>
<h1>spt</h1>
<p>Permanent SSH tunnels with reconnect, observability, and service integration.</p>
<p>This installer places <code>spt</code> at <code>/usr/local/bin/spt</code> and man pages
under <code>/usr/local/share/man/man1/</code>.</p>
</body></html>
HTML
fi

# Stub distribution.xml on first run.
if [[ ! -f "$distribution_xml" ]]; then
  info "creating stub $distribution_xml"
  cat >"$distribution_xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>spt</title>
    <organization>com.spt</organization>
    <welcome    file="welcome.html"/>
    <options customize="never" require-scripts="false" hostArchitectures="x86_64,arm64"/>
    <choices-outline>
        <line choice="default">
            <line choice="com.spt.cli"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="com.spt.cli" visible="false">
        <pkg-ref id="com.spt.cli"/>
    </choice>
    <pkg-ref id="com.spt.cli" version="$version" onConclusion="none">spt-component.pkg</pkg-ref>
</installer-gui-script>
XML
fi

work=$(mktemp -d -t spt-pkg.XXXXXX)
trap 'rm -rf "$work"' EXIT

staging="$work/payload"
mkdir -p "$staging/usr/local/bin" "$staging/usr/local/share/man/man1"
install -m 0755 "$universal" "$staging/usr/local/bin/spt"
if [[ -d "$root/packaging/man" ]]; then
  cp "$root"/packaging/man/spt*.1 "$staging/usr/local/share/man/man1/" 2>/dev/null || true
fi

component="$work/spt-component.pkg"
final="$dist/spt-$version-universal.pkg"

cmd_component=(pkgbuild
  --root "$staging"
  --identifier com.spt.cli
  --version "$version"
  --install-location /
  "$component")

cmd_product=(productbuild
  --package "$component"
  --resources "$resources_dir"
  --distribution "$distribution_xml"
  "$final")

info "pkgbuild: ${cmd_component[*]}"
info "productbuild: ${cmd_product[*]}"
if (( dry_run )); then exit 0; fi

"${cmd_component[@]}"
"${cmd_product[@]}"

info "produced: $final"
echo "$final"
