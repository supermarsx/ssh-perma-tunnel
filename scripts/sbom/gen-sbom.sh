#!/usr/bin/env bash
# gen-sbom.sh — produce CycloneDX SBOMs (json + xml) for spt-bin.
#
# Output:
#   dist/<version>/sbom.json
#   dist/<version>/sbom.xml

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

# Pinned to the last 0.5.x release, which is known to compile under MSRV 1.83.
# 0.6+ may bump dependencies past edition2024.
CYCLONEDX_VERSION_PIN="0.5.7"

usage() {
  cat <<EOF
Usage: scripts/sbom/gen-sbom.sh [--no-install]

Generates CycloneDX SBOMs (JSON + XML) for the spt-bin crate via
\`cargo cyclonedx\`. If cargo-cyclonedx is missing, attempts to install
version $CYCLONEDX_VERSION_PIN (override with --no-install for hermetic CI).

Outputs to dist/<version>/sbom.json and dist/<version>/sbom.xml.
EOF
  print_help_footer
}

no_install=0
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --no-install) no_install=1; shift ;;
    *) die "unknown flag: $1" ;;
  esac
done

if ! cargo cyclonedx --help >/dev/null 2>&1; then
  if (( no_install )); then
    warn "cargo-cyclonedx missing and --no-install set; skipping SBOM"
    exit 0
  fi
  info "installing cargo-cyclonedx@$CYCLONEDX_VERSION_PIN"
  if ! cargo install --locked "cargo-cyclonedx@$CYCLONEDX_VERSION_PIN"; then
    warn "cargo install cargo-cyclonedx failed; skipping SBOM (rerun manually)"
    exit 0
  fi
fi

root=$(repo_root)
dist=$(ensure_dist_dir)

# cargo-cyclonedx 0.5 writes <pattern>.<format> next to the crate's Cargo.toml.
# We run from repo root and move the resulting files into dist/.
cd "$root"

(cd "$root" && cargo cyclonedx --format json --output-pattern bom -p spt-bin)
if [[ -f "$root/crates/spt-bin/bom.json" ]]; then
  mv -f "$root/crates/spt-bin/bom.json" "$dist/sbom.json"
elif [[ -f "$root/bom.json" ]]; then
  mv -f "$root/bom.json" "$dist/sbom.json"
fi

(cd "$root" && cargo cyclonedx --format xml --output-pattern bom -p spt-bin)
if [[ -f "$root/crates/spt-bin/bom.xml" ]]; then
  mv -f "$root/crates/spt-bin/bom.xml" "$dist/sbom.xml"
elif [[ -f "$root/bom.xml" ]]; then
  mv -f "$root/bom.xml" "$dist/sbom.xml"
fi

[[ -f "$dist/sbom.json" ]] && info "wrote $dist/sbom.json" || warn "sbom.json missing"
[[ -f "$dist/sbom.xml"  ]] && info "wrote $dist/sbom.xml"  || warn "sbom.xml missing"
