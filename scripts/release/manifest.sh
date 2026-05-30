#!/usr/bin/env bash
# manifest.sh — emit a typed release-manifest.json describing every
# artifact in dist/<version>/.
#
# Schema (release-manifest v1):
#
#   {
#     "schema": "release-manifest",
#     "schema_version": 1,
#     "release": {
#       "tag": "<YY.N>",                 // user-facing rolling tag (no `v` prefix)
#       "cargo_version": "0.<YY.N>",     // workspace Cargo.toml version
#       "git_sha": "<full 40-char hex>",
#       "git_short_sha": "<7-char hex>",
#       "build_date": "<ISO 8601 UTC>",
#       "repository": "https://github.com/<owner>/<repo>",
#       "release_url": "<repo>/releases/tag/<tag>"
#     },
#     "checksums": {
#       "sha256sums": "SHA256SUMS",     // present if `checksum-all.sh` ran
#       "sha512sums": "SHA512SUMS",
#       "b3sums": "B3SUMS"              // present iff b3sum was on PATH
#     },
#     "signatures": {
#       "gpg_sha256sums": "SHA256SUMS.asc",  // null when LINUX_GPG_KEY unset
#       "minisign_pubkey": "minisign.pub"    // referenced by sig fields below
#     },
#     "sbom": {                          // present if scripts/sbom/gen-sbom.sh ran
#       "cyclonedx_json": "spt-<tag>.cdx.json",
#       "cyclonedx_xml":  "spt-<tag>.cdx.xml",
#       "spdx_json":      "spt-<tag>.spdx.json"
#     },
#     "artifacts": [
#       {
#         "name":      "<filename>",
#         "kind":      "package|binary|checksum|signature|sbom|notes|other",
#         "format":    "deb|rpm|pkg|msi|tar.gz|zip|json|xml|asc|minisig|md|...",
#         "target":    "<rust target triple>" | null,
#         "os":        "linux|macos|windows" | null,
#         "arch":      "amd64|arm64|universal" | null,
#         "size":      <bytes>,
#         "sha256":    "<hex>",
#         "sha512":    "<hex>" | null,
#         "blake3":    "<hex>" | null,
#         "minisign":  "<filename.minisig>" | null,
#         "media_type": "application/<...>" | null
#       },
#       ...
#     ]
#   }
#
# Companion JSON Schema lives at scripts/release/manifest.schema.json.
#
# Idempotent. Sorted by artifact name (NFC).

set -euo pipefail

# shellcheck source=../build/_common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/../build/_common.sh"

usage() {
  cat <<EOF
Usage: scripts/release/manifest.sh

Produces dist/<version>/release-manifest.json. See the script header for
the schema; the companion JSON Schema is in
scripts/release/manifest.schema.json.
EOF
  print_help_footer
}

case "${1:-}" in -h|--help) usage; exit 0 ;; esac

dist=$(dist_dir)
[[ -d "$dist" ]] || die "dist dir missing: $dist"

cargo_version=$(version_from_cargo)
# Strip leading `0.` to get the user-facing rolling tag (`0.26.3` → `26.3`).
tag=${cargo_version#0.}
git_sha=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
git_short_sha=$(git rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")
date_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
manifest="$dist/release-manifest.json"

# Repository URL: honour GITHUB_REPOSITORY when set (CI), otherwise derive
# from git's origin remote, falling back to the project's canonical home.
if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
  repo_url="https://github.com/${GITHUB_REPOSITORY}"
else
  remote=$(git config --get remote.origin.url 2>/dev/null || true)
  case "$remote" in
    git@github.com:*) repo_url="https://github.com/${remote#git@github.com:}"; repo_url="${repo_url%.git}" ;;
    https://github.com/*) repo_url="${remote%.git}" ;;
    *) repo_url="https://github.com/supermarsx/ssh-perma-tunnel" ;;
  esac
fi
release_url="${repo_url}/releases/tag/${tag}"

# ----- artifact classification -------------------------------------------
#
# Each artifact is bucketed by extension + name. The triple is recovered
# from the embedded version + arch token where possible (cargo-deb,
# cargo-generate-rpm, and pack-tarball.sh all encode the triple in the
# filename); when not derivable, target/os/arch are reported as null and
# the consumer can fall back to the `kind` + `format` fields.

classify() {
  # $1 = filename → emits:  kind\tformat\ttarget\tos\tarch\tmedia_type
  local f=$1
  local lower=${f,,}
  case "$lower" in
    # ---- SBOMs ----
    *.cdx.json|*-cyclonedx*.json|*sbom*.json)
      printf 'sbom|cyclonedx-json||||application/vnd.cyclonedx+json'; return ;;
    *.cdx.xml|*-cyclonedx*.xml|*sbom*.xml)
      printf 'sbom|cyclonedx-xml||||application/vnd.cyclonedx+xml'; return ;;
    *.spdx.json)
      printf 'sbom|spdx-json||||application/spdx+json'; return ;;
    *.spdx)
      printf 'sbom|spdx-tag-value||||text/plain'; return ;;

    # ---- Checksums / signatures ----
    sha256sums|sha512sums|b3sums)
      printf 'checksum|%s||||text/plain' "$lower"; return ;;
    sha256sums.asc|sha512sums.asc|*.asc)
      printf 'signature|gpg-armor||||application/pgp-signature'; return ;;
    minisign.pub)
      printf 'signature|minisign-pub||||text/plain'; return ;;
    *.minisig)
      printf 'signature|minisign||||application/octet-stream'; return ;;

    # ---- Release manifest (this file) ----
    release-manifest.json)
      printf 'other|manifest||||application/json'; return ;;

    # ---- Release notes ----
    changelog-fragment.md|*.md|notes-*.md)
      printf 'notes|markdown||||text/markdown'; return ;;
  esac

  # ---- Packages / binaries (derive target triple from filename) ----
  local target="" os="" arch=""
  # Common triples we emit.
  for t in \
    x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
    aarch64-apple-darwin universal-apple-darwin \
    x86_64-pc-windows-msvc aarch64-pc-windows-msvc ; do
    if [[ "$lower" == *"$t"* ]]; then target=$t; break; fi
  done
  case "$target" in
    *linux*)  os=linux ;;
    *darwin*) os=macos ;;
    *windows*)os=windows ;;
  esac
  case "$target" in
    x86_64-*)    arch=amd64 ;;
    aarch64-*)   arch=arm64 ;;
    universal-*) arch=universal ;;
  esac

  case "$lower" in
    *.deb)    printf 'package|deb|%s|%s|%s|application/vnd.debian.binary-package' "$target" "$os" "$arch"; return ;;
    *.rpm)    printf 'package|rpm|%s|%s|%s|application/x-rpm' "$target" "$os" "$arch"; return ;;
    *.pkg)    printf 'package|macos-pkg|%s|%s|%s|application/x-newton-compatible-pkg' "$target" "$os" "$arch"; return ;;
    *.msi)    printf 'package|msi|%s|%s|%s|application/x-msi' "$target" "$os" "$arch"; return ;;
    *.tar.gz) printf 'package|tar-gz|%s|%s|%s|application/gzip' "$target" "$os" "$arch"; return ;;
    *.zip)    printf 'package|zip|%s|%s|%s|application/zip' "$target" "$os" "$arch"; return ;;
    spt|spt-*|spt.exe|spt-*.exe)
              printf 'binary|raw|%s|%s|%s|application/octet-stream' "$target" "$os" "$arch"; return ;;
  esac

  printf 'other|unknown||||application/octet-stream'
}

# ----- helpers ------------------------------------------------------------

# Look up a hash for $1 in a SHASUMS file. Returns empty if not present.
lookup_sum() {
  local file=$1 list=$2
  [[ -f "$list" ]] || { echo ""; return; }
  awk -v f="$file" '$2 == f || $2 == "*"f { print $1; exit }' "$list"
}

json_str() {
  # Escape a string for JSON. Uses python3 when available; falls back to a
  # minimal subset (backslash + dquote) otherwise. `printf %s` (no \n) and
  # `python3 sys.argv` (no stdin) keep trailing newlines out of values.
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys;sys.stdout.write(json.dumps(sys.argv[1]))' "$1"
  else
    printf '"%s"' "${1//\"/\\\"}"
  fi
}

json_null_or_str() {
  if [[ -z "$1" ]]; then echo "null"; else json_str "$1"; fi
}

# ----- walk dist/ ---------------------------------------------------------

shopt -s nullglob
cd "$dist"
mapfile -t files < <(
  for f in *; do
    [[ -f "$f" ]] || continue
    # Skip the manifest itself + minisign sigs (referenced inline below).
    case "$f" in
      release-manifest.json) continue ;;
      *.minisig) continue ;;
    esac
    printf '%s\n' "$f"
  done | LC_ALL=C sort
)

# Index optional SBOM filenames so the top-level `sbom` block can reference
# them without re-walking the directory.
sbom_cdx_json=""
sbom_cdx_xml=""
sbom_spdx_json=""
for f in "${files[@]}"; do
  case "${f,,}" in
    *.cdx.json|*-cyclonedx*.json|*sbom*.json) sbom_cdx_json=$f ;;
    *.cdx.xml|*-cyclonedx*.xml|*sbom*.xml)    sbom_cdx_xml=$f ;;
    *.spdx.json)                              sbom_spdx_json=$f ;;
  esac
done

# ----- emit ---------------------------------------------------------------

{
  printf '{\n'
  printf '  "schema": "release-manifest",\n'
  printf '  "schema_version": 1,\n'
  printf '  "release": {\n'
  printf '    "tag": %s,\n'            "$(json_str "$tag")"
  printf '    "cargo_version": %s,\n'  "$(json_str "$cargo_version")"
  printf '    "git_sha": %s,\n'        "$(json_str "$git_sha")"
  printf '    "git_short_sha": %s,\n'  "$(json_str "$git_short_sha")"
  printf '    "build_date": %s,\n'     "$(json_str "$date_iso")"
  printf '    "repository": %s,\n'     "$(json_str "$repo_url")"
  printf '    "release_url": %s\n'     "$(json_str "$release_url")"
  printf '  },\n'

  printf '  "checksums": {\n'
  printf '    "sha256sums": %s,\n' "$([[ -f SHA256SUMS ]] && json_str "SHA256SUMS" || echo null)"
  printf '    "sha512sums": %s,\n' "$([[ -f SHA512SUMS ]] && json_str "SHA512SUMS" || echo null)"
  printf '    "b3sums": %s\n'       "$([[ -f B3SUMS    ]] && json_str "B3SUMS"    || echo null)"
  printf '  },\n'

  printf '  "signatures": {\n'
  printf '    "gpg_sha256sums": %s,\n' "$([[ -f SHA256SUMS.asc ]] && json_str "SHA256SUMS.asc" || echo null)"
  printf '    "minisign_pubkey": %s\n' "$([[ -f minisign.pub   ]] && json_str "minisign.pub"   || echo null)"
  printf '  },\n'

  printf '  "sbom": {\n'
  printf '    "cyclonedx_json": %s,\n' "$(json_null_or_str "$sbom_cdx_json")"
  printf '    "cyclonedx_xml": %s,\n'  "$(json_null_or_str "$sbom_cdx_xml")"
  printf '    "spdx_json": %s\n'       "$(json_null_or_str "$sbom_spdx_json")"
  printf '  },\n'

  printf '  "artifacts": [\n'
  count=${#files[@]}
  i=0
  for f in "${files[@]}"; do
    i=$((i + 1))
    # Use `|` (non-whitespace) as the field separator so consecutive empty
    # fields aren't collapsed (POSIX read collapses adjacent IFS whitespace,
    # which \t counts as). Capture into a variable first — process
    # substitution + `set -e` + an empty trailing field interact badly here.
    classified=$(classify "$f")
    IFS='|' read -r kind format target os arch media_type <<<"$classified"

    if have_cmd sha256sum; then
      sha256=$(sha256sum "$f" | awk '{print $1}')
    else
      sha256=$(shasum -a 256 "$f" | awk '{print $1}')
    fi
    sha512=$(lookup_sum "$f" SHA512SUMS)
    blake3=$(lookup_sum "$f" B3SUMS)
    if have_cmd stat; then
      size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
    else
      size=$(wc -c <"$f" | tr -d ' ')
    fi
    minisign=""
    [[ -f "$f.minisig" ]] && minisign="$f.minisig"

    sep=","
    (( i == count )) && sep=""
    printf '    {\n'
    printf '      "name": %s,\n'        "$(json_str "$f")"
    printf '      "kind": %s,\n'        "$(json_str "$kind")"
    printf '      "format": %s,\n'      "$(json_str "$format")"
    printf '      "target": %s,\n'      "$(json_null_or_str "$target")"
    printf '      "os": %s,\n'          "$(json_null_or_str "$os")"
    printf '      "arch": %s,\n'        "$(json_null_or_str "$arch")"
    printf '      "size": %s,\n'        "$size"
    printf '      "sha256": %s,\n'      "$(json_str "$sha256")"
    printf '      "sha512": %s,\n'      "$(json_null_or_str "$sha512")"
    printf '      "blake3": %s,\n'      "$(json_null_or_str "$blake3")"
    printf '      "minisign": %s,\n'    "$(json_null_or_str "$minisign")"
    printf '      "media_type": %s\n'   "$(json_null_or_str "$media_type")"
    printf '    }%s\n' "$sep"
  done
  printf '  ]\n}\n'
} > "$manifest"

info "wrote $manifest (${#files[@]} artifacts, schema=release-manifest v1)"
