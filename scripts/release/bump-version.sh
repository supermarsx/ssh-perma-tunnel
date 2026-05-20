#!/usr/bin/env bash
# bump-version.sh — compute the next YY.N rolling version and (in CI) commit
# the workspace Cargo.toml + tag the release.
#
#   YY  = two-digit year (UTC)        — e.g. "26" for 2026
#   N   = monotonic counter, resets   — first release of the year is N=1
#   Tag = "v<YY>.<N>"                 — e.g. "v26.1", "v26.2", ..., "v26.314"
#
# Usage:
#   bash scripts/release/bump-version.sh             # CI mode: writes
#                                                    # $GITHUB_OUTPUT (if set)
#                                                    # and edits Cargo.toml
#   bash scripts/release/bump-version.sh --dry-run   # print version + exit
#
# Outputs (when GITHUB_OUTPUT is set):
#   version=<YY.N>
#   tag=v<YY.N>
#   prev_tag=v<YY.PREV> (or empty if first of year)

set -euo pipefail

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "::error::unknown flag: $arg" >&2; exit 2 ;;
  esac
done

YY=$(date -u +%y)

# Find the highest existing tag for this year.
LAST=$(git tag --list "v${YY}.*" --sort=-version:refname 2>/dev/null | head -n1 || true)
if [[ -z "${LAST}" ]]; then
  N=1
  PREV_TAG=""
else
  # Strip "v${YY}." prefix; what remains is the N counter.
  PREV_N=${LAST##*.}
  if ! [[ "${PREV_N}" =~ ^[0-9]+$ ]]; then
    echo "::error::cannot parse counter from previous tag: ${LAST}" >&2
    exit 1
  fi
  N=$((PREV_N + 1))
  PREV_TAG="${LAST}"
fi

VERSION="${YY}.${N}"
TAG="v${VERSION}"

# Refuse to clobber a tag that somehow already exists locally.
if git rev-parse --quiet --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
  echo "::error::${TAG} already exists" >&2
  exit 1
fi

echo "version=${VERSION}"
echo "tag=${TAG}"
echo "prev_tag=${PREV_TAG}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "version=${VERSION}"
    echo "tag=${TAG}"
    echo "prev_tag=${PREV_TAG}"
  } >>"${GITHUB_OUTPUT}"
fi

if [[ "${DRY_RUN}" == "1" ]]; then
  exit 0
fi

# Update workspace Cargo.toml. The version line must carry the trailing
# `# rolling` marker so this sed is unambiguous; see CONTRIBUTING.md.
ROOT="$(git rev-parse --show-toplevel)"
CARGO_TOML="${ROOT}/Cargo.toml"
if grep -qE '^version = "[^"]*"[[:space:]]*#[[:space:]]*rolling' "${CARGO_TOML}"; then
  # Portable in-place edit (BSD/GNU sed compatible).
  tmp=$(mktemp)
  sed -E "s/^version = \"[^\"]*\"([[:space:]]*#[[:space:]]*rolling.*)$/version = \"${VERSION}\"\\1/" \
    "${CARGO_TOML}" >"${tmp}"
  mv "${tmp}" "${CARGO_TOML}"
else
  echo "::warning::Cargo.toml version line missing '# rolling' marker; skipping in-place bump"
fi

echo "::notice::computed next version ${TAG} (prev: ${PREV_TAG:-<none>})"
