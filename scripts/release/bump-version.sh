#!/usr/bin/env bash
# bump-version.sh — compute the next YY.N rolling version and (in CI) commit
# the workspace Cargo.toml + tag the release.
#
#   YY        = two-digit year (UTC)    — e.g. "26" for 2026
#   N         = monotonic counter,      — first release of the year is N=1
#               resets each year
#   Tag       = "<YY>.<N>"              — e.g. "26.1", "26.2", ..., "26.314"
#                                         (no "v" prefix)
#   Cargo TOML = "0.<YY>.<N>"           — Cargo's TOML parser requires full
#                                         SemVer X.Y.Z, so the workspace
#                                         `version` field carries a leading
#                                         `0.` (e.g. "0.26.1"). The user-
#                                         facing tag drops it.
#
# Usage:
#   bash scripts/release/bump-version.sh             # CI mode: writes
#                                                    # $GITHUB_OUTPUT (if set)
#                                                    # and edits Cargo.toml
#                                                    # plus Cargo.lock files
#   bash scripts/release/bump-version.sh --dry-run   # print version + exit
#
# Outputs (when GITHUB_OUTPUT is set):
#   version=<YY.N>
#   tag=<YY.N>
#   prev_tag=<YY.PREV> (or empty if first of year)

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

# Find the highest existing tag for this year (bare YY.N, no "v" prefix).
LAST=$(git tag --list "${YY}.*" --sort=-version:refname 2>/dev/null | head -n1 || true)
if [[ -z "${LAST}" ]]; then
  N=1
  PREV_TAG=""
else
  # Strip "${YY}." prefix; what remains is the N counter.
  PREV_N=${LAST##*.}
  if ! [[ "${PREV_N}" =~ ^[0-9]+$ ]]; then
    echo "::error::cannot parse counter from previous tag: ${LAST}" >&2
    exit 1
  fi
  N=$((PREV_N + 1))
  PREV_TAG="${LAST}"
fi

VERSION="${YY}.${N}"
TAG="${VERSION}"   # no "v" prefix — user-facing tag is the bare YY.N
# Cargo's TOML parser rejects the bare `YY.N` form (it expects full SemVer
# X.Y.Z and emits `unexpected end of input while parsing minor version
# number`). The workspace manifest therefore carries `0.YY.N` — a SemVer-
# valid prefix that still encodes the rolling year + counter unambiguously.
CARGO_VERSION="0.${VERSION}"

# Refuse to clobber a tag that somehow already exists locally.
if git rev-parse --quiet --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
  echo "::error::${TAG} already exists" >&2
  exit 1
fi

echo "version=${VERSION}"
echo "tag=${TAG}"
echo "cargo_version=${CARGO_VERSION}"
echo "prev_tag=${PREV_TAG}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "version=${VERSION}"
    echo "tag=${TAG}"
    echo "cargo_version=${CARGO_VERSION}"
    echo "prev_tag=${PREV_TAG}"
  } >>"${GITHUB_OUTPUT}"
fi

if [[ "${DRY_RUN}" == "1" ]]; then
  exit 0
fi

# Update workspace Cargo.toml. The version line must carry the trailing
# `# rolling` marker so this sed is unambiguous; see contributing.md.
ROOT="$(git rev-parse --show-toplevel)"
CARGO_TOML="${ROOT}/Cargo.toml"
CARGO_LOCK="${ROOT}/Cargo.lock"

rewrite_lock_versions() {
  local lockfile="$1"
  shift

  if [[ ! -f "${lockfile}" ]]; then
    return 0
  fi

  local py_bin=""
  if command -v python3 >/dev/null 2>&1; then
    py_bin="python3"
  elif command -v python >/dev/null 2>&1; then
    py_bin="python"
  else
    echo "::error::python is required to refresh ${lockfile}" >&2
    return 1
  fi

  LOCKFILE="${lockfile}" CARGO_VERSION="${CARGO_VERSION}" "${py_bin}" - "$@" <<'PY'
from pathlib import Path
import os
import re
import sys

lockfile = Path(os.environ["LOCKFILE"])
version = os.environ["CARGO_VERSION"]
packages = set(sys.argv[1:])
name_re = re.compile(r'^name = "([^"]+)"')
version_re = re.compile(r'^version = "[^"]+"')

lines = lockfile.read_text(encoding="utf-8").splitlines(keepends=True)
out = []
in_package = False
current = None
seen = set()

for line in lines:
    if line.startswith("[[package]]"):
        in_package = True
        current = None
        out.append(line)
        continue
    if in_package and line.startswith("[") and not line.startswith("[[package]]"):
        in_package = False
        current = None

    if in_package:
        name = name_re.match(line)
        if name:
            current = name.group(1)
            if current in packages:
                seen.add(current)
        elif current in packages and version_re.match(line):
            newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            line = f'version = "{version}"{newline}'

    out.append(line)

missing = sorted(packages - seen)
if missing:
    print(f"missing package entries in {lockfile}: {', '.join(missing)}", file=sys.stderr)
    sys.exit(1)

lockfile.write_text("".join(out), encoding="utf-8")
PY
}

refresh_standalone_locks() {
  # These two harnesses are deliberately outside the root workspace, but they
  # depend on rolling-version spt crates by path. Rewrite only the local spt
  # package version fields; running `cargo update` here can rewrite registry
  # packages when CI's offline cache is only partially warm.
  rewrite_lock_versions "${ROOT}/tests/chaos/Cargo.lock" \
    spt-auth \
    spt-chaos-proxy \
    spt-config \
    spt-core \
    spt-events \
    spt-forward \
    spt-key \
    spt-net \
    spt-observability \
    spt-protocol \
    spt-secrets \
    spt-sftp \
    spt-state \
    spt-stats \
    spt-supervisor \
    spt-trust

  rewrite_lock_versions "${ROOT}/tests/property/Cargo.lock" \
    spt-auth \
    spt-config \
    spt-core \
    spt-events \
    spt-forward \
    spt-key \
    spt-net \
    spt-protocol \
    spt-secrets \
    spt-snmp \
    spt-ssh3 \
    spt-state \
    spt-trust
}

refresh_root_lock() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "::warning::cargo not on PATH; skipping Cargo.lock refresh"
    return 0
  fi

  (cd "${ROOT}" && cargo update --workspace --offline) || \
    (cd "${ROOT}" && cargo update --workspace)
}

if grep -qE '^version = "[^"]*"[[:space:]]*#[[:space:]]*rolling' "${CARGO_TOML}"; then
  # Portable in-place edit (BSD/GNU sed compatible).
  tmp=$(mktemp)
  sed -E "s/^version = \"[^\"]*\"([[:space:]]*#[[:space:]]*rolling.*)$/version = \"${CARGO_VERSION}\"\\1/" \
    "${CARGO_TOML}" >"${tmp}"
  mv "${tmp}" "${CARGO_TOML}"

  # Refresh Cargo.lock against the new workspace version. Without this,
  # the very next `cargo --locked` invocation on main (the package matrix
  # is the immediate consumer) fails with `the lock file ... needs to be
  # updated but --locked was passed to prevent this`. `cargo update -w`
  # touches only workspace members — it does not silently bump third-
  # party deps. `--offline` keeps the runner from hitting crates.io for
  # what is purely a version-string refresh of locally-owned entries.
  if [[ -f "${CARGO_LOCK}" ]]; then
    refresh_root_lock
  fi

  # The property and chaos harnesses are decoupled workspaces with their own
  # Cargo.lock files. Keep them aligned with the root rolling version so the
  # next push after an automated release does not fail their `--locked` jobs.
  refresh_standalone_locks
else
  echo "::warning::Cargo.toml version line missing '# rolling' marker; skipping in-place bump"
fi

echo "::notice::computed next version ${TAG} (prev: ${PREV_TAG:-<none>})"
