#!/usr/bin/env bash
# Regenerate the committed roff man pages under packaging/man/ from the live
# clap::Command tree exposed by spt-cli. Idempotent — output is deterministic.
#
# Usage:
#   scripts/gen_manpages.sh [OUT_DIR]
#
# CI uses this with `git diff --exit-code packaging/man/` to assert the
# committed pages stay in sync with the CLI surface.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT/packaging/man}"
cd "$ROOT"
cargo run --quiet --bin spt-mangen -- --out "$OUT_DIR"
echo "spt-mangen: regenerated man pages in $OUT_DIR" >&2
