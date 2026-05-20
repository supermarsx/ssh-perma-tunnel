#!/usr/bin/env bash
# Regenerate committed shell completions under packaging/completions/ from the
# live Clap command tree.
#
# Usage:
#   scripts/gen_completions.sh [OUT_DIR]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/packaging/completions}"

cargo run -p spt-bin --bin spt-completions -- --out "$OUT_DIR"
echo "spt-completions: regenerated shell completions in $OUT_DIR" >&2
