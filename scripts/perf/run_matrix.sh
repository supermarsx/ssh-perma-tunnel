#!/usr/bin/env bash
# t8-C3: comparative-bench matrix runner.
#
# Drives the 3 (latency) × 3 (loss) × 2 (load) × 3 (tool) = 54-cell matrix
# by invoking the `matrix_cell` binary once per cell. Each invocation
# writes a JSON outcome to $OUT_DIR/<cell>.json; cells where the comparator
# binary isn't installed are recorded with "skipped: true" and the run
# continues (FAIL is logged but not fatal — per the C3 brief).
#
# Usage:
#   scripts/perf/run_matrix.sh                  # default 3-tool matrix
#   scripts/perf/run_matrix.sh --tools spt      # spt-only
#   OUT_DIR=/tmp/x ./scripts/perf/run_matrix.sh # custom output directory
#
# The output directory layout matches what C4's render_html.py expects:
#   docs/perf/runs/<ts>/<tool>_lat<n>_loss<n>_<load>.json
#   docs/perf/runs/<ts>/matrix.json   (aggregate index)

set -euo pipefail

LATENCIES=(10 100 500)
LOSSES=(0 1 5)
LOADS=("idle" "saturated")
TOOLS_DEFAULT=("spt" "openssh" "autossh")

# --tools spt,openssh override (comma-separated).
TOOLS=("${TOOLS_DEFAULT[@]}")
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tools)
      IFS=',' read -r -a TOOLS <<< "$2"
      shift 2
      ;;
    --upstream)
      UPSTREAM="$2"
      shift 2
      ;;
    --forward-remote)
      FORWARD_REMOTE="$2"
      shift 2
      ;;
    -h|--help)
      sed -n '2,18p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

UPSTREAM="${UPSTREAM:-127.0.0.1:22}"
FORWARD_REMOTE="${FORWARD_REMOTE:-127.0.0.1:80}"
OUT_DIR="${OUT_DIR:-docs/perf/runs/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT_DIR"

echo "==> matrix output: $OUT_DIR"
echo "==> tools:    ${TOOLS[*]}"
echo "==> upstream: $UPSTREAM"
echo "==> forward:  $FORWARD_REMOTE"

# Build the binary once up front so each cell is fast.
cargo build -p spt-benchmark --release --bin matrix_cell --locked

# Track failures separately so we can exit non-zero if EVERY cell failed
# (e.g., the binary couldn't run at all) while still tolerating per-tool
# install gaps.
total=0
fails=0

for tool in "${TOOLS[@]}"; do
  for lat in "${LATENCIES[@]}"; do
    for loss in "${LOSSES[@]}"; do
      for load in "${LOADS[@]}"; do
        cell="${tool}_lat${lat}_loss${loss}_${load}"
        out="$OUT_DIR/${cell}.json"
        echo "==> $cell"
        total=$((total + 1))
        if ! cargo run -p spt-benchmark --release --bin matrix_cell --locked -- \
            --tool "$tool" \
            --latency "$lat" \
            --loss "$loss" \
            --load "$load" \
            --upstream "$UPSTREAM" \
            --forward-remote "$FORWARD_REMOTE" \
            --out "$out"
        then
          echo "FAIL: $cell"
          fails=$((fails + 1))
        fi
      done
    done
  done
done

# Build the matrix index. Uses python3 if available, otherwise raw jq, else
# a hand-written shell loop. We pick the first available.
if command -v python3 >/dev/null 2>&1; then
  python3 - "$OUT_DIR" <<'PY'
import json, os, sys, glob
out = sys.argv[1]
cells = []
for p in sorted(glob.glob(os.path.join(out, "*.json"))):
    if os.path.basename(p) == "matrix.json":
        continue
    with open(p) as f:
        cells.append(json.load(f))
with open(os.path.join(out, "matrix.json"), "w") as f:
    json.dump({"cells": cells, "version": 1}, f, indent=2)
print(f"index: {len(cells)} cells")
PY
else
  echo "python3 not found; skipping matrix.json aggregation"
fi

echo "==> matrix complete: $OUT_DIR ($total cells, $fails failures)"
# Exit non-zero only if EVERY cell failed.
if [[ "$fails" -ne 0 && "$fails" -eq "$total" ]]; then
  exit 1
fi
