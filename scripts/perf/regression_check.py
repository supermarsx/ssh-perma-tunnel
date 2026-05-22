#!/usr/bin/env python3
"""Compare a current perf-matrix run against a checked-in baseline.

Both inputs are JSON documents shaped like one of:
  - The aggregate produced by `scripts/perf/run_matrix.sh`:
      {"version": 1, "cells": [ <CellOutcome>, ... ]}
  - A baseline file (`docs/perf/baseline-v1.0.json`):
      {"version": "...", "captured_at": "...", "host": "...",
       "cells": [ <baseline cell>, ... ]}
  - A bare list of cells: `[ <cell>, ... ]`.

Each cell is keyed by `(tool, latency_ms, loss_pct, load)`. The current
file uses C3's `CellOutcome` schema (`throughput_bps`, `p50_us`,
`p99_us`, `reconnect_ms`, optionally `extras.peak_rss_mb`); the baseline
uses the dashboard schema (`throughput_mbps`, `p50_us`, `p99_us`,
`reconnect_ms`, `peak_rss_mb`). Both are normalised before comparison.

Cells where the baseline value is null are treated as "not yet
measured" and skipped. Skipped current cells (`skipped: true`) are
likewise ignored.

Exit codes:
  0 — every measured metric is within `--threshold` percent of baseline
  1 — at least one regression exceeded the threshold (summary on stdout)
  2 — invalid input (file missing, unparseable JSON, malformed shape)

Usage:
  regression_check.py --baseline docs/perf/baseline-v1.0.json \
                      --current  docs/perf/runs/pr/matrix.json \
                      [--threshold 10]

Stdlib only (no `pip install`). Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Metrics for which a higher value is BETTER (a drop is a regression).
HIGHER_IS_BETTER = {"throughput_mbps"}
# Metrics for which a lower value is BETTER (a rise is a regression).
LOWER_IS_BETTER = {"p50_us", "p99_us", "reconnect_ms", "peak_rss_mb"}
ALL_METRICS = sorted(HIGHER_IS_BETTER | LOWER_IS_BETTER)

CellKey = Tuple[str, int, int, str]


def _load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        print(f"error: file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {path}: {exc}", file=sys.stderr)
        sys.exit(2)


def _extract_cells(doc: Any, label: str) -> List[Dict[str, Any]]:
    """Pull a list of cells out of a baseline/current document."""
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict) and isinstance(doc.get("cells"), list):
        return doc["cells"]
    print(
        f"error: {label} document has no 'cells' array (got {type(doc).__name__})",
        file=sys.stderr,
    )
    sys.exit(2)


def _cell_key(cell: Dict[str, Any]) -> Optional[CellKey]:
    try:
        return (
            str(cell["tool"]),
            int(cell["latency_ms"]),
            int(cell["loss_pct"]),
            str(cell["load"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _normalise(cell: Dict[str, Any]) -> Dict[str, Optional[float]]:
    """Coerce a raw cell into the dashboard's metric vocabulary.

    Accepts both C3's `CellOutcome` (throughput_bps + extras.peak_rss_mb)
    and the baseline's dashboard shape (throughput_mbps + peak_rss_mb).
    Missing/null fields become None.
    """
    out: Dict[str, Optional[float]] = {k: None for k in ALL_METRICS}

    # Throughput: prefer explicit Mbps, else convert from bps.
    tput_mbps = cell.get("throughput_mbps")
    if tput_mbps is None:
        bps = cell.get("throughput_bps")
        if isinstance(bps, (int, float)):
            tput_mbps = float(bps) / 1_000_000.0
    if isinstance(tput_mbps, (int, float)):
        out["throughput_mbps"] = float(tput_mbps)

    for k in ("p50_us", "p99_us", "reconnect_ms"):
        v = cell.get(k)
        if isinstance(v, (int, float)):
            out[k] = float(v)

    # peak_rss_mb: prefer top-level (baseline shape), else extras (CellOutcome).
    rss = cell.get("peak_rss_mb")
    if rss is None:
        extras = cell.get("extras")
        if isinstance(extras, dict):
            rss = extras.get("peak_rss_mb")
    if isinstance(rss, (int, float)):
        out["peak_rss_mb"] = float(rss)

    return out


def _delta_pct(base: float, cur: float) -> float:
    """Return the signed percent change from base to cur (cur > base => +%)."""
    if base == 0:
        # Anything from zero is an infinite delta; treat any non-zero as 100%.
        return 0.0 if cur == 0 else float("inf")
    return ((cur - base) / abs(base)) * 100.0


def _is_regression(metric: str, base: float, cur: float, threshold_pct: float) -> bool:
    delta = _delta_pct(base, cur)
    if metric in HIGHER_IS_BETTER:
        # Throughput dropped — regression if drop exceeds threshold.
        return delta < -threshold_pct
    # Lower is better: rise above threshold is a regression.
    return delta > threshold_pct


def compare(
    baseline_doc: Any,
    current_doc: Any,
    threshold_pct: float,
) -> Tuple[List[str], int, int]:
    """Return (regression_messages, compared_metrics, total_cells)."""
    base_cells = _extract_cells(baseline_doc, "baseline")
    cur_cells = _extract_cells(current_doc, "current")

    base_index: Dict[CellKey, Dict[str, Optional[float]]] = {}
    for raw in base_cells:
        key = _cell_key(raw)
        if key is not None:
            base_index[key] = _normalise(raw)

    messages: List[str] = []
    compared = 0
    total = 0

    for raw in cur_cells:
        key = _cell_key(raw)
        if key is None:
            continue
        total += 1
        if raw.get("skipped"):
            continue
        base = base_index.get(key)
        if base is None:
            # Current produced a cell the baseline doesn't know about.
            # Not a regression; surface it for visibility but don't fail.
            messages.append(
                f"info: cell {key} missing from baseline; skipping"
            )
            continue
        cur = _normalise(raw)
        for metric in ALL_METRICS:
            b = base[metric]
            c = cur[metric]
            if b is None or c is None:
                continue
            compared += 1
            if _is_regression(metric, b, c, threshold_pct):
                delta = _delta_pct(b, c)
                direction = "drop" if metric in HIGHER_IS_BETTER else "rise"
                messages.append(
                    f"REGRESSION {key} {metric}: "
                    f"baseline={b:.3f} current={c:.3f} "
                    f"delta={delta:+.2f}% ({direction} exceeds {threshold_pct:.1f}%)"
                )

    return messages, compared, total


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="regression_check.py",
        description=(
            "Compare a current perf-matrix run JSON against a baseline. "
            "Exits 0 if every measured metric is within the configured "
            "threshold of baseline, 1 if any cell regresses, 2 on bad input."
        ),
    )
    p.add_argument(
        "--baseline",
        required=True,
        type=Path,
        help="Path to baseline JSON (e.g. docs/perf/baseline-v1.0.json).",
    )
    p.add_argument(
        "--current",
        required=True,
        type=Path,
        help="Path to current run JSON (matrix.json from run_matrix.sh).",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=10.0,
        help="Regression threshold in percent (default: 10).",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    if args.threshold <= 0:
        print("error: --threshold must be > 0", file=sys.stderr)
        return 2

    baseline_doc = _load_json(args.baseline)
    current_doc = _load_json(args.current)

    messages, compared, total = compare(baseline_doc, current_doc, args.threshold)

    regressions = [m for m in messages if m.startswith("REGRESSION ")]
    infos = [m for m in messages if not m.startswith("REGRESSION ")]

    for m in infos:
        print(m)
    for m in regressions:
        print(m)

    print(
        f"summary: {len(regressions)} regression(s); "
        f"{compared} metric comparison(s) over {total} cell(s); "
        f"threshold={args.threshold:.1f}%"
    )

    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
