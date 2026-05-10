#!/usr/bin/env python3
"""Compare two Criterion result trees and flag regressions.

Usage:
    bench-compare.py <baseline_dir> <candidate_dir> [--threshold 0.10]

Both directory arguments should point at a Criterion target directory of the
shape produced by `cargo bench` — i.e. each leaf benchmark lives at
``<root>/<group>/<bench>/new/estimates.json``. The script walks the
*candidate* tree and looks up each estimate in the baseline tree:

* If the baseline file is missing the bench is reported as ``new`` and is
  *not* counted as a regression (so adding a bench never fails CI).
* If the baseline is present, the mean point estimate (nanoseconds) is
  compared and any candidate ≥ ``baseline * (1 + threshold)`` is recorded
  as a regression.

Exit code is non-zero only if at least one regression beats the threshold.
The script writes a one-line-per-bench summary to stdout so the workflow
can paste it into a PR comment verbatim.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterator, Optional


def find_estimates(root: Path) -> Iterator[tuple[Path, Path]]:
    """Yield (relative_bench_path, estimates_json_path) under ``root``."""
    if not root.is_dir():
        return
    for est in root.rglob("new/estimates.json"):
        try:
            rel = est.parent.parent.relative_to(root)
        except ValueError:
            continue
        # Skip `report` etc.
        if any(part == "report" for part in rel.parts):
            continue
        yield rel, est


def mean_ns(path: Path) -> Optional[float]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return float(data["mean"]["point_estimate"])
    except (KeyError, TypeError, ValueError):
        return None


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("baseline", type=Path, help="Baseline criterion root.")
    p.add_argument("candidate", type=Path, help="Candidate criterion root.")
    p.add_argument(
        "--threshold",
        type=float,
        default=0.10,
        help="Regression threshold as a fraction (default 0.10 = 10%%).",
    )
    args = p.parse_args(argv)

    if args.threshold < 0:
        print("error: --threshold must be non-negative", file=sys.stderr)
        return 2

    rows: list[tuple[str, str, str]] = []
    regressions: list[str] = []
    seen = 0

    for rel, cand_est in find_estimates(args.candidate):
        seen += 1
        cand_ns = mean_ns(cand_est)
        baseline_est = args.baseline / rel / "new" / "estimates.json"
        base_ns = mean_ns(baseline_est) if baseline_est.is_file() else None
        name = "/".join(rel.parts)

        if cand_ns is None:
            rows.append((name, "?", "candidate estimates unreadable"))
            continue
        if base_ns is None or base_ns <= 0:
            rows.append((name, "new", f"{cand_ns:.1f} ns"))
            continue

        delta = (cand_ns - base_ns) / base_ns
        marker = "ok"
        if delta >= args.threshold:
            marker = "REGRESSION"
            regressions.append(f"{name}: {delta * 100:+.1f}%")
        elif delta <= -args.threshold:
            marker = "improved"
        rows.append(
            (
                name,
                marker,
                f"{base_ns:.1f} -> {cand_ns:.1f} ns ({delta * 100:+.1f}%)",
            )
        )

    print(f"# Bench comparison ({seen} benchmarks)")
    print(f"threshold = {args.threshold * 100:.1f}%")
    print()
    print(f"{'name':<60} {'status':<12} detail")
    for name, status, detail in sorted(rows):
        print(f"{name:<60} {status:<12} {detail}")

    if regressions:
        print()
        print(f"## {len(regressions)} regression(s)")
        for r in regressions:
            print(f"- {r}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
