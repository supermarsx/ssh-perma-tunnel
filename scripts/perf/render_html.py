#!/usr/bin/env python3
"""Render a perf-matrix run JSON into a single static HTML dashboard.

Accepts:
  - The aggregate produced by `scripts/perf/run_matrix.sh`:
      {"version": 1, "cells": [ <CellOutcome>, ... ]}
  - A baseline document (`docs/perf/baseline-v1.0.json`) when passed via
    `--baseline`; green/yellow/red shading is computed from each cell's
    delta vs the baseline for the same `(tool, latency_ms, loss_pct,
    load)` key.

Output:
  A single self-contained HTML file (`--output`, default
  `docs/perf/dashboard.html`) with one tab per `(load, tool)` pair and a
  3x3 grid of (latency rows) x (loss columns) inside each tab. Every
  cell shows p50, p99, throughput (MB/s), reconnect cost (ms), and peak
  RSS (MB).

Pure stdlib. No external dependencies. Python 3.8+.

Shading rules per metric (vs baseline):
  green   delta within +/- threshold (default 10%)
  yellow  delta between +/-threshold and +/- 2 * threshold
  red     delta beyond +/- 2 * threshold (regression direction)

Higher-is-better: throughput_mbps. Lower-is-better: p50_us, p99_us,
reconnect_ms, peak_rss_mb.

CellOutcome field translation:
  - throughput_bps -> throughput_mbps via /1e6
  - extras.peak_rss_mb -> top-level peak_rss_mb if absent

Cells flagged `skipped: true` are rendered grey with the skip reason.
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

LATENCIES = (10, 100, 500)
LOSSES = (0, 1, 5)
LOADS = ("idle", "saturated")
TOOLS = ("spt", "openssh", "autossh")

METRICS = [
    ("p50_us", "p50 (us)", False),
    ("p99_us", "p99 (us)", False),
    ("throughput_mbps", "throughput (MB/s)", True),
    ("reconnect_ms", "reconnect (ms)", False),
    ("peak_rss_mb", "peak RSS (MB)", False),
]
# (key, label, higher_is_better)

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


def _extract_cells(doc: Any) -> List[Dict[str, Any]]:
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict) and isinstance(doc.get("cells"), list):
        return doc["cells"]
    return []


def _normalise(cell: Dict[str, Any]) -> Dict[str, Any]:
    """Add `throughput_mbps` / `peak_rss_mb` top-level fields if missing."""
    out = dict(cell)
    if out.get("throughput_mbps") is None:
        bps = out.get("throughput_bps")
        if isinstance(bps, (int, float)):
            out["throughput_mbps"] = float(bps) / 1_000_000.0
    if out.get("peak_rss_mb") is None:
        extras = out.get("extras") or {}
        rss = extras.get("peak_rss_mb") if isinstance(extras, dict) else None
        if isinstance(rss, (int, float)):
            out["peak_rss_mb"] = float(rss)
    return out


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


def _index_cells(doc: Any) -> Dict[CellKey, Dict[str, Any]]:
    idx: Dict[CellKey, Dict[str, Any]] = {}
    for raw in _extract_cells(doc):
        key = _cell_key(raw)
        if key is not None:
            idx[key] = _normalise(raw)
    return idx


def _delta_pct(base: float, cur: float) -> Optional[float]:
    if base == 0:
        return None if cur == 0 else float("inf")
    return ((cur - base) / abs(base)) * 100.0


def _shade(
    metric_key: str,
    higher_is_better: bool,
    cur: Optional[float],
    base: Optional[float],
    threshold: float,
) -> str:
    """Return a CSS class (green/yellow/red/neutral) for the cell metric."""
    if cur is None or base is None:
        return "neutral"
    delta = _delta_pct(base, cur)
    if delta is None:
        return "neutral"
    if delta == float("inf"):
        return "red"
    # Regression direction:
    bad = (-delta) if higher_is_better else delta
    if bad <= threshold:
        return "green"
    if bad <= 2 * threshold:
        return "yellow"
    return "red"


def _fmt(v: Optional[float], digits: int = 2) -> str:
    if v is None:
        return "&mdash;"
    if isinstance(v, float):
        return f"{v:.{digits}f}"
    return str(v)


def _render_cell(
    cur: Optional[Dict[str, Any]],
    base: Optional[Dict[str, Any]],
    threshold: float,
) -> str:
    if cur is None:
        return '<td class="missing">no data</td>'
    if cur.get("skipped"):
        reason = html.escape(str(cur.get("skip_reason") or "skipped"))
        return f'<td class="skipped" title="{reason}">skipped</td>'

    rows = []
    for key, label, higher_is_better in METRICS:
        c = cur.get(key)
        b = base.get(key) if base else None
        cls = _shade(key, higher_is_better, _num(c), _num(b), threshold)
        delta_txt = ""
        if base is not None and _num(b) is not None and _num(c) is not None:
            d = _delta_pct(_num(b), _num(c))
            if d is not None and d != float("inf"):
                delta_txt = f' <span class="delta">({d:+.1f}%)</span>'
        rows.append(
            f'<tr class="{cls}">'
            f'<td class="m-label">{html.escape(label)}</td>'
            f'<td class="m-value">{_fmt(_num(c))}{delta_txt}</td>'
            f"</tr>"
        )
    return f'<td class="cell"><table class="metrics">{"".join(rows)}</table></td>'


def _num(v: Any) -> Optional[float]:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    return None


def _render_tab(
    tool: str,
    load: str,
    current: Dict[CellKey, Dict[str, Any]],
    baseline: Dict[CellKey, Dict[str, Any]],
    threshold: float,
) -> str:
    header_cols = "".join(
        f'<th>loss {loss}%</th>' for loss in LOSSES
    )
    rows = []
    for lat in LATENCIES:
        cells = []
        for loss in LOSSES:
            key: CellKey = (tool, lat, loss, load)
            cur = current.get(key)
            base = baseline.get(key)
            cells.append(_render_cell(cur, base, threshold))
        rows.append(
            f'<tr><th class="lat">latency {lat} ms</th>{"".join(cells)}</tr>'
        )
    body = "".join(rows)
    return (
        f'<div class="tab-panel" data-tab="{tool}-{load}">'
        f'<table class="matrix"><thead><tr><th></th>{header_cols}</tr></thead>'
        f"<tbody>{body}</tbody></table>"
        f"</div>"
    )


HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>spt perf dashboard</title>
<style>
  :root {{
    --green:  #c8f1c8;
    --yellow: #fff4c4;
    --red:    #f8c8c8;
    --grey:   #ececec;
    --bg:     #ffffff;
    --fg:     #1a1a1a;
    --muted:  #666;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    margin: 1.5rem;
    color: var(--fg);
    background: var(--bg);
  }}
  h1 {{ margin-top: 0; font-size: 1.4rem; }}
  .meta {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 1rem; }}
  .tabs {{ margin-bottom: 0.75rem; }}
  .tabs button {{
    font: inherit; padding: 0.35rem 0.7rem; margin-right: 0.3rem;
    border: 1px solid #bbb; background: #f4f4f4; cursor: pointer;
    border-radius: 4px;
  }}
  .tabs button.active {{ background: #1f6feb; color: white; border-color: #1f6feb; }}
  .tab-panel {{ display: none; }}
  .tab-panel.active {{ display: block; }}
  table.matrix {{ border-collapse: collapse; width: 100%; }}
  table.matrix th, table.matrix td {{
    border: 1px solid #ccc; padding: 0.4rem; vertical-align: top;
    text-align: left;
  }}
  th.lat {{ background: #fafafa; white-space: nowrap; width: 8rem; }}
  td.cell {{ padding: 0; }}
  td.skipped {{ background: var(--grey); text-align: center; color: var(--muted); }}
  td.missing {{ background: var(--grey); text-align: center; color: var(--muted); font-style: italic; }}
  table.metrics {{ border-collapse: collapse; width: 100%; }}
  table.metrics td {{ border: none; padding: 0.2rem 0.4rem; font-size: 0.85rem; }}
  table.metrics td.m-label {{ color: var(--muted); width: 9rem; }}
  table.metrics td.m-value {{ font-variant-numeric: tabular-nums; }}
  tr.green   td {{ background: var(--green); }}
  tr.yellow  td {{ background: var(--yellow); }}
  tr.red     td {{ background: var(--red); }}
  tr.neutral td {{ background: transparent; }}
  .delta {{ color: var(--muted); font-size: 0.75rem; }}
  .legend {{ font-size: 0.8rem; color: var(--muted); margin-top: 1rem; }}
  .legend span {{ display: inline-block; padding: 0 0.4rem; margin-right: 0.25rem; border-radius: 3px; }}
</style>
</head>
<body>
<h1>spt perf dashboard</h1>
<div class="meta">
  rendered: {rendered_at} &middot;
  current: {current_label} &middot;
  baseline: {baseline_label} &middot;
  threshold: {threshold:.1f}%
</div>
<div class="tabs" role="tablist">{tab_buttons}</div>
{tab_panels}
<div class="legend">
  <span style="background:var(--green)">green</span> within +/- {threshold:.0f}% of baseline &middot;
  <span style="background:var(--yellow)">yellow</span> between +/-{threshold:.0f}% and +/-{double:.0f}% &middot;
  <span style="background:var(--red)">red</span> beyond +/-{double:.0f}% in the regression direction &middot;
  <span style="background:var(--grey)">grey</span> skipped or no data
</div>
<script>
  (function() {{
    const buttons = document.querySelectorAll('.tabs button');
    const panels  = document.querySelectorAll('.tab-panel');
    function show(name) {{
      buttons.forEach(b => b.classList.toggle('active', b.dataset.tab === name));
      panels.forEach(p => p.classList.toggle('active', p.dataset.tab === name));
    }}
    buttons.forEach(b => b.addEventListener('click', () => show(b.dataset.tab)));
    if (buttons.length > 0) show(buttons[0].dataset.tab);
  }})();
</script>
</body>
</html>
"""


def _render(
    current_doc: Any,
    baseline_doc: Optional[Any],
    threshold: float,
    current_label: str,
    baseline_label: str,
) -> str:
    current = _index_cells(current_doc)
    baseline = _index_cells(baseline_doc) if baseline_doc is not None else {}

    tab_buttons = []
    tab_panels = []
    first = True
    for load in LOADS:
        for tool in TOOLS:
            label = f"{tool} / {load}"
            tab_id = f"{tool}-{load}"
            active = " active" if first else ""
            tab_buttons.append(
                f'<button class="tab-btn{active}" data-tab="{html.escape(tab_id)}">'
                f"{html.escape(label)}</button>"
            )
            tab_panels.append(
                _render_tab(tool, load, current, baseline, threshold)
                .replace('class="tab-panel"', f'class="tab-panel{active}"')
            )
            first = False

    rendered_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return HTML_TEMPLATE.format(
        rendered_at=html.escape(rendered_at),
        current_label=html.escape(current_label),
        baseline_label=html.escape(baseline_label),
        threshold=threshold,
        double=threshold * 2,
        tab_buttons="".join(tab_buttons),
        tab_panels="".join(tab_panels),
    )


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="render_html.py",
        description=(
            "Render a perf-matrix run JSON to a static HTML dashboard. "
            "If --baseline is supplied, cells are shaded green/yellow/red "
            "based on delta vs the baseline."
        ),
    )
    p.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Current matrix JSON (e.g. docs/perf/runs/pr/matrix.json).",
    )
    p.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Optional baseline JSON for shading (e.g. docs/perf/baseline-v1.0.json).",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("docs/perf/dashboard.html"),
        help="Output HTML path (default: docs/perf/dashboard.html).",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=10.0,
        help="Regression threshold for shading, percent (default: 10).",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    current_doc = _load_json(args.input)
    baseline_doc = _load_json(args.baseline) if args.baseline else None

    html_str = _render(
        current_doc,
        baseline_doc,
        args.threshold,
        current_label=str(args.input),
        baseline_label=str(args.baseline) if args.baseline else "(none)",
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(html_str, encoding="utf-8")
    print(f"wrote {args.output} ({len(html_str)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
