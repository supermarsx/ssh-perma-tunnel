#!/usr/bin/env python3
"""Render the README terminal screenshot from the live `spt --help` output."""

from __future__ import annotations

import argparse
import html
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PORTABLE_REPLACEMENTS = {
    "spt.exe": "spt",
    "\u2192": "->",
    "\u2194": "<->",
    "\u2014": "-",
    "\u2013": "-",
    "\u2026": "...",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    root = repo_root()
    parser = argparse.ArgumentParser(
        description="Render docs/assets/readme-spt-help.svg from live spt help output."
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=root / "docs" / "assets" / "readme-spt-help.svg",
        help="SVG output path.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the existing SVG is missing or stale.",
    )
    parser.add_argument(
        "--bin",
        type=Path,
        default=os.environ.get("SPT_SCREENSHOT_BIN"),
        help="Existing spt binary to run instead of cargo run.",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=28,
        help="Maximum captured help lines to render.",
    )
    parser.add_argument(
        "--max-cols",
        type=int,
        default=104,
        help="Maximum terminal columns to render before wrapping.",
    )
    return parser.parse_args()


def run_spt_help(root: Path, bin_path: Path | None) -> str:
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    env["CLICOLOR"] = "0"
    env["CARGO_TERM_COLOR"] = "never"

    if bin_path is not None:
        cmd = [str(bin_path), "--help"]
    else:
        env.setdefault(
            "CARGO_TARGET_DIR",
            str(Path(tempfile.gettempdir()) / "spt-readme-screenshot-target"),
        )
        cmd = ["cargo", "run", "--quiet", "-p", "spt-bin", "--bin", "spt", "--", "--help"]

    proc = subprocess.run(
        cmd,
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)

    return proc.stdout


def normalized_lines(text: str, max_lines: int, max_cols: int) -> list[str]:
    clean = ANSI_RE.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    for old, new in PORTABLE_REPLACEMENTS.items():
        clean = clean.replace(old, new)

    lines = clean.split("\n")
    while lines and lines[-1] == "":
        lines.pop()

    wrapped = []
    for line in lines:
        if len(line) <= max_cols:
            wrapped.append(line)
            continue

        indent = re.match(r"^\s*", line).group(0)
        wrapped.extend(
            textwrap.wrap(
                line,
                width=max_cols,
                subsequent_indent=f"{indent}  ",
                break_long_words=False,
                break_on_hyphens=False,
            )
        )

    lines = wrapped
    if len(lines) > max_lines:
        lines = lines[: max_lines - 1] + ["..."]
    return lines


def render_svg(lines: list[str]) -> str:
    line_height = 22
    top = 86
    width = 980
    height = top + max(len(lines), 1) * line_height + 34

    svg_lines = [
        '<svg xmlns="http://www.w3.org/2000/svg" role="img" '
        'aria-label="spt command-line help screenshot" '
        f'width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "  <title>spt command-line help</title>",
        "  <style>",
        "    .term { fill: #0b1020; }",
        "    .bar { fill: #182235; }",
        "    .prompt { fill: #7dd3fc; font: 600 15px Consolas, 'SFMono-Regular', monospace; }",
        "    .text { fill: #dbe7ff; font: 14px Consolas, 'SFMono-Regular', monospace; }",
        "    .muted { fill: #94a3b8; font: 13px Consolas, 'SFMono-Regular', monospace; }",
        "  </style>",
        '  <rect class="term" x="0" y="0" width="980" height="100%" rx="14"/>',
        '  <rect class="bar" x="0" y="0" width="980" height="42" rx="14"/>',
        '  <circle cx="24" cy="21" r="6" fill="#f87171"/>',
        '  <circle cx="44" cy="21" r="6" fill="#fbbf24"/>',
        '  <circle cx="64" cy="21" r="6" fill="#34d399"/>',
        '  <text class="muted" x="86" y="26">ssh-perma-tunnel</text>',
        '  <text class="prompt" x="24" y="66">PS&gt; spt --help</text>',
    ]
    for index, line in enumerate(lines):
        y = top + index * line_height
        svg_lines.append(f'  <text class="text" x="24" y="{y}">{html.escape(line)}</text>')
    svg_lines.append("</svg>")
    return "\n".join(svg_lines) + "\n"


def main() -> int:
    args = parse_args()
    root = repo_root()
    output = run_spt_help(root, args.bin)
    svg = render_svg(normalized_lines(output, args.max_lines, args.max_cols))
    out = args.out if args.out.is_absolute() else root / args.out

    if args.check:
        if not out.exists():
            sys.stderr.write(f"{out} is missing; run this script without --check.\n")
            return 1
        current = out.read_text(encoding="utf-8")
        if current != svg:
            sys.stderr.write(f"{out} is stale; rerun {Path(__file__).as_posix()}.\n")
            return 1
        print(f"readme screenshot is current: {out}")
        return 0

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(svg, encoding="utf-8", newline="\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
