#!/usr/bin/env python3
"""Plot the quality curve from measure.py output.

Reads the JSONL produced by measure.py and draws the heavy-findings
curve (critical+high per 1000 non-test Go lines) over time. Optionally
plots any other numeric metric from the records.

Usage:
    plot.py curve.jsonl -o curve.png
    plot.py curve.jsonl --metric per_kloc_total -o total.png
    plot.py a.jsonl b.jsonl -o compare.png   # one line per file

Requires matplotlib: pip install matplotlib
"""

import argparse
import datetime as dt
import json
import os
import sys

METRIC_LABELS = {
    "per_kloc_crit_high": "critical+high findings per 1000 lines",
    "per_kloc_total": "all findings per 1000 lines",
    "sloc": "non-test Go lines",
}


def load(path):
    points = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            points.append(rec)
    points.sort(key=lambda r: r["date"])
    return points


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("jsonl", nargs="+", help="output file(s) of measure.py")
    ap.add_argument("-o", "--out", default="curve.png", help="output PNG")
    ap.add_argument("--metric", default="per_kloc_crit_high",
                    help="record field to plot (default: per_kloc_crit_high)")
    ap.add_argument("--title", default=None)
    args = ap.parse_args()

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        sys.exit("matplotlib is required: pip install matplotlib")

    fig, ax = plt.subplots(figsize=(10, 5), dpi=150)
    colors = ["#2a78d6", "#eb6834", "#3b9e4f", "#8b5cb8"]

    for i, path in enumerate(args.jsonl):
        points = load(path)
        if not points:
            print(f"warning: {path} is empty, skipping", file=sys.stderr)
            continue
        # Slices where the historical tree failed to build carry an
        # "error" field instead of metrics - skip them.
        usable = [r for r in points if args.metric in r]
        if not usable:
            sys.exit(f"{path}: no field '{args.metric}' in any record; "
                     f"available: {', '.join(sorted(points[-1]))}")
        if len(usable) < len(points):
            print(f"{path}: skipped {len(points) - len(usable)} broken "
                  f"slice(s)", file=sys.stderr)
        dates = [dt.date.fromisoformat(r["date"]) for r in usable]
        values = [r[args.metric] for r in usable]
        label = os.path.splitext(os.path.basename(path))[0]
        ax.plot(dates, values, color=colors[i % len(colors)],
                linewidth=2, marker="o", markersize=3, label=label)

    ax.set_ylabel(METRIC_LABELS.get(args.metric, args.metric))
    ax.set_ylim(bottom=0)
    ax.grid(True, alpha=0.25, linewidth=0.5)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    if len(args.jsonl) > 1:
        ax.legend(frameon=False)
    if args.title:
        ax.set_title(args.title)
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(args.out)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
