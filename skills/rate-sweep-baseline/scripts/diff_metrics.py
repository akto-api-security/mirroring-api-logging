#!/usr/bin/env python3
"""Numeric tier-by-tier diff between two rate-sweep prefixes' parsed results.

Usage: diff_metrics.py <prefixA.json> <prefixB.json>

Input files are parse_results.py's output (run it first, save to a file).
Prints one table per config x rate tier, comparing the fields that matter for
"did anything change": completed (y/n), coverage_pct, events_dropped_*,
offered/consumed rate (derived from events_received/duration_sec). No causal
claims, no narrative — arithmetic only. Where a run's numbers vary run-to-run
within one prefix, both min and max are shown.
"""
import json
import sys

FIELDS = [
    ("coverage_pct", "cov%", "{:.1f}"),
    ("events_dropped_kernel_ring_buf", "kernelDrop", "{:.0f}"),
    ("events_dropped_channel_full", "chanFullDrop", "{:.0f}"),
    ("pairs_parse_failure", "parseFail", "{:.0f}"),
]


def load(path):
    with open(path) as f:
        return json.load(f)


def tier_range(runs, rate, field):
    vals = []
    for r in runs:
        t = r["tiers"].get(rate)
        if t and t["completed"]:
            vals.append(t["metrics"].get(field, 0))
    return vals


def fmt_range(vals, fmt):
    if not vals:
        return "DNF"
    lo, hi = min(vals), max(vals)
    if lo == hi:
        return fmt.format(lo)
    return f"{fmt.format(lo)}-{fmt.format(hi)}"


def completed_count(runs, rate):
    return sum(1 for r in runs if r["tiers"].get(rate, {}).get("completed"))


def main():
    if len(sys.argv) != 3:
        print("usage: diff_metrics.py <prefixA.json> <prefixB.json>", file=sys.stderr)
        sys.exit(1)

    a = load(sys.argv[1])
    b = load(sys.argv[2])
    rates = ["50k", "100k", "200k", "300k", "500k"]

    all_slugs = sorted(set(a["configs"]) | set(b["configs"]))
    print(f"# Diff: {a['prefix']} vs {b['prefix']}\n")

    for slug in all_slugs:
        ca = a["configs"].get(slug)
        cb = b["configs"].get(slug)
        print(f"## {slug}")
        if ca is None or cb is None:
            missing = a["prefix"] if ca is None else b["prefix"]
            print(f"  (missing from {missing} — skipping)\n")
            continue

        na, nb = ca["num_runs"], cb["num_runs"]
        col_w = 22
        print(f"{'rate':>6} | {'completed':>{col_w}} | " + " | ".join(f"{label:>{col_w}}" for _, label, _ in FIELDS))
        print(f"{'':>6} | {'(' + a['prefix'] + ' -> ' + b['prefix'] + ')':>{col_w}} | " + " | ".join(f"{'':>{col_w}}" for _ in FIELDS))

        for rate in rates:
            ca_done = completed_count(ca["runs"], rate)
            cb_done = completed_count(cb["runs"], rate)
            cells = [f"{f'{ca_done}/{na} -> {cb_done}/{nb}':>{col_w}}"]
            for field, _label, fmt in FIELDS:
                va = fmt_range(tier_range(ca["runs"], rate, field), fmt)
                vb = fmt_range(tier_range(cb["runs"], rate, field), fmt)
                cells.append(f"{f'{va} -> {vb}':>{col_w}}")
            print(f"{rate:>6} | " + " | ".join(cells))
        print()


if __name__ == "__main__":
    main()
