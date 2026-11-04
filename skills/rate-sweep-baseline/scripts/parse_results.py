#!/usr/bin/env python3
"""Aggregate rate-sweep run dirs for one prefix into a per-config metrics table.

Usage: parse_results.py <prefix> [pprof_dir]

Reads connections/pprof/<prefix>-<config>-r<N>/ dirs (however many exist for
each config — not hardcoded to 3), and for each config walks its arm/[encoder/]
rate dirs' metrics.json. A rate tier with no metrics.json for a given run means
that run died before reaching it; the OOM line (if any) is pulled from that
run's stdout.log. Outputs one JSON blob to stdout: pure data, no narrative.
"""
import json
import os
import re
import sys
from collections import defaultdict

RATES = ["50k", "100k", "200k", "300k", "500k"]

# config slug -> (arm, encoder-or-None) pairs actually produced under pprof/<testname>/
CONFIG_LAYOUT = {
    "parse-off": [("parse-off", None)],
    "parse-on-json": [("parse-on", "json")],
    "parse-on-json-kafka": [("parse-on", "json")],
    # Older baselines (feature/k8s_ebpf) also had flatbuffers configs; ebpf-core
    # has only the JSON encoder.
    "parse-on-fb": [("parse-on", "flatbuffers")],
    "parse-on-fb-kafka": [("parse-on", "flatbuffers")],
    # -threat=true doesn't change the arm/encoder dir layout (still parse-on/json/<rate>/),
    # only adds the second akto.api.logs2 protobuf produce path inside the same run.
    "parse-on-json-kafka-threat": [("parse-on", "json")],
}


def find_run_dirs(pprof_dir, prefix):
    """slug -> sorted list of (run_num, dirpath) for every <prefix>-<slug>-r<N> dir."""
    pat = re.compile(rf"^{re.escape(prefix)}-(.+)-r(\d+)$")
    out = defaultdict(list)
    if not os.path.isdir(pprof_dir):
        return out
    for name in os.listdir(pprof_dir):
        m = pat.match(name)
        if not m:
            continue
        slug, run_num = m.group(1), int(m.group(2))
        out[slug].append((run_num, os.path.join(pprof_dir, name)))
    for slug in out:
        out[slug].sort()
    return out


def oom_line(run_dir):
    log_path = os.path.join(run_dir, "stdout.log")
    if not os.path.isfile(log_path):
        return None
    last = None
    with open(log_path, errors="replace") as f:
        for line in f:
            if "Refreshing, current" in line:
                last = line.strip()
    return last


def read_tier_metrics(run_dir, arm, encoder):
    """rate_label -> {completed, metrics} for one run dir. completed=False means
    this run's process didn't survive to finish writing this tier's metrics.json
    (OOM mid-cell or mid-warmup) — metrics is None in that case."""
    result = {}
    for rate in RATES:
        parts = [run_dir, arm]
        if encoder:
            parts.append(encoder)
        parts.append(rate)
        mpath = os.path.join(*parts, "metrics.json")
        if os.path.isfile(mpath):
            with open(mpath) as f:
                result[rate] = {"completed": True, "metrics": json.load(f)}
        else:
            result[rate] = {"completed": False, "metrics": None}
    return result


def summarize_config(slug, run_dirs):
    layout = CONFIG_LAYOUT.get(slug)
    if layout is None:
        return {"error": f"unknown config slug {slug!r}, not in CONFIG_LAYOUT"}
    arm, encoder = layout[0]

    runs_out = []
    for run_num, run_dir in run_dirs:
        runs_out.append({
            "run": run_num,
            "dir": run_dir,
            "tiers": read_tier_metrics(run_dir, arm, encoder),
            "oom_line": oom_line(run_dir),
        })

    # No computed "clean ceiling" here on purpose: a tier can have metrics.json
    # (the process survived it) yet still show real drops/cov<100 — collapsing
    # that into one pass/fail scalar bakes in a threshold judgment call. Callers
    # read the raw per-tier numbers (events_dropped_*, coverage_pct, etc.)
    # themselves, same as every rate-sweep report has done by eye so far.
    return {
        "arm": arm,
        "encoder": encoder,
        "num_runs": len(run_dirs),
        "runs": runs_out,
    }


def main():
    if len(sys.argv) < 2:
        print("usage: parse_results.py <prefix> [pprof_dir]", file=sys.stderr)
        sys.exit(1)
    prefix = sys.argv[1]
    pprof_dir = sys.argv[2] if len(sys.argv) > 2 else "connections/pprof"

    run_dirs_by_slug = find_run_dirs(pprof_dir, prefix)
    if not run_dirs_by_slug:
        print(f"no run dirs found matching {pprof_dir}/{prefix}-*-r<N>", file=sys.stderr)
        sys.exit(1)

    out = {"prefix": prefix, "configs": {}}
    for slug, run_dirs in sorted(run_dirs_by_slug.items()):
        out["configs"][slug] = summarize_config(slug, run_dirs)

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
