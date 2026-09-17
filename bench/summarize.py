#!/usr/bin/env python3
"""Summarize bench results: read all *.json in a results dir and print a
markdown table (tool by profile: CPU%, cgroup CPU%, RSS MB, changes/s).

Usage: python3 bench/summarize.py bench/results/baseline
"""

import glob
import json
import os
import sys

RUN_ORDER = ['sentinel-tui', 'sentinel-light', 'sentinel-service', 'btop', 'htop']
PROFILE_ORDER = ['pi3', 'pi4']


def fmt(v, nd=1):
    return f"{v:.{nd}f}" if isinstance(v, (int, float)) else "-"


def main():
    results_dir = sys.argv[1] if len(sys.argv) > 1 else 'bench/results/baseline'
    rows = []
    for path in sorted(glob.glob(os.path.join(results_dir, '*.json'))):
        try:
            with open(path) as f:
                r = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"warning: skipping {path}: {e}", file=sys.stderr)
            continue
        name = r.get('name', os.path.basename(path)[:-5])
        profile, _, run = name.partition('-')
        # Run names hold a dash (sentinel-tui). Split at the first dash only
        rows.append((profile, run, r))

    rows.sort(key=lambda x: (
        PROFILE_ORDER.index(x[0]) if x[0] in PROFILE_ORDER else 99,
        RUN_ORDER.index(x[1]) if x[1] in RUN_ORDER else 99))

    print("| Profile | Tool | CPU% mean (p95) | Cgroup CPU% mean (max) | RSS MB mean (max) | ctx/s vol (nonvol) | Throttled |")
    print("|---------|------|-----------------|------------------------|-------------------|--------------------|-----------|")
    for profile, run, r in rows:
        cpu = r.get('cpu_percent', {})
        cg = r.get('cgroup_cpu_percent', {})
        rss = r.get('rss_kb', {})
        ctx = r.get('ctx_switches_per_sec', {})
        thr = r.get('nr_throttled_delta')
        rss_mean = rss.get('mean') / 1024 if isinstance(rss.get('mean'), (int, float)) else None
        rss_max = rss.get('max') / 1024 if isinstance(rss.get('max'), (int, float)) else None
        print(f"| {profile} | {run} "
              f"| {fmt(cpu.get('mean'))} ({fmt(cpu.get('p95'))}) "
              f"| {fmt(cg.get('mean'))} ({fmt(cg.get('max'))}) "
              f"| {fmt(rss_mean)} ({fmt(rss_max)}) "
              f"| {fmt(ctx.get('voluntary'))} ({fmt(ctx.get('nonvoluntary'))}) "
              f"| {thr if thr is not None else '-'} |")


if __name__ == '__main__':
    main()
