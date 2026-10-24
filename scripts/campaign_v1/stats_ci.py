#!/usr/bin/env python3
"""ARCHIVIRT — confidence intervals for run-level detection ratios (Wilson score interval).

Wilson is used instead of the normal approximation because ARCHIVIRT ratios are computed on few runs
(10 per scenario) and are often 0 or 1, where the normal interval collapses to zero width.
Read-only helper: it never writes into a results directory; `--report OUT.json` must not exist.
Usage: stats_ci.py aggregated_metrics.json [--z 1.959964] [--report OUT.json]
"""
import argparse, hashlib, json, math, os, sys


def wilson(k, n, z=1.959964):
    """Two-sided Wilson score interval for k successes out of n trials; None when n == 0."""
    if n == 0:
        return None
    if not 0 <= k <= n:
        raise ValueError(f"k={k} outside 0..{n}")
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(max(0.0, centre - half), 6), round(min(1.0, centre + half), 6)]


def ratios_with_ci(c, z=1.959964):
    tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
    out = {}
    for name, k, n in (("precision", tp, tp + fp), ("recall_TPR", tp, tp + fn), ("fpr", fp, fp + tn),
                       ("fnr", fn, fn + tp), ("accuracy", tp + tn, tp + tn + fp + fn)):
        out[name] = {"k": k, "n": n, "point": round(k / n, 6) if n else None, "wilson95": wilson(k, n, z)}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("aggregated")
    ap.add_argument("--z", type=float, default=1.959964)
    ap.add_argument("--report")
    a = ap.parse_args(argv)
    raw = open(a.aggregated, "rb").read()
    agg = json.loads(raw)
    res = {"source": os.path.abspath(a.aggregated), "source_sha256": hashlib.sha256(raw).hexdigest(),
           "method": "Wilson score interval, run-level confusion", "z": a.z, "modes": {}}
    for mode, m in agg.get("modes", {}).items():
        c = m.get("derived_metrics", {}).get("confusion")
        if c and sum(c.values()) > 0:
            res["modes"][mode] = {"confusion": c, "ratios": ratios_with_ci(c, a.z)}
    if a.report:
        if os.path.exists(a.report):
            print(f"REFUSED: {a.report} exists", file=sys.stderr)
            return 2
        with open(a.report, "w") as fh:
            json.dump(res, fh, indent=1)
    print(json.dumps(res["modes"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
