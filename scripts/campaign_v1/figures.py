#!/usr/bin/env python3
"""ARCHIVIRT campaign_v1 — Article 2 figures (matplotlib, Agg backend).

Reads aggregated_metrics.json (+ raw runs for dispersion) and renders only the
figures the data actually supports. A metric with no data yields no figure.

Usage: figures.py OUT_DIR CAMPAIGN_DIR [CAMPAIGN_DIR ...]
  (OUT_DIR must already contain aggregated_metrics.json from analyze.py)

External dependency: matplotlib (installed during the Article-2 dev phase;
record for the future Offline Artifact Set).
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = Path(sys.argv[1])
FIG = OUT / "figures"; FIG.mkdir(parents=True, exist_ok=True)
AGG = json.loads((OUT / "aggregated_metrics.json").read_text())


def num(x):
    return x if isinstance(x, (int, float)) else None


def raw_latencies(campaign_dirs):
    out = defaultdict(lambda: defaultdict(list))  # mode -> scenario -> [lat]
    for cd in campaign_dirs:
        for rp in Path(cd).rglob("result.json"):
            try:
                r = json.loads(rp.read_text())
            except Exception:
                continue
            if r.get("run_status") != "VALID":
                continue
            v = r.get("detection_latency_ms")
            if isinstance(v, (int, float)):
                out[r["mode"]][r["scenario"]].append(v)
    return out


def save(fig, name):
    fig.tight_layout(); fig.savefig(FIG / name, dpi=130); plt.close(fig)
    print("figure:", FIG / name)


# Fig 1 — Precision/Recall/F1 per mode
modes = [m for m in AGG["modes"] if m != "baseline"]
if modes:
    import numpy as np
    labels = ["precision", "recall_TPR", "f1"]
    x = np.arange(len(modes)); wdt = 0.25
    fig, ax = plt.subplots(figsize=(7, 4))
    for i, lab in enumerate(labels):
        vals = [num(AGG["modes"][m]["derived_metrics"][lab]) or 0 for m in modes]
        ax.bar(x + (i - 1) * wdt, vals, wdt, label=lab.replace("_TPR", ""))
    ax.set_xticks(x); ax.set_xticklabels(modes); ax.set_ylim(0, 1.05)
    ax.set_ylabel("score"); ax.set_title("Precision / Recall / F1 by engine mode"); ax.legend()
    save(fig, "fig1_precision_recall_f1.png")

# Fig 2 — detection rate per scenario (IDS)
if "ids" in AGG["modes"]:
    ps = AGG["modes"]["ids"]["per_scenario"]
    scn = [s for s in ps if isinstance(ps[s]["detection_rate"], (int, float))]
    if scn:
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.bar(scn, [ps[s]["detection_rate"] for s in scn], color="#3b7dd8")
        ax.set_ylim(0, 1.05); ax.set_ylabel("detection rate"); ax.set_title("IDS detection rate per scenario")
        save(fig, "fig2_detection_rate.png")

# Fig 3 & 9 — detection latency mean±std and dispersion (box) per scenario (IDS)
rawlat = raw_latencies(sys.argv[2:])
if rawlat.get("ids"):
    scn = sorted(rawlat["ids"])
    means = [AGG["modes"]["ids"]["per_scenario"][s]["detection_latency_ms"]["mean"] for s in scn]
    stds = [AGG["modes"]["ids"]["per_scenario"][s]["detection_latency_ms"]["std"] or 0 for s in scn]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(scn, means, yerr=stds, capsize=4, color="#48a56a")
    ax.set_ylabel("detection latency (ms)"); ax.set_title("IDS detection latency (mean ± SD)")
    save(fig, "fig3_detection_latency.png")

    data = [rawlat["ids"][s] for s in scn]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.boxplot(data, labels=scn, showmeans=True)
    ax.set_ylabel("detection latency (ms)"); ax.set_title("Detection latency dispersion over repetitions")
    save(fig, "fig9_latency_dispersion.png")

# Fig 4/5 — IPS blocking rate & latency
if "ips" in AGG["modes"]:
    ps = AGG["modes"]["ips"]["per_scenario"]
    scn = list(ps)
    if scn:
        fig, ax = plt.subplots(figsize=(7, 4))
        rates = [(ps[s]["blocked_runs"] / ps[s]["runs_valid"]) if ps[s]["runs_valid"] else 0 for s in scn]
        ax.bar(scn, rates, color="#d8663b"); ax.set_ylim(0, 1.05)
        ax.set_ylabel("blocking rate"); ax.set_title("IPS blocking rate per scenario")
        save(fig, "fig4_ips_blocking_rate.png")
        blat = [ps[s]["blocking_latency_ms"]["mean"] for s in scn]
        if any(isinstance(b, (int, float)) for b in blat):
            fig, ax = plt.subplots(figsize=(7, 4))
            ax.bar(scn, [num(b) or 0 for b in blat], color="#d8a93b")
            ax.set_ylabel("blocking latency (ms)"); ax.set_title("IPS blocking latency (mean)")
            save(fig, "fig5_ips_blocking_latency.png")

# Fig 6/7 — CPU & RAM per scenario, grouped by mode
def perf_fig(field, ylabel, title, name):
    allscn = sorted({s for m in AGG["modes"].values() for s in m["per_scenario"]})
    import numpy as np
    modes_ = list(AGG["modes"]); x = np.arange(len(allscn)); wdt = 0.8 / max(len(modes_), 1)
    fig, ax = plt.subplots(figsize=(8, 4)); any_data = False
    for i, m in enumerate(modes_):
        vals = []
        for s in allscn:
            d = AGG["modes"][m]["per_scenario"].get(s, {})
            v = d.get(field, {}).get("mean") if d else None
            vals.append(num(v) or 0)
            if num(v):
                any_data = True
        ax.bar(x + i * wdt, vals, wdt, label=m)
    if any_data:
        ax.set_xticks(x + wdt * (len(modes_) - 1) / 2); ax.set_xticklabels(allscn, rotation=30, ha="right")
        ax.set_ylabel(ylabel); ax.set_title(title); ax.legend()
        save(fig, name)
    else:
        plt.close(fig)

perf_fig("cpu_percent", "CPU %", "Suricata CPU per scenario/mode", "fig6_cpu.png")
perf_fig("rss_mb", "RSS (MB)", "Suricata RAM per scenario/mode", "fig7_ram.png")
perf_fig("captured_mbps", "Mbps", "Captured throughput: baseline vs IDS vs IPS", "fig8_baseline_ids_ips.png")

print("figures done")
