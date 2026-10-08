#!/usr/bin/env python3
"""Build Article-2 publication-source tables (A–K) from aggregated_metrics.json.

Clean CSVs destined for later manuscript typesetting — NOT the final manuscript.
No fabricated values: undefined measures are written NOT_AVAILABLE / NOT_APPLICABLE.

Usage: make_publication_tables.py ARTICLE2_DIR
"""
import csv
import json
import sys
from pathlib import Path

D = Path(sys.argv[1])
A = json.loads((D / "aggregated_metrics.json").read_text())
PUB = D / "tables" / "publication"
PUB.mkdir(parents=True, exist_ok=True)


def w(name, header, rows):
    with open(PUB / name, "w", newline="") as f:
        c = csv.writer(f); c.writerow(header); c.writerows(rows)


SCN = {
    "SCN-001": ("Nmap SYN scan", "tcp", "SYN rate >=100/5s by src"),
    "SCN-002": ("SSH connection-rate attack pattern", "tcp/22", "SYN rate >=5/10s by src"),
    "SCN-003": ("SQLMap (tool User-Agent)", "http", "User-Agent contains 'sqlmap'"),
    "SCN-004": ("Slowloris HTTP DoS", "tcp/80", "SYN rate >=50/10s by src"),
    "SCN-005": ("Benign HTTP (negative control)", "http", "none (control)"),
}

# A — scenarios
w("tableA_scenarios.csv", ["scenario", "ground_truth", "description", "protocol", "trigger"],
  [[s, "benign" if s == "SCN-005" else "attack", m[0], m[1], m[2]] for s, m in SCN.items()])


def confusion(mode):
    return A["modes"].get(mode, {}).get("derived_metrics", {}).get("confusion", {})


def metrics(mode):
    return A["modes"].get(mode, {}).get("derived_metrics", {})


for mode, b_name, m_name in (("ids", "tableB_confusion_ids.csv", "tableC_metrics_ids.csv"),
                              ("ips", "tableE_confusion_ips.csv", "tableF_metrics_ips.csv")):
    c = confusion(mode)
    w(b_name, ["class", "count", "unit", "definition"],
      [["TP", c.get("TP"), "runs", "attack run, expected SID fired"],
       ["FN", c.get("FN"), "runs", "attack run, expected SID did NOT fire"],
       ["FP", c.get("FP"), "runs", "benign run, an attack SID fired"],
       ["TN", c.get("TN"), "runs", "benign run, no attack SID fired"]])
    dm = metrics(mode)
    w(m_name, ["metric", "value", "n_runs", "note"],
      [["accuracy", dm.get("accuracy"), c.get("TP", 0)+c.get("TN", 0)+c.get("FP", 0)+c.get("FN", 0), "controlled signature set"],
       ["precision", dm.get("precision"), "", ""],
       ["recall", dm.get("recall_TPR"), "", ""],
       ["f1", dm.get("f1"), "", ""],
       ["fpr", dm.get("fpr"), "", ""],
       ["fnr", dm.get("fnr"), "", ""]])


def lat_rows(mode):
    rows = []
    for s, d in A["modes"].get(mode, {}).get("per_scenario", {}).items():
        l = d["detection_latency_ms"]
        if l["n"]:
            rows.append([s, l["n"], l["mean"], l["median"], l["std"], l["min"], l["max"],
                         l["ci95"] if l["ci95"] else "NOT_AVAILABLE", l["cv"]])
    return rows


# D — IDS latency
w("tableD_latency_ids.csv",
  ["scenario", "n", "mean_ms", "median_ms", "sd_ms", "min_ms", "max_ms", "ci95_ms", "cv"],
  lat_rows("ids"))

# G — IPS blocking
rowsG = []
for s, d in A["modes"].get("ips", {}).get("per_scenario", {}).items():
    rv = d["runs_valid"]
    rate = round(d["blocked_runs"]/rv, 4) if rv else "NOT_AVAILABLE"
    rowsG.append([s, rv, d["blocked_runs"], rate, "runs"])
w("tableG_ips_blocking.csv", ["scenario", "runs_valid", "blocked_runs", "blocking_rate", "unit"], rowsG)

# H — IPS detection + blocking latency
rowsH = []
for s, d in A["modes"].get("ips", {}).get("per_scenario", {}).items():
    l = d["detection_latency_ms"]; b = d["blocking_latency_ms"]
    if l["n"]:
        rowsH.append([s, l["n"], l["mean"], l["std"], l["ci95"] or "NOT_AVAILABLE",
                      b["mean"], b["std"], b["ci95"] or "NOT_AVAILABLE"])
w("tableH_ips_latency.csv",
  ["scenario", "n", "det_mean_ms", "det_sd_ms", "det_ci95", "block_mean_ms", "block_sd_ms", "block_ci95"], rowsH)

# I — CPU / RAM per scenario per mode
rowsI = []
for mode in A["modes"]:
    for s, d in A["modes"][mode]["per_scenario"].items():
        cpu = d["cpu_percent"]; rss = d["rss_mb"]
        cpu_v = cpu["mean"] if isinstance(cpu["mean"], (int, float)) else "NOT_APPLICABLE"
        rss_v = rss["mean"] if isinstance(rss["mean"], (int, float)) else "NOT_APPLICABLE"
        rowsI.append([mode, s, cpu["n"], cpu_v, cpu["std"], rss_v, rss["std"]])
w("tableI_cpu_ram.csv", ["mode", "scenario", "n", "cpu_pct_mean", "cpu_sd", "rss_mb_mean", "rss_sd"], rowsI)

# J — baseline / IDS / IPS comparison with deltas vs baseline (traffic only; CPU/RAM N/A in baseline)
def mode_mean(mode, field):
    md = A["modes"].get(mode)
    if not md:
        return None
    v = [d[field]["mean"] for d in md["per_scenario"].values() if isinstance(d[field]["mean"], (int, float))]
    return round(sum(v)/len(v), 4) if v else None


rowsJ = []
for field, unit in (("cpu_percent", "%"), ("rss_mb", "MB"), ("captured_pps", "pps"), ("captured_mbps", "Mbps")):
    b, i, p = mode_mean("baseline", field), mode_mean("ids", field), mode_mean("ips", field)
    if field in ("cpu_percent", "rss_mb"):
        b = "NOT_APPLICABLE"
    if field in ("captured_pps", "captured_mbps"):
        p = "NOT_APPLICABLE"
    def dlt(x, base):
        if isinstance(x, (int, float)) and isinstance(base, (int, float)) and base:
            return f"{round(100*(x-base)/base,1)}%"
        return "NOT_AVAILABLE"
    rowsJ.append([field, unit, b, i, p, dlt(i, b) if isinstance(b, (int, float)) else "NOT_AVAILABLE"])
w("tableJ_baseline_ids_ips.csv", ["metric", "unit", "baseline", "ids", "ips", "ids_vs_baseline_rel"], rowsJ)

# K — reproducibility / statistics (latency CV + CI95)
rowsK = []
for mode in A["modes"]:
    for s, d in A["modes"][mode]["per_scenario"].items():
        l = d["detection_latency_ms"]
        if l["n"] > 1:
            rowsK.append([mode, s, "detection_latency_ms", l["n"], l["mean"], l["std"],
                          l["cv"], l["ci95"]])
w("tableK_reproducibility.csv", ["mode", "scenario", "metric", "n", "mean", "sd", "cv", "ci95"], rowsK)

print("publication tables written to", PUB)
for p in sorted(PUB.glob("*.csv")):
    print("  ", p.name)
