#!/usr/bin/env python3
"""ARCHIVIRT campaign_v1 — Article 2 analysis: metrics, confusion matrix, stats.

Reads the raw per-run result.json / perf.json of one or more campaigns and
produces aggregated metrics, a run-level confusion matrix, derived metrics
(Accuracy/Precision/Recall/F1/FPR/FNR), latency & performance statistics, and
the Article-2 tables (CSV + markdown). It never fabricates a value: a metric
whose denominator is undefined is reported as NOT_AVAILABLE / NOT_APPLICABLE.

Only VALID runs feed detection/latency/perf aggregates. INVALID and
PREREQUISITE_MISSING runs are counted but excluded from VALID means.

Usage:
  analyze.py OUT_DIR CAMPAIGN_DIR [CAMPAIGN_DIR ...]
"""
import csv
import json
import math
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

try:
    from scipy import stats as scistats
    HAVE_SCIPY = True
except Exception:
    HAVE_SCIPY = False


def load_runs(campaign_dirs):
    runs = []
    for cd in campaign_dirs:
        cd = Path(cd)
        for rp in sorted(cd.rglob("result.json")):
            try:
                r = json.loads(rp.read_text())
            except Exception:
                continue
            if "ground_truth" not in r:          # skip legacy-schema runs
                continue
            perf = {}
            pp = rp.parent / "perf.json"
            if pp.exists():
                try:
                    perf = json.loads(pp.read_text())
                except Exception:
                    perf = {}
            r["_perf"] = perf
            r["_path"] = str(rp)
            runs.append(r)
    return runs


def descr(values):
    vals = [v for v in values if isinstance(v, (int, float))]
    n = len(vals)
    if n == 0:
        return {"n": 0, "mean": None, "median": None, "std": None,
                "min": None, "max": None, "ci95": None, "cv": None}
    mean = st.mean(vals)
    sd = st.stdev(vals) if n > 1 else 0.0
    ci = None
    if n > 1 and HAVE_SCIPY:
        tcrit = scistats.t.ppf(0.975, n - 1)
        half = tcrit * sd / math.sqrt(n)
        ci = [round(mean - half, 3), round(mean + half, 3)]
    cv = round(sd / mean, 4) if mean else None
    if ci:
        ci = [float(ci[0]), float(ci[1])]
    return {"n": n, "mean": round(mean, 3), "median": round(st.median(vals), 3),
            "std": round(sd, 3), "min": round(min(vals), 3), "max": round(max(vals), 3),
            "ci95": ci, "cv": cv}


def analyze_mode(runs, mode):
    """Aggregate one engine mode (ids/ips/baseline).

    Detection/confusion/latency use VALID runs only. Performance uses VALID
    runs for ids/ips, but ALL runs for baseline (baseline is INVALID-by-design
    for detection — no engine, no EVE — yet its system/traffic measurements are
    valid and must be aggregated).
    """
    by_scn = defaultdict(list)
    for r in runs:
        by_scn[r["scenario"]].append(r)

    per_scenario = {}
    conf = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for scn, rs in sorted(by_scn.items()):
        valid = [r for r in rs if r["run_status"] == "VALID"]
        perf_runs = rs if mode == "baseline" else valid
        tally = defaultdict(int)
        for r in rs:
            if r["classification"] in conf:
                tally[r["classification"]] += 1
        # Confusion counts come from ALL runs with a ground-truth class that
        # actually produced evidence (VALID attack/benign runs).
        for r in valid:
            c = r["classification"]
            if c in conf:
                conf[c] += 1
        lat = descr([r["detection_latency_ms"] for r in valid])
        blat = descr([r["blocking_latency_ms"] for r in valid])
        cpu = descr([r["_perf"].get("cpu_percent") for r in perf_runs])
        rss = descr([r["_perf"].get("rss_mb") for r in perf_runs])
        pps = descr([r["_perf"].get("captured_pps") for r in perf_runs])
        mbps = descr([r["_perf"].get("captured_mbps") for r in perf_runs])
        drops = descr([r["_perf"].get("captured_drops") for r in perf_runs])
        alerts = descr([r["alert_count"] for r in valid])
        n_attack = sum(1 for r in rs if r["ground_truth"] == "attack")
        n_det = sum(1 for r in valid if r["ground_truth"] == "attack" and r["detection_status"])
        n_block = sum(1 for r in valid if r.get("blocking_status") is True)
        per_scenario[scn] = {
            "ground_truth": rs[0]["ground_truth"],
            "expected_sid": rs[0].get("expected_sid"),
            "runs_total": len(rs),
            "runs_valid": len(valid),
            "runs_invalid": sum(1 for r in rs if r["run_status"] == "INVALID"),
            "runs_prereq_missing": sum(1 for r in rs if r["run_status"] == "PREREQUISITE_MISSING"),
            "classification_tally": dict(tally),
            "detection_rate": (round(n_det / len([r for r in valid if r["ground_truth"] == "attack"]), 4)
                               if any(r["ground_truth"] == "attack" for r in valid) else "NOT_APPLICABLE"),
            "blocked_runs": n_block,
            "alert_count": alerts,
            "detection_latency_ms": lat,
            "blocking_latency_ms": blat,
            "cpu_percent": cpu,
            "rss_mb": rss,
            "captured_pps": pps,
            "captured_mbps": mbps,
            "captured_drops": drops,
        }

    tp, fp, fn, tn = conf["TP"], conf["FP"], conf["FN"], conf["TN"]
    def ratio(num, den):
        return round(num / den, 4) if den > 0 else "NOT_AVAILABLE"
    derived = {
        "confusion": conf,
        "accuracy": ratio(tp + tn, tp + tn + fp + fn),
        "precision": ratio(tp, tp + fp),
        "recall_TPR": ratio(tp, tp + fn),
        "f1": (round(2 * tp / (2 * tp + fp + fn), 4) if (2 * tp + fp + fn) > 0 else "NOT_AVAILABLE"),
        "fpr": ratio(fp, fp + tn),
        "fnr": ratio(fn, fn + tp),
    }
    return {"per_scenario": per_scenario, "derived_metrics": derived}


def main():
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
    (out / "tables").mkdir(exist_ok=True)
    runs = load_runs(sys.argv[2:])

    by_mode = defaultdict(list)
    for r in runs:
        by_mode[r["mode"]].append(r)

    report = {"n_runs_total": len(runs), "campaigns": sys.argv[2:], "modes": {},
              "signature_note": "Metrics reflect the controlled, discriminative ARCHIVIRT "
              "Article-2 signature set (4 threshold-based signatures), not a general property "
              "of Suricata. Run-level confusion: attack runs -> TP/FN by expected SID; benign "
              "runs -> TN/FP by any attack SID. Baseline is INVALID-by-design for detection."}
    for mode, rs in by_mode.items():
        report["modes"][mode] = analyze_mode(rs, mode)

    (out / "aggregated_metrics.json").write_text(json.dumps(report, indent=2))

    # ---- Tables (CSV) ----
    def w(name, header, rows):
        with open(out / "tables" / name, "w", newline="") as f:
            cw = csv.writer(f); cw.writerow(header); cw.writerows(rows)

    # Table 2 — IDS results per scenario
    for mode in report["modes"]:
        rows = []
        for scn, d in report["modes"][mode]["per_scenario"].items():
            rows.append([scn, d["ground_truth"], d["runs_total"], d["runs_valid"],
                         d["runs_invalid"], d["runs_prereq_missing"], d["detection_rate"],
                         d["alert_count"]["mean"], d["detection_latency_ms"]["mean"]])
        w(f"table2_{mode}_results.csv",
          ["scenario", "ground_truth", "runs", "valid", "invalid", "prereq_missing",
           "detection_rate", "alerts_mean", "det_latency_ms_mean"], rows)

    # Table 3/4 — confusion + derived metrics per mode
    rows34 = []
    for mode, md in report["modes"].items():
        c = md["derived_metrics"]["confusion"]; dm = md["derived_metrics"]
        rows34.append([mode, c["TP"], c["FP"], c["FN"], c["TN"], dm["accuracy"],
                       dm["precision"], dm["recall_TPR"], dm["f1"], dm["fpr"], dm["fnr"]])
    w("table3_4_confusion_metrics.csv",
      ["mode", "TP", "FP", "FN", "TN", "accuracy", "precision", "recall", "f1", "fpr", "fnr"], rows34)

    # Table 5 — detection latency stats
    rows5 = []
    for mode, md in report["modes"].items():
        for scn, d in md["per_scenario"].items():
            l = d["detection_latency_ms"]
            rows5.append([mode, scn, l["n"], l["mean"], l["median"], l["std"],
                          l["min"], l["max"], l["ci95"]])
    w("table5_detection_latency.csv",
      ["mode", "scenario", "n", "mean_ms", "median_ms", "std_ms", "min_ms", "max_ms", "ci95"], rows5)

    # Table 6 — IPS blocking
    rows6 = []
    for scn, d in report["modes"].get("ips", {}).get("per_scenario", {}).items():
        rows6.append([scn, d["runs_valid"], d["blocked_runs"],
                      (round(d["blocked_runs"] / d["runs_valid"], 4) if d["runs_valid"] else "NOT_AVAILABLE"),
                      d["blocking_latency_ms"]["mean"]])
    w("table6_ips_blocking.csv",
      ["scenario", "runs_valid", "blocked_runs", "blocking_rate", "block_latency_ms_mean"], rows6)

    # Table 7 — IPS latency (blocking + detection in inline mode)
    rows7 = []
    for scn, d in report["modes"].get("ips", {}).get("per_scenario", {}).items():
        b = d["blocking_latency_ms"]; l = d["detection_latency_ms"]
        rows7.append([scn, l["n"], l["mean"], l["std"], b["mean"], b["std"], b["ci95"]])
    w("table7_ips_latency.csv",
      ["scenario", "n", "det_latency_ms_mean", "det_std", "block_latency_ms_mean",
       "block_std", "block_ci95"], rows7)

    # Table 1 — experimental scenarios
    SCN_META = {
        "SCN-001": ("Nmap SYN scan", "tcp", "SYN rate >=100/5s by src", 2000001),
        "SCN-002": ("SSH connection-rate pattern", "tcp/22", "SYN rate >=5/10s by src", 2000002),
        "SCN-003": ("SQLMap (tool UA)", "http", "User-Agent contains 'sqlmap'", 2000003),
        "SCN-004": ("Slowloris HTTP DoS", "tcp/80", "SYN rate >=50/10s by src", 2000004),
        "SCN-005": ("Benign HTTP (negative control)", "http", "none (control)", None),
    }
    w("table1_scenarios.csv",
      ["scenario", "description", "protocol", "trigger_condition", "expected_sid_ids", "ground_truth"],
      [[s, m[0], m[1], m[2], m[3], ("benign" if s == "SCN-005" else "attack")]
       for s, m in SCN_META.items()])

    # Table 8 — Baseline/IDS/IPS resource impact (+ deltas vs baseline).
    # Engine CPU/RAM averaged over scenarios per mode. IPS mirror-interface
    # throughput is NOT_APPLICABLE (inline path is ens4/ens5, not mirrored).
    def mode_mean(mode, field):
        md = report["modes"].get(mode)
        if not md:
            return None
        vals = [d[field]["mean"] for d in md["per_scenario"].values()
                if isinstance(d[field]["mean"], (int, float))]
        return round(sum(vals) / len(vals), 3) if vals else None

    rows8 = []
    for field, unit in (("cpu_percent", "%"), ("rss_mb", "MB"),
                        ("captured_pps", "pps"), ("captured_mbps", "Mbps"),
                        ("captured_drops", "pkts")):
        b = mode_mean("baseline", field)
        i = mode_mean("ids", field)
        p = mode_mean("ips", field)
        # IPS traffic counters are off-path on the mirror interfaces.
        if field in ("captured_pps", "captured_mbps", "captured_drops"):
            p = "NOT_APPLICABLE(inline path not mirrored)"
        if field in ("cpu_percent", "rss_mb"):
            b = "NOT_APPLICABLE(no engine)"
        def delta(x, base):
            if not isinstance(x, (int, float)) or not isinstance(base, (int, float)) or base == 0:
                return "NOT_AVAILABLE"
            return f"{round(100*(x-base)/base,1)}%"
        rows8.append([field, unit, b, i, p])
    w("table8_resource_impact.csv", ["metric", "unit", "baseline", "ids", "ips"], rows8)

    # Table 9 — statistical reproducibility (per mode/scenario: latency n/mean/sd/cv).
    rows9 = []
    stat_summary = {"detection_latency_ms": {}, "cpu_percent": {}, "rss_mb": {}}
    for mode, md in report["modes"].items():
        for scn, d in md["per_scenario"].items():
            l = d["detection_latency_ms"]
            if l["n"] > 0:
                rows9.append([mode, scn, "detection_latency_ms", l["n"], l["mean"],
                              l["std"], l["cv"], l["ci95"]])
            for metric in ("detection_latency_ms", "cpu_percent", "rss_mb"):
                dd = d[metric]
                if dd["n"] > 0:
                    stat_summary[metric][f"{mode}:{scn}"] = dd
    w("table9_reproducibility.csv",
      ["mode", "scenario", "metric", "n", "mean", "std", "cv", "ci95"], rows9)

    (out / "statistical_summary.json").write_text(json.dumps(stat_summary, indent=2))

    # Flat per-run CSV (raw, exploitable).
    with open(out / "article2_results.csv", "w", newline="") as f:
        cw = csv.writer(f)
        cw.writerow(["experiment_id", "run_id", "mode", "scenario", "ground_truth",
                     "run_status", "classification", "detection_status", "blocking_status",
                     "alert_count", "fired_attack_sids", "detection_latency_ms",
                     "blocking_latency_ms", "cpu_percent", "rss_mb", "captured_pps",
                     "captured_mbps", "captured_drops"])
        for r in runs:
            p = r["_perf"]
            cw.writerow([r.get("experiment_id"), r["run_id"], r["mode"], r["scenario"],
                         r["ground_truth"], r["run_status"], r["classification"],
                         r["detection_status"], r["blocking_status"], r["alert_count"],
                         "|".join(str(s) for s in r["fired_attack_sids"]),
                         r["detection_latency_ms"], r["blocking_latency_ms"],
                         p.get("cpu_percent"), p.get("rss_mb"), p.get("captured_pps"),
                         p.get("captured_mbps"), p.get("captured_drops")])

    print(json.dumps({"n_runs": len(runs), "modes": list(report["modes"].keys()),
                      "out": str(out)}, indent=2))


if __name__ == "__main__":
    main()
