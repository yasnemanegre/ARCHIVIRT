#!/usr/bin/env python3
"""
ARCHIVIRT - Sigma Analysis across 10 campaigns
Author: Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
Version: 2.0.0 — extends sigma to Table 3 (CPU/RAM/Mbps per IDS)
"""
import json, sys, os, glob
import statistics

campaigns_dir = sys.argv[1] if len(sys.argv) > 1 else "results/campaigns"
output_file   = sys.argv[2] if len(sys.argv) > 2 else "results/sigma_analysis.json"

# ── Table 2 — Detection metrics (DR/FPR/latency per scenario+IDS) ────────────
files = sorted(glob.glob(os.path.join(campaigns_dir, "campaign_*_comparison.json")))
print(f"Campagnes Table 2 trouvées: {len(files)}")

metrics = {}
for f in files:
    with open(f) as fh:
        data = json.load(fh)
    for row in data.get("results", []):
        key = f"{row['scenario']}_{row['ids']}"
        if key not in metrics:
            metrics[key] = {"dr": [], "fpr": [], "latency": [], "alerts": []}
        metrics[key]["dr"].append(float(row.get("dr_pct", 0)))
        metrics[key]["fpr"].append(float(row.get("fpr_pct", 0)))
        metrics[key]["latency"].append(float(row.get("latency_ms", 0)))
        metrics[key]["alerts"].append(int(row.get("alerts", 0)))

sigma_results = {}
max_sigma_dr = 0.0
print(f"\n{'Scénario/IDS':<40} {'DR mean':>8} {'σ DR':>8} {'σ%':>8}")
print("-" * 70)
for key, vals in sorted(metrics.items()):
    if len(vals["dr"]) < 2:
        continue
    mean_dr  = statistics.mean(vals["dr"])
    sigma_dr = statistics.stdev(vals["dr"])
    sigma_pct = (sigma_dr / mean_dr * 100) if mean_dr > 0 else 0
    max_sigma_dr = max(max_sigma_dr, sigma_pct)
    sigma_results[key] = {
        "dr_mean":     round(mean_dr, 2),
        "dr_sigma":    round(sigma_dr, 4),
        "dr_sigma_pct": round(sigma_pct, 2),
        "fpr_mean":    round(statistics.mean(vals["fpr"]), 3),
        "fpr_sigma":   round(statistics.stdev(vals["fpr"]), 4),
        "lat_mean":    round(statistics.mean(vals["latency"]), 1),
        "lat_sigma":   round(statistics.stdev(vals["latency"]), 2),
        "n_campaigns": len(vals["dr"]),
    }
    print(f"{key:<40} {mean_dr:>8.2f} {sigma_dr:>8.4f} {sigma_pct:>7.2f}%")

# ── Table 3 — Performance metrics (CPU/RAM/Mbps per IDS) ─────────────────────
perf_files = sorted(glob.glob(os.path.join(campaigns_dir, "campaign_*_performance.json")))
print(f"\nCampagnes Table 3 trouvées: {len(perf_files)}")

perf_metrics = {
    "snort":    {"cpu": [], "ram": [], "throughput": []},
    "suricata": {"cpu": [], "ram": [], "throughput": []},
}
for f in perf_files:
    with open(f) as fh:
        data = json.load(fh)
    for ids in ("snort", "suricata"):
        cpu_key = f"{ids}_cpu"
        ram_key = f"{ids}_ram"
        tput_key = f"{ids}_throughput"
        if cpu_key in data:
            perf_metrics[ids]["cpu"].append(float(data[cpu_key]))
        if ram_key in data:
            perf_metrics[ids]["ram"].append(float(data[ram_key]))
        if tput_key in data:
            perf_metrics[ids]["throughput"].append(float(data[tput_key]))

perf_sigma_results = {}
max_sigma_perf = 0.0
if perf_files:
    print(f"\n{'IDS':<12} {'Metric':<12} {'Mean':>10} {'σ':>10} {'σ%':>8}")
    print("-" * 60)
    for ids, vals in perf_metrics.items():
        perf_sigma_results[ids] = {}
        for metric_name, samples in vals.items():
            if len(samples) < 2:
                continue
            mean_v = statistics.mean(samples)
            sigma_v = statistics.stdev(samples)
            sigma_pct = (sigma_v / mean_v * 100) if mean_v > 0 else 0
            max_sigma_perf = max(max_sigma_perf, sigma_pct)
            perf_sigma_results[ids][metric_name] = {
                "mean": round(mean_v, 3),
                "sigma": round(sigma_v, 4),
                "sigma_pct": round(sigma_pct, 2),
                "n_campaigns": len(samples),
            }
            print(f"{ids:<12} {metric_name:<12} {mean_v:>10.3f} {sigma_v:>10.4f} {sigma_pct:>7.2f}%")
else:
    print("⚠ Aucun fichier campaign_*_performance.json trouvé — Table 3 non incluse dans σ")

# ── Verdicts ──────────────────────────────────────────────────────────────────
verdict_dr = "✅ VALIDÉ σ < 2%" if max_sigma_dr < 2.0 else f"❌ σ max = {max_sigma_dr:.2f}% > 2%"
verdict_perf = (
    "✅ VALIDÉ σ < 2%" if (perf_files and max_sigma_perf < 2.0)
    else (f"❌ σ max = {max_sigma_perf:.2f}% > 2%" if perf_files else "⚠ NON ÉVALUÉ (pas de données)")
)

print(f"\nσ maximum Table 2 (DR%): {max_sigma_dr:.2f}%  →  {verdict_dr}")
if perf_files:
    print(f"σ maximum Table 3 (CPU/RAM/Mbps): {max_sigma_perf:.2f}%  →  {verdict_perf}")

output = {
    "n_campaigns_table2": len(files),
    "n_campaigns_table3": len(perf_files),
    "max_sigma_dr_pct": round(max_sigma_dr, 2),
    "max_sigma_performance_pct": round(max_sigma_perf, 2) if perf_files else None,
    "verdict_table2": verdict_dr,
    "verdict_table3": verdict_perf,
    "details_table2": sigma_results,
    "details_table3": perf_sigma_results,
}
with open(output_file, "w") as f:
    json.dump(output, f, indent=2)
print(f"\nRésultats sauvegardés: {output_file}")
