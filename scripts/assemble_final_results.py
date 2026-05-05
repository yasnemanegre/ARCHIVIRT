#!/usr/bin/env python3
import json, os, glob
from datetime import date

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
TMP_DIR = "/tmp"

def load_json(filename):
    filepath = os.path.join(RESULTS_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath) as f:
            return json.load(f)
    return None

def load_perf_baseline():
    return load_json("performance_baseline.json") or {}

def assemble(ids_type, prefix):
    pattern = os.path.join(TMP_DIR, f"{prefix}_SCN-*_result.json")
    files = sorted(glob.glob(pattern))
    if not files:
        return None
    scenarios = {}
    total_alerts = 0
    for fpath in files:
        with open(fpath) as f:
            data = json.load(f)
        sid = data.get("scenario", os.path.basename(fpath).split("_")[1])
        alerts = data.get("alerts", 0)
        scenarios[sid] = {"alerts": alerts}
        total_alerts += alerts

    version = "Unknown"
    if files:
        with open(files[0]) as f:
            version = json.load(f).get("ids", f"{ids_type} unknown")

    # Load detection metrics if available
    metrics_file = os.path.join(RESULTS_DIR, f"detection_metrics_{prefix}.json")
    if os.path.exists(metrics_file):
        with open(metrics_file) as f:
            det_metrics = json.load(f)
        for sid in scenarios:
            if sid in det_metrics:
                scenarios[sid].update(det_metrics[sid])
    else:
        # Add placeholders
        for sid in scenarios:
            scenarios[sid]["detection_rate"] = "N/A"
            scenarios[sid]["latency_ms"] = "N/A"
            scenarios[sid]["false_positive"] = 0.0

    final = {
        "ids": version,
        "date": str(date.today()),
        "scenarios": scenarios,
        "total_alerts": total_alerts,
        "performance": load_perf_baseline()
    }
    return final

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    snort_final = assemble("Snort", "snort3")
    suricata_final = assemble("Suricata", "suricata")
    if snort_final:
        with open(os.path.join(RESULTS_DIR, "snort3_final_results.json"), "w") as f:
            json.dump(snort_final, f, indent=2)
    if suricata_final:
        with open(os.path.join(RESULTS_DIR, "suricata_final_results.json"), "w") as f:
            json.dump(suricata_final, f, indent=2)
    print("Assembly complete.")

if __name__ == "__main__":
    main()
