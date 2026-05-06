#!/usr/bin/env python3
"""
ARCHIVIRT - IDS Comparison Report Generator (English version)
Reads: results/snort3_final_results.json, results/suricata_final_results.json,
       results/performance_baseline.json, results/dbscan_latest.json
Output: results/archivirt_final_comparison.json (Tables 2, 3, 4)
"""

import json, os
from datetime import date

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "..", "results")

def load_json(filename):
    filepath = os.path.join(RESULTS_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath) as f:
            return json.load(f)
    return None

def safe_get(d, key, default=0):
    return d.get(key, default)

def load_perf():
    return load_json("performance_baseline.json") or {}

def load_dbscan():
    db = load_json("dbscan_latest.json")
    if not db:
        return {"snort": {}, "suricata": {}}
    snort_db = db.get("snort_dbscan", {})
    suricata_db = db.get("suricata_dbscan", {})
    return {"snort": snort_db, "suricata": suricata_db}

SCENARIO_EN = {
    "SCN-001": "Port Scan",
    "SCN-002": "SSH Brute-force",
    "SCN-003": "SQL Injection",
    "SCN-004": "DDoS Slowloris",
    "SCN-005": "Normal Traffic"
}

def build_report():
    snort = load_json("snort3_final_results.json")
    suricata = load_json("suricata_final_results.json")
    perf = load_perf()
    dbscan = load_dbscan()

    if not snort or not suricata:
        print("ERROR: missing result files")
        return None

    snort_sc = safe_get(snort, "scenarios", {})
    suricata_sc = safe_get(suricata, "scenarios", {})

    # Table 2 – Detection Efficiency
    table2 = {"title": "Table 2: Detection Efficiency Metrics (average over 10 runs)", "rows": []}
    for sid in ["SCN-001","SCN-002","SCN-003","SCN-004","SCN-005"]:
        s = snort_sc.get(sid, {})
        u = suricata_sc.get(sid, {})
        row = {
            "scenario": SCENARIO_EN.get(sid, sid),
            "snort": {
                "alerts": safe_get(s, "alerts", 0),
                "detection": safe_get(s, "detection_rate", "N/A"),
                "fpr": safe_get(s, "false_positive", 0.0),
                "latency": safe_get(s, "latency_ms", "N/A")
            },
            "suricata": {
                "alerts": safe_get(u, "alerts", 0),
                "detection": safe_get(u, "detection_rate", "N/A"),
                "fpr": safe_get(u, "false_positive", 0.0),
                "latency": safe_get(u, "latency_ms", "N/A")
            }
        }
        table2["rows"].append(row)

    # Table 3 – System Performance
    table3 = {"title": "Table 3: System Performance Metrics (peak during tests)", "rows": []}
    snort_perf = {
        "ids": "Snort",
        "cpu": perf.get("snort_cpu","N/A"),
        "ram": perf.get("snort_ram","N/A"),
        "mbit": perf.get("snort_throughput","N/A")
    }
    suricata_perf = {
        "ids": "Suricata",
        "cpu": perf.get("suricata_cpu","N/A"),
        "ram": perf.get("suricata_ram","N/A"),
        "mbit": perf.get("suricata_throughput","N/A")
    }
    table3["rows"].append(snort_perf)
    table3["rows"].append(suricata_perf)

    # Table 4 – DBSCAN Analysis
    table4 = {"title": "Table 4: DBSCAN/UEBA Analysis Results", "rows": []}
    for ids_key, ids_name in [("snort","Snort"), ("suricata","Suricata")]:
        d = dbscan.get(ids_key, {})
        table4["rows"].append({
            "ids": ids_name,
            "events": 3000 if d else "N/A",
            "clusters": d.get("clusters", "N/A"),
            "anomalies": d.get("anomalies", "N/A"),
            "anomaly_rate": d.get("anomaly_rate", "N/A")
        })

    return {
        "title": "ARCHIVIRT - IDS Comparison Report",
        "date": str(date.today()),
        "table2": table2,
        "table3": table3,
        "table4": table4
    }

def print_report(rep):
    if not rep:
        return
    # Table 2
    print("=" * 90)
    print(rep["table2"]["title"])
    header = f"{'Scenario':<22} {'IDS':<12} {'Alerts':>7} {'Detect%':>8} {'FPR%':>7} {'Lat(ms)':>10}"
    print(header)
    print("-" * len(header))
    for row in rep["table2"]["rows"]:
        for ids_key in ["snort", "suricata"]:
            d = row[ids_key]
            name = "Snort" if ids_key=="snort" else "Suricata"
            det = f"{d['detection']:.1f}" if isinstance(d['detection'], (int,float)) else str(d['detection'])
            fpr = f"{d['fpr']:.2f}" if isinstance(d['fpr'], (int,float)) else str(d['fpr'])
            lat = f"{d['latency']:.1f}" if isinstance(d['latency'], (int,float)) else str(d['latency'])
            print(f"{row['scenario']:<22} {name:<12} {d['alerts']:>7} {det:>8} {fpr:>7} {lat:>10}")
        print()

    # Table 3
    print("=" * 70)
    print(rep["table3"]["title"])
    header3 = f"{'IDS':<12} {'CPU%':>6} {'RAM MB':>7} {'Mbps':>7}"
    print(header3)
    print("-" * 35)
    for r in rep["table3"]["rows"]:
        cpu = f"{r['cpu']:.1f}" if isinstance(r['cpu'], (int,float)) else str(r['cpu'])
        ram = f"{r['ram']:.1f}" if isinstance(r['ram'], (int,float)) else str(r['ram'])
        mbit = f"{r['mbit']:.1f}" if isinstance(r['mbit'], (int,float)) else str(r['mbit'])
        print(f"{r['ids']:<12} {cpu:>6} {ram:>7} {mbit:>7}")

    # Table 4
    print("\n" + "=" * 70)
    print(rep["table4"]["title"])
    header4 = f"{'IDS':<12} {'Events':>7} {'Clusters':>10} {'Anomalies':>10} {'Rate%':>7}"
    print(header4)
    print("-" * 47)
    for r in rep["table4"]["rows"]:
        eve = str(r['events'])
        clu = str(r['clusters'])
        ano = str(r['anomalies'])
        rate = f"{r['anomaly_rate']:.2f}" if isinstance(r['anomaly_rate'], (int,float)) else str(r['anomaly_rate'])
        print(f"{r['ids']:<12} {eve:>7} {clu:>10} {ano:>10} {rate:>7}")

if __name__ == "__main__":
    rep = build_report()
    if rep:
        outpath = os.path.join(RESULTS_DIR, "archivirt_final_comparison.json")
        with open(outpath, "w") as f:
            json.dump(rep, f, indent=2, ensure_ascii=False)
        print(f"Saved: {outpath}\n")
        print_report(rep)
    else:
        print("ERROR: could not build comparison")
        exit(1)
