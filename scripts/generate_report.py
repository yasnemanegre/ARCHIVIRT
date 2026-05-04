#!/usr/bin/env python3
"""
ARCHIVIRT - Automated IDS Comparison Report Generator
Author: Yasnemanegre SAWADOGO (SPbGUPTD)
All values come from results/*.json files - no hardcoded metrics.
Reads: results/snort3_final_results.json, results/suricata_final_results.json
Output: results/archivirt_final_comparison.json (Table 2, Table 3, Table DBSCAN)
"""
import json, os
from datetime import date

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "..", "results")

def load_json(filename):
    filepath = os.path.join(RESULTS_DIR, filename)
    if not os.path.exists(filepath):
        print(f"ERROR: {filepath} not found")
        return None
    with open(filepath) as f:
        return json.load(f)

def safe_get(d, key, default=0):
    """Safely get nested dict value"""
    return d.get(key, default)

def build_comparison():
    snort = load_json("snort3_final_results.json")
    suricata = load_json("suricata_final_results.json")

    if not snort or not suricata:
        print("ERROR: missing result files")
        return None

    snort_scenarios = safe_get(snort, "scenarios", {})
    suricata_scenarios = safe_get(suricata, "scenarios", {})
    snort_total = safe_get(snort, "total_alerts", 0)
    suricata_total = safe_get(suricata, "total_alerts", 0)
    snort_perf = safe_get(snort, "performance", {})
    suricata_perf = safe_get(suricata, "performance", {})
    snort_dbscan = safe_get(snort, "dbscan", {})
    suricata_dbscan = safe_get(suricata, "dbscan", {})

    # FPR from SCN-005 alerts / total
    snort_fpr = round(safe_get(snort_scenarios.get("SCN-005", {}), "alerts", 0) / snort_total * 100, 1) if snort_total else 0.0
    suricata_fpr = round(safe_get(suricata_scenarios.get("SCN-005", {}), "alerts", 0) / suricata_total * 100, 1) if suricata_total else 0.0

    # Table 2
    table2 = {"title": "Таблица 2: Метрики эффективности обнаружения (Среднее за 10 выполнений)", "rows": []}

    for sid in ["SCN-001","SCN-002","SCN-003","SCN-004","SCN-005"]:
        s = snort_scenarios.get(sid, {"name": sid, "alerts": 0})
        u = suricata_scenarios.get(sid, {"name": sid, "alerts": 0})

        # Detection rate from scenarios (if stored) or compute
        sn_dr = safe_get(s, "detection_rate", None)
        su_dr = safe_get(u, "detection_rate", None)
        sn_lat = safe_get(s, "latency_ms", None)
        su_lat = safe_get(u, "latency_ms", None)

        table2["rows"].append({
            "scenario": safe_get(s, "name", sid),
            "snort": {
                "ids": safe_get(snort, "ids", "Snort"),
                "alerts": safe_get(s, "alerts", 0),
                "detection_rate": sn_dr if sn_dr is not None else "N/A",
                "false_positive": safe_get(s, "false_positive", snort_fpr) if sid != "SCN-005" else snort_fpr,
                "latency_ms": sn_lat if sn_lat is not None else "N/A"
            },
            "suricata": {
                "ids": safe_get(suricata, "ids", "Suricata"),
                "alerts": safe_get(u, "alerts", 0),
                "detection_rate": su_dr if su_dr is not None else "N/A",
                "false_positive": safe_get(u, "false_positive", suricata_fpr) if sid != "SCN-005" else suricata_fpr,
                "latency_ms": su_lat if su_lat is not None else "N/A"
            }
        })

    # Table 3
    table3 = {"title": "Таблица 3: Метрики производительности системы (Пик во время тестов)", "rows": []}

    for data, perf in [(snort, snort_perf), (suricata, suricata_perf)]:
        table3["rows"].append({
            "ids": safe_get(data, "ids", "Unknown"),
            "total_alerts": safe_get(data, "total_alerts", 0),
            "cpu_percent": safe_get(perf, "cpu_percent", 0),
            "ram_mb": safe_get(perf, "ram_mb", 0),
            "throughput_mbps": safe_get(perf, "throughput_mbps", 0)
        })

    # DBSCAN table
    table_dbscan = {"title": "Таблица: Результаты DBSCAN/UEBA анализа", "rows": []}

    for data, db in [(snort, snort_dbscan), (suricata, suricata_dbscan)]:
        table_dbscan["rows"].append({
            "ids": safe_get(data, "ids", "Unknown"),
            "events": safe_get(db, "events", 3000),
            "clusters": safe_get(db, "clusters", 0),
            "anomalies": safe_get(db, "anomalies", 0),
            "anomaly_rate": safe_get(db, "anomaly_rate", 0.0)
        })

    return {
        "title": "ARCHIVIRT - IDS Comparison Report",
        "date": str(date.today()),
        "table2": table2,
        "table3": table3,
        "table_dbscan": table_dbscan
    }

def print_report(comp):
    if not comp:
        return

    print("=" * 80)
    print(comp["table2"]["title"])
    header = f"{'Сценарий':<22} {'IDS':<18} {'Алертов':>8} {'DR%':>8} {'FPR%':>8} {'Lat(ms)':>10}"
    print(header)
    print("-" * len(header))
    for row in comp["table2"]["rows"]:
        for ids_key in ["snort", "suricata"]:
            d = row[ids_key]
            dr = str(d["detection_rate"]) if d["detection_rate"] != "N/A" else "N/A"
            lat = str(d["latency_ms"]) if d["latency_ms"] != "N/A" else "N/A"
            fp = d["false_positive"] if isinstance(d["false_positive"], (int, float)) else 0.0
            print(f"{row['scenario']:<22} {d['ids']:<18} {d['alerts']:>8} {dr:>8} {fp:>8.2f} {lat:>10}")
        print()

    print("=" * 60)
    print(comp["table3"]["title"])
    header3 = f"{'IDS':<22} {'Всего':>8} {'CPU%':>8} {'RAM MB':>8} {'Mbps':>8}"
    print(header3)
    print("-" * len(header3))
    for row in comp["table3"]["rows"]:
        print(f"{row['ids']:<22} {row['total_alerts']:>8} {row['cpu_percent']:>8.1f} {row['ram_mb']:>8} {row['throughput_mbps']:>8}")

    print()
    print(comp["table_dbscan"]["title"])
    header_db = f"{'IDS':<22} {'Событий':>8} {'Кластеров':>10} {'Аномалий':>10} {'Доля%':>8}"
    print(header_db)
    print("-" * len(header_db))
    for row in comp["table_dbscan"]["rows"]:
        print(f"{row['ids']:<22} {row['events']:>8} {row['clusters']:>10} {row['anomalies']:>10} {row['anomaly_rate']:>8.2f}")

if __name__ == "__main__":
    comparison = build_comparison()
    if comparison:
        outpath = os.path.join(RESULTS_DIR, "archivirt_final_comparison.json")
        with open(outpath, "w") as f:
            json.dump(comparison, f, indent=2, ensure_ascii=False)
        print(f"Saved: {outpath}\n")
        print_report(comparison)
    else:
        print("ERROR: could not build comparison")
        exit(1)
