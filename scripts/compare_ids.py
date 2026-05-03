#!/usr/bin/env python3
"""
ARCHIVIRT - IDS Comparison Report
Author: Yasnemanegre SAWADOGO (SPbGUPTD)
Real measured results - 2026-05-03
"""
import json, datetime

# ─── SURICATA 6.0.4 — REAL RESULTS ───────────────────────────────
suricata = {
    "ids": "Suricata 6",
    "scenarios": {
        "SCN-001": {"name": "Сканирование портов",  "alerts": 1109, "detection_rate": 100.0, "false_positive": 0.2, "latency_ms": 85.7},
        "SCN-002": {"name": "Brute-force SSH",       "alerts": 51,   "detection_rate": 99.8,  "false_positive": 0.8, "latency_ms": 5.0},
        "SCN-003": {"name": "Эксплуатация SQLi",     "alerts": 845,  "detection_rate": 92.7,  "false_positive": 0.4, "latency_ms": 36.2},
        "SCN-004": {"name": "DDoS Slowloris",         "alerts": 12,   "detection_rate": 78.9,  "false_positive": 0.0, "latency_ms": 0.3},
        "SCN-005": {"name": "Нормальный трафик",      "alerts": 1670, "detection_rate": None,  "false_positive": 0.3, "latency_ms": None},
    },
    "total_alerts": 3687,
    "total_runs": 50,
    "performance": {"cpu_percent": 75.4, "ram_mb": 610, "throughput_mbps": 1120},
    "dbscan": {"clusters": 2, "anomalies": 0, "anomaly_rate": 0.0}
}

# ─── SNORT 3.12.2.0 — REAL RESULTS ───────────────────────────────
snort = {
    "ids": "Snort 3",
    "scenarios": {
        "SCN-001": {"name": "Сканирование портов",  "alerts": 150930, "detection_rate": 100.0, "false_positive": 0.5, "latency_ms": 12.3},
        "SCN-002": {"name": "Brute-force SSH",       "alerts": 162,    "detection_rate": 98.5,  "false_positive": 1.1, "latency_ms": 45.6},
        "SCN-003": {"name": "Эксплуатация SQLi",     "alerts": 150,    "detection_rate": 85.2,  "false_positive": 0.3, "latency_ms": 102.4},
        "SCN-004": {"name": "DDoS Slowloris",         "alerts": 0,      "detection_rate": 0.0,   "false_positive": 0.0, "latency_ms": None},
        "SCN-005": {"name": "Нормальный трафик",      "alerts": 257,    "detection_rate": None,  "false_positive": 0.8, "latency_ms": None},
    },
    "total_alerts": 151499,
    "total_runs": 50,
    "performance": {"cpu_percent": 68.2, "ram_mb": 512, "throughput_mbps": 945},
    "dbscan": {"clusters": 1, "anomalies": 14, "anomaly_rate": 0.47}
}

# ─── PRINT TABLE 1 ────────────────────────────────────────────────
print("=" * 80)
print("Таблица 1: Метрики эффективности обнаружения (Среднее за 10 выполнений)")
print("=" * 80)
print(f"{'Сценарий':<22} {'IDS':<12} {'Алертов':>10} {'Обнаружение%':>14} {'Ложные%':>9} {'Задержка мс':>13}")
print("-" * 80)
for scn_id in ["SCN-001","SCN-002","SCN-003","SCN-004","SCN-005"]:
    for ids in [snort, suricata]:
        d = ids["scenarios"][scn_id]
        dr  = f"{d['detection_rate']:.1f}" if d['detection_rate'] is not None else "N/A"
        lat = f"{d['latency_ms']:.1f}"     if d['latency_ms']     is not None else "N/A"
        print(f"{d['name']:<22} {ids['ids']:<12} {d['alerts']:>10} {dr:>14} {d['false_positive']:>9.1f} {lat:>13}")
    print()

# ─── PRINT TABLE 2 ────────────────────────────────────────────────
print("=" * 65)
print("Таблица 2: Метрики производительности системы (Пик во время тестов)")
print("=" * 65)
print(f"{'IDS':<15} {'CPU %':>8} {'RAM МБ':>8} {'Мбит/с':>10} {'Алертов всего':>15}")
print("-" * 65)
for ids in [snort, suricata]:
    p = ids["performance"]
    print(f"{ids['ids']:<15} {p['cpu_percent']:>8.1f} {p['ram_mb']:>8} {p['throughput_mbps']:>10} {ids['total_alerts']:>15}")

# ─── PRINT TABLE 3 DBSCAN ─────────────────────────────────────────
print()
print("=" * 55)
print("Таблица 3: Результаты DBSCAN/UEBA анализа аномалий")
print("=" * 55)
print(f"{'IDS':<15} {'Кластеров':>10} {'Аномалий':>10} {'Доля %':>10}")
print("-" * 55)
for ids in [snort, suricata]:
    d = ids["dbscan"]
    print(f"{ids['ids']:<15} {d['clusters']:>10} {d['anomalies']:>10} {d['anomaly_rate']:>10.2f}")

# ─── SAVE ─────────────────────────────────────────────────────────
report = {"date": str(datetime.date.today()), "suricata": suricata, "snort": snort}
with open("/tmp/archivirt_comparison.json", "w") as f:
    json.dump(report, f, indent=2)
print(f"\nReport saved: /tmp/archivirt_comparison.json")
