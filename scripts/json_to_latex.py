#!/usr/bin/env python3
"""
ARCHIVIRT - JSON to LaTeX table converter (Russian article)
Author: Yasnemanegre SAWADOGO (SPbGUPTD)
Input: results/archivirt_final_comparison.json
Output: LaTeX code printed to stdout
"""
import json, os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
with open(os.path.join(BASE, "archivirt_final_comparison.json")) as f:
    data = json.load(f)

def escape(s):
    return str(s).replace("_", "\\_").replace("%", "\\%")

# Table 2
print("% " + data["table2"]["title"])
print("\\begin{table}[h]")
print("\\centering")
print("\\caption{" + data["table2"]["title"] + "}")
print("\\begin{tabular}{|l|l|r|r|r|r|}")  # 6 columns
print("\\hline")
print("Сценарий & IDS & Алертов & DR,\\% & FPR,\\% & Задержка, мс \\\\")
print("\\hline")
for row in data["table2"]["rows"]:
    for key in ["snort", "suricata"]:
        d = row[key]
        dr = d["detection_rate"] if isinstance(d["detection_rate"], (int, float)) else "N/A"
        lat = d["latency_ms"] if isinstance(d["latency_ms"], (int, float)) else "N/A"
        fp = d["false_positive"] if isinstance(d["false_positive"], (int, float)) else "N/A"
        print(f"{escape(row['scenario'])} & {escape(d['ids'])} & {d['alerts']} & {dr} & {fp} & {lat} \\\\")
    print("\\hline")
print("\\end{tabular}")
print("\\end{table}")
print()

# Table 3
print("% " + data["table3"]["title"])
print("\\begin{table}[h]")
print("\\centering")
print("\\caption{" + data["table3"]["title"] + "}")
print("\\begin{tabular}{|l|r|r|r|r|}")
print("\\hline")
print("IDS & Всего алертов & CPU,\\% & RAM, МБ & Мбит/с \\\\")
print("\\hline")
for row in data["table3"]["rows"]:
    print(f"{escape(row['ids'])} & {row['total_alerts']} & {row['cpu_percent']} & {row['ram_mb']} & {row['throughput_mbps']} \\\\")
print("\\hline")
print("\\end{tabular}")
print("\\end{table}")
print()

# Table DBSCAN
print("% " + data["table_dbscan"]["title"])
print("\\begin{table}[h]")
print("\\centering")
print("\\caption{" + data["table_dbscan"]["title"] + "}")
print("\\begin{tabular}{|l|r|r|r|r|}")
print("\\hline")
print("IDS & Событий & Кластеров & Аномалий & Доля,\\% \\\\")
print("\\hline")
for row in data["table_dbscan"]["rows"]:
    print(f"{escape(row['ids'])} & {row['events']} & {row['clusters']} & {row['anomalies']} & {row['anomaly_rate']} \\\\")
print("\\hline")
print("\\end{tabular}")
print("\\end{table}")
