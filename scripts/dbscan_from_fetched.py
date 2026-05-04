#!/usr/bin/env python3
"""
ARCHIVIRT - DBSCAN analysis from fetched raw logs (per IDS)
Author: Yasnemanegre SAWADOGO (SPbGUPTD)
Input: /tmp/snort3_SCN-*_alerts.json and /tmp/suricata_SCN-*_eve.json
Output: results/dbscan_latest.json (separate results for Snort and Suricata)
"""
import json, glob, random, numpy as np, os
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from datetime import datetime

MAX_EVENTS = 3000
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")

def parse_snort(line):
    d = json.loads(line)
    src = d.get('src_ap','0:0').split(':')
    dst = d.get('dst_ap','0:0').split(':')
    rule = d.get('rule','0:0:0').split(':')
    return [
        len(events_snort) % 3600,
        int(src[0].split('.')[-1]) if src[0] else 0,
        int(dst[1]) if len(dst)>1 and dst[1].isdigit() else 0,
        1 if d.get('proto')=='TCP' else 3,
        int(rule[1]) if len(rule)>1 and rule[1].isdigit() else 0
    ]

def parse_suricata(line):
    d = json.loads(line)
    if d.get('event_type') != 'alert':
        return None
    return [
        len(events_suricata) % 3600,
        int(d.get('src_ip','0').split('.')[-1]),
        d.get('dest_port', 0),
        1 if d.get('proto')=='TCP' else 2,
        d['alert'].get('signature_id', 0)
    ]

def run_dbscan(events, name):
    print(f"[DBSCAN] {name}: {len(events)} events before sampling")
    if len(events) == 0:
        return {"clusters": 0, "anomalies": 0, "anomaly_rate": 0.0}
    if len(events) > MAX_EVENTS:
        events = random.sample(events, MAX_EVENTS)
        print(f"  Sampled to {MAX_EVENTS}")
    X = np.array(events)
    X_scaled = StandardScaler().fit_transform(X)
    db = DBSCAN(eps=0.5, min_samples=5).fit(X_scaled)
    labels = db.labels_
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise = list(labels).count(-1)
    rate = round(n_noise / len(events) * 100, 2) if len(events) > 0 else 0.0
    print(f"  Clusters: {n_clusters}, Anomalies: {n_noise}, Rate: {rate}%")
    return {"clusters": n_clusters, "anomalies": n_noise, "anomaly_rate": rate}

# Snort
events_snort = []
for f in sorted(glob.glob('/tmp/snort3_SCN-*_alerts.json')):
    with open(f) as fh:
        for line in fh:
            try:
                feat = parse_snort(line)
                events_snort.append(feat)
            except:
                pass
snort_result = run_dbscan(events_snort, "Snort")

# Suricata
events_suricata = []
for f in sorted(glob.glob('/tmp/suricata_SCN-*_eve.json')):
    with open(f) as fh:
        for line in fh:
            try:
                feat = parse_suricata(line)
                if feat:
                    events_suricata.append(feat)
            except:
                pass
suricata_result = run_dbscan(events_suricata, "Suricata")

output = {
    "date": datetime.now().isoformat(),
    "snort_dbscan": snort_result,
    "suricata_dbscan": suricata_result
}

os.makedirs(RESULTS_DIR, exist_ok=True)
outpath = os.path.join(RESULTS_DIR, "dbscan_latest.json")
with open(outpath, "w") as f:
    json.dump(output, f, indent=2)
print(f"Saved: {outpath}")
