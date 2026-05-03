#!/usr/bin/env python3
"""
ARCHIVIRT - DBSCAN/UEBA Anomaly Detection
Author: Yasnemanegre SAWADOGO (SPbGUPTD)
Paths: /tmp/snort3_alerts.json, /tmp/suricata_eve.json
"""
import json, random
from datetime import datetime
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

MAX_EVENTS = 3000

def parse_snort(filepath):
    events = []
    try:
        with open(filepath) as f:
            for line in f:
                try:
                    d = json.loads(line)
                    src = d.get('src_ap','0:0').split(':')
                    dst = d.get('dst_ap','0:0').split(':')
                    rule = d.get('rule','0:0:0').split(':')
                    events.append([
                        len(events) % 3600,
                        int(src[0].split('.')[-1]) if src[0] else 0,
                        int(dst[1]) if len(dst)>1 and dst[1].isdigit() else 0,
                        1 if d.get('proto')=='TCP' else 3,
                        int(rule[1]) if len(rule)>1 and rule[1].isdigit() else 0
                    ])
                except: pass
    except FileNotFoundError:
        print(f"Not found: {filepath}")
    return events

def parse_suricata(filepath):
    events = []
    try:
        with open(filepath) as f:
            for line in f:
                try:
                    d = json.loads(line)
                    if d.get('event_type') == 'alert':
                        events.append([
                            len(events) % 3600,
                            int(d.get('src_ip','0').split('.')[-1]),
                            d.get('dest_port', 0),
                            1 if d.get('proto')=='TCP' else 2,
                            d['alert'].get('signature_id', 0)
                        ])
                except: pass
    except FileNotFoundError:
        print(f"Not found: {filepath}")
    return events

def run_dbscan(events, name):
    print(f"\n{'='*50}\nDBSCAN — {name} ({len(events)} events)")
    if len(events) < 5:
        print("Insufficient data"); return None
    if len(events) > MAX_EVENTS:
        events = random.sample(events, MAX_EVENTS)
        print(f"Sampled to {MAX_EVENTS} events")
    X = np.array(events)
    X_scaled = StandardScaler().fit_transform(X)
    db = DBSCAN(eps=0.5, min_samples=5).fit(X_scaled)
    labels = db.labels_
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise = list(labels).count(-1)
    print(f"Clusters: {n_clusters} | Anomalies: {n_noise} | Rate: {n_noise/len(events)*100:.1f}%")
    return {'ids': name, 'total': len(events), 'clusters': n_clusters,
            'anomalies': n_noise, 'anomaly_rate': round(n_noise/len(events)*100,2)}

print(f"ARCHIVIRT DBSCAN — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
results = []
r1 = run_dbscan(parse_snort('/tmp/snort3_alerts.json'), 'Snort 3')
r2 = run_dbscan(parse_suricata('/tmp/suricata_eve.json'), 'Suricata 6')
for r in [r1,r2]:
    if r: results.append(r)
with open('/tmp/dbscan_results.json','w') as f:
    json.dump(results, f, indent=2)
print(f"\nSaved: /tmp/dbscan_results.json")
