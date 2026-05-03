#!/usr/bin/env python3
"""
ARCHIVIRT - DBSCAN/UEBA Anomaly Detection
Author: Yasnemanegre SAWADOGO (SPbGUPTD)
Clusters IDS alerts using DBSCAN for behavioral analytics
"""
import json, re, sys
from datetime import datetime
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

def parse_snort(filepath):
    events = []
    try:
        with open(filepath) as f:
            for line in f:
                m = re.match(r'(\d+/\d+-\d+:\d+:\d+\.\d+).*?"(.*?)".*?\{(\w+)\}\s+(\S+)\s+->\s+(\S+)', line)
                if m:
                    ts_str, msg, proto, src, dst = m.groups()
                    try:
                        ts = datetime.strptime(ts_str, '%m/%d-%H:%M:%S.%f')
                        dst_port = int(dst.split(':')[1]) if ':' in dst else 0
                        events.append({
                            'ts': ts.timestamp() % 3600,
                            'src_last': int(src.split(':')[0].split('.')[-1]),
                            'dst_port': dst_port,
                            'proto': 1 if proto=='TCP' else 2 if proto=='UDP' else 3,
                            'msg': msg
                        })
                    except: pass
    except FileNotFoundError:
        print(f"File not found: {filepath}")
    return events

def parse_suricata(filepath):
    events = []
    try:
        with open(filepath) as f:
            for line in f:
                try:
                    d = json.loads(line)
                    if d.get('event_type') == 'alert':
                        ts = datetime.fromisoformat(d['timestamp'].replace('+0000','+00:00'))
                        events.append({
                            'ts': ts.timestamp() % 3600,
                            'src_last': int(d.get('src_ip','0').split('.')[-1]),
                            'dst_port': d.get('dest_port', 0),
                            'proto': 1 if d.get('proto')=='TCP' else 2,
                            'msg': d['alert']['signature']
                        })
                except: pass
    except FileNotFoundError:
        print(f"File not found: {filepath}")
    return events

def run_dbscan(events, name):
    print(f"\n{'='*60}")
    print(f"DBSCAN — {name} ({len(events)} events)")
    print('='*60)
    if len(events) < 5:
        print("Insufficient data (min 5 events)")
        return None
    X = np.array([[e['ts'], e['src_last'], e['dst_port'], e['proto']] for e in events])
    X_scaled = StandardScaler().fit_transform(X)
    db = DBSCAN(eps=0.5, min_samples=5).fit(X_scaled)
    labels = db.labels_
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise = list(labels).count(-1)
    print(f"Clusters: {n_clusters} | Anomalies: {n_noise} | Rate: {n_noise/len(events)*100:.1f}%")
    for cid in sorted(set(labels)):
        evs = [events[i] for i,l in enumerate(labels) if l==cid]
        msgs = list(set([e['msg'] for e in evs]))[:2]
        label = "ANOMALY" if cid==-1 else f"Cluster {cid}"
        print(f"  [{label}] {len(evs)} events: {msgs}")
    return {'ids': name, 'total': len(events), 'clusters': n_clusters,
            'anomalies': n_noise, 'anomaly_rate': round(n_noise/len(events)*100,2)}

print(f"ARCHIVIRT DBSCAN/UEBA — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

results = []
r1 = run_dbscan(parse_snort('/tmp/snort3_alerts.txt'), 'Snort 3')
r2 = run_dbscan(parse_suricata('/tmp/suricata_eve.json'), 'Suricata 6')
for r in [r1, r2]:
    if r: results.append(r)

with open('/tmp/dbscan_results.json', 'w') as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved: /tmp/dbscan_results.json")
