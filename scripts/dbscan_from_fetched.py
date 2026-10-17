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

def parse_snort_fastlog(line):
    # fast.log format: 05/10-09:20:40.962754 [**] [1:sid:rev] "msg" ...
    m = re.match(r'(\d+/\d+-\d+:\d+:\d+\.\d+).*\[(\d+):(\d+):(\d+)\].*{(\w+)}\s+(\S+)\s*->\s*(\S+)', line)
    if not m:
        return None
    ts_str, gid, sid, rev, proto, src, dst = m.groups()
    try:
        from datetime import datetime
        dt = datetime.strptime(ts_str, "%m/%d-%H:%M:%S.%f").replace(year=2026)
        ts = dt.timestamp()
    except:
        ts = 0.0
    src_port = int(src.split(":")[-1]) if ":" in src else 0
    dst_port = int(dst.split(":")[-1]) if ":" in dst else 0
    return [ts % 3600, src_port / 65535, dst_port / 65535, int(sid) % 1000 / 1000]

def parse_snort_fastlog(line):
    import re as _re
    m = _re.match(r"(\d+/\d+-\d+:\d+:\d+\.\d+).*\[(\d+):(\d+):(\d+)\].*{(\w+)}\s+(\S+)\s*->\s*(\S+)", line)
    if not m:
        return None
    ts_str, gid, sid, rev, proto, src, dst = m.groups()
    try:
        from datetime import datetime
        dt = datetime.strptime(ts_str, "%m/%d-%H:%M:%S.%f").replace(year=2026)
        ts = dt.timestamp()
    except:
        ts = 0.0
    src_port = int(src.split(":")[-1]) if ":" in src else 0
    dst_port = int(dst.split(":")[-1]) if ":" in dst else 0
    return [ts % 3600, src_port / 65535, dst_port / 65535, int(sid) % 1000 / 1000]

def parse_snort(line):
    import json
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
    raw_count = len(events)
    print(f"[DBSCAN] {name}: {raw_count} events before sampling")
    if raw_count == 0:
        return {"events": 0, "clusters": 0, "anomalies": 0, "anomaly_rate": 0.0}
    if raw_count > MAX_EVENTS:
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
    return {"events": raw_count, "clusters": n_clusters, "anomalies": n_noise, "anomaly_rate": rate}

# Snort
import re as _re
events_snort = []
# Try fast.log first (Snort 3 default output)
fastlogs = sorted(glob.glob('/tmp/snort3_SCN-*_fast.log'))
jsonlogs = sorted(glob.glob('/tmp/snort3_SCN-*_alerts.json'))
snort_files = fastlogs if fastlogs else jsonlogs
is_fastlog = bool(fastlogs)
for f in snort_files:
    with open(f) as fh:
        for line in fh:
            try:
                feat = parse_snort_fastlog(line) if is_fastlog else parse_snort(line)
                if feat:
                    events_snort.append(feat)
            except:
                pass
snort_result = run_dbscan(events_snort, "Snort")

# Suricata
events_suricata = []
for f in sorted(glob.glob('/tmp/suricata_SCN-*_alerts.json')):
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
