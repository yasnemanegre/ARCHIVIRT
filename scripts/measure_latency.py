#!/usr/bin/env python3
"""
ARCHIVIRT - Latency Measurement Script
Author: Yasnemanegre SAWADOGO (SPbGUPTD)
Measures detection latency from eve.json timestamps
"""
import json
import sys
from datetime import datetime

def measure_latency(eve_json_path, scenario_signature):
    """Calculate average detection latency from Suricata eve.json"""
    latencies = []
    
    try:
        with open(eve_json_path, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('event_type') == 'alert':
                        sig = event['alert']['signature']
                        if scenario_signature in sig:
                            ts = event['timestamp']
                            # Parse timestamp
                            dt = datetime.fromisoformat(ts.replace('+0000', '+00:00'))
                            latencies.append(dt)
                except:
                    pass
    except FileNotFoundError:
        print(f"File not found: {eve_json_path}")
        return None
    
    if len(latencies) < 2:
        return None
    
    # Calculate intervals between alerts (ms)
    intervals = []
    for i in range(1, len(latencies)):
        delta = (latencies[i] - latencies[i-1]).total_seconds() * 1000
        if 0 < delta < 5000:  # Filter outliers
            intervals.append(delta)
    
    if intervals:
        avg = sum(intervals) / len(intervals)
        return round(avg, 1)
    return None

# Signatures per scenario
signatures = {
    "SCN-001": "TCP SYN Scan",
    "SCN-002": "SSH Connection",
    "SCN-003": "HTTP Connection",
    "SCN-004": "Slowloris",
}

print("=== ARCHIVIRT Latency Measurement ===")
eve_path = "/var/log/suricata/eve.json"

for scn, sig in signatures.items():
    lat = measure_latency(eve_path, sig)
    if lat:
        print(f"{scn}: avg latency = {lat:.1f} ms")
    else:
        print(f"{scn}: insufficient data")
