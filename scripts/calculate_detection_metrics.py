#!/usr/bin/env python3
"""
Calculate detection rate, latency, and false positive rate from raw alert logs and attack timestamps.
Reads: /tmp/<ids>_SCN-*_alerts.json, /tmp/attack_start_times_SCN-*.txt
Writes: results/detection_metrics_<ids>.json
"""
import json, os, sys, glob

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
TMP_DIR = "/tmp"

# Time window (seconds) after attack start to consider alerts as related to that attack
WINDOWS = {
    "SCN-001": 120,   # port scan
    "SCN-002": 120,   # SSH brute
    "SCN-003": 300,   # SQLi – sqlmap can take long
    "SCN-004": 120,   # DDoS
    "SCN-005": 120    # normal traffic
}

def load_alert_timestamps(alert_file):
    """Parse alert JSON file and return list of epoch timestamps."""
    timestamps = []
    try:
        with open(alert_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    ts = obj.get("timestamp", None)
                    if ts:
                        # Snort/Suricata JSON timestamp format: "2024-01-01T12:00:00.000000+0000"
                        # Convert to epoch. We'll assume ISO format.
                        import dateutil.parser
                        try:
                            dt = dateutil.parser.isoparse(ts)
                            epoch = dt.timestamp()
                            timestamps.append(epoch)
                        except:
                            pass
                except:
                    pass
    except FileNotFoundError:
        pass
    return sorted(timestamps)

def load_start_times(start_file):
    """Read list of epoch start times (one per line)."""
    if not os.path.exists(start_file):
        return []
    with open(start_file) as f:
        return [float(line.strip()) for line in f if line.strip()]

def compute_detection_rate_and_latency(timestamps, start_times, window):
    """Return detection_rate (%), latencies list in ms."""
    if not start_times:
        return 0.0, []
    detected_iters = 0
    latencies = []
    for start in start_times:
        # Find first alert after start within window
        first_alert = None
        for t in timestamps:
            if start <= t <= start + window:
                first_alert = t
                break
        if first_alert is not None:
            detected_iters += 1
            lat_ms = (first_alert - start) * 1000.0
            latencies.append(lat_ms)
    detection_rate = (detected_iters / len(start_times)) * 100.0
    return detection_rate, latencies

def compute_fpr(normal_alerts, total_alerts):
    if total_alerts == 0:
        return 0.0
    return (normal_alerts / total_alerts) * 100.0

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    for ids_prefix, ids_name in [("snort3", "Snort"), ("suricata", "Suricata")]:
        # Load total alerts per scenario from result files (or from assemble later)
        # But we need total alerts; we can compute from alert files count lines.
        total_alerts = 0
        normal_alerts = 0
        metrics = {}   # key: SCN-xxx, value: {detection_rate, latency_ms, false_positive}
        for sc in ["SCN-001", "SCN-002", "SCN-003", "SCN-004", "SCN-005"]:
            alert_file = os.path.join(TMP_DIR, f"{ids_prefix}_{sc}_alerts.json")
            start_file = os.path.join(TMP_DIR, f"attack_start_times_{sc}.txt")
            
            # Count alerts (lines)
            alerts_count = 0
            if os.path.exists(alert_file):
                with open(alert_file) as f:
                    alerts_count = sum(1 for line in f if line.strip())
            total_alerts += alerts_count
            if sc == "SCN-005":
                normal_alerts = alerts_count

            if sc == "SCN-005":
                # For normal traffic, no detection metrics
                metrics[sc] = {
                    "detection_rate": "N/A",
                    "latency_ms": "N/A",
                    "alerts": alerts_count
                }
                continue

            timestamps = load_alert_timestamps(alert_file)
            start_times = load_start_times(start_file)
            window = WINDOWS.get(sc, 120)
            dr, latencies = compute_detection_rate_and_latency(timestamps, start_times, window)
            avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
            metrics[sc] = {
                "detection_rate": round(dr, 1),
                "latency_ms": round(avg_latency, 1),
                "alerts": alerts_count
            }

        # False positive rate across all scenarios
        fpr = compute_fpr(normal_alerts, total_alerts)
        for sc in metrics:
            metrics[sc]["false_positive"] = round(fpr, 2)

        outpath = os.path.join(RESULTS_DIR, f"detection_metrics_{ids_prefix}.json")
        with open(outpath, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"Wrote {outpath}")

if __name__ == "__main__":
    main()
