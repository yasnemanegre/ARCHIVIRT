#!/usr/bin/env python3
"""ARCHIVIRT campaign_v1 — per-run performance from two monitor snapshots.

Computes, over the experiment window, the Suricata process CPU% and RSS, plus
the captured packet/byte/drop volume on the mirror interfaces (ens6+ens7).
Real measurements only: any counter that is missing or whose Suricata PID
changed between snapshots is reported as null with a reason (never a fake 0).

Usage: compute_perf.py perf_start.txt perf_end.txt > perf.json
"""
import json
import os
import sys
from pathlib import Path


def load(p):
    d = {}
    if Path(p).exists():
        for line in Path(p).read_text(errors="replace").splitlines():
            line = line.strip().replace("\r", "")
            if "=" in line:
                k, _, v = line.partition("=")
                d[k.strip()] = v.strip()
    return d


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def main():
    s, e = load(sys.argv[1]), load(sys.argv[2])
    notes = []

    ws, we = num(s.get("wall_ns")), num(e.get("wall_ns"))
    wall_s = (we - ws) / 1e9 if (ws is not None and we is not None and we > ws) else None
    if wall_s is None:
        notes.append("window_seconds=null: wall timestamps unusable")

    clk = num(s.get("clk_tck")) or 100.0

    # CPU% of the Suricata process (same PID across the window).
    cpu_percent = None
    pid_s, pid_e = s.get("suricata_pid"), e.get("suricata_pid")
    cj_s, cj_e = num(s.get("cpu_jiffies")), num(e.get("cpu_jiffies"))
    if pid_s in ("NONE", None) or pid_e in ("NONE", None):
        notes.append("cpu_percent=null: no Suricata process (expected in baseline mode)")
    elif pid_s != pid_e:
        notes.append("cpu_percent=null: Suricata PID changed during the window")
    elif cj_s is None or cj_e is None or wall_s is None:
        notes.append("cpu_percent=null: missing CPU jiffies")
    else:
        cpu_percent = round(((cj_e - cj_s) / clk) / wall_s * 100.0, 2)

    rss_kb = num(e.get("rss_kb"))
    rss_mb = round(rss_kb / 1024.0, 1) if rss_kb is not None else None
    if rss_mb is None:
        notes.append("rss_mb=null: no Suricata RSS (expected in baseline mode)")

    # Interface capture volume: interfaces the engine actually reads (ARCHIVIRT_CAPTURE_IFACES, comma list;
    # default ens6,ens7 = historical behaviour). With ens7 only, ens6 still receives its mirror copy.
    ifaces = [i.strip() for i in (os.environ.get("ARCHIVIRT_CAPTURE_IFACES") or "ens6,ens7").split(",") if i.strip()]
    def delta(key):
        a, b = num(s.get(key)), num(e.get(key))
        return (b - a) if (a is not None and b is not None and b >= a) else None

    pkts = [delta(f"{i}_rx_packets") for i in ifaces]
    byts = [delta(f"{i}_rx_bytes") for i in ifaces]
    drps = [delta(f"{i}_rx_dropped") for i in ifaces]

    tot_pkts = sum(x for x in pkts if x is not None) if any(x is not None for x in pkts) else None
    tot_byts = sum(x for x in byts if x is not None) if any(x is not None for x in byts) else None
    tot_drps = sum(x for x in drps if x is not None) if any(x is not None for x in drps) else None

    pps = round(tot_pkts / wall_s, 1) if (tot_pkts is not None and wall_s) else None
    mbps = round(tot_byts * 8 / 1e6 / wall_s, 4) if (tot_byts is not None and wall_s) else None

    print(json.dumps({
        "window_seconds": round(wall_s, 3) if wall_s else None,
        "cpu_percent": cpu_percent,
        "rss_mb": rss_mb,
        "captured_packets": tot_pkts,
        "captured_bytes": tot_byts,
        "captured_pps": pps,
        "captured_mbps": mbps,
        "captured_drops": tot_drps,
        "notes": notes,
    }, indent=2))


if __name__ == "__main__":
    main()
