#!/usr/bin/env python3
"""ARCHIVIRT mission — 1 Hz SSH metrics sampler (read-only on the VMs). Runs until <stopfile> exists.
Usage: sampler.py <out.jsonl> <stopfile> <ssh_known_hosts_for_monitor>
Each sample: ts, per-metric value and status (MEASURED | MISSING | ERROR); never a default 0."""
import json, os, subprocess, sys, time

out, stopf, kh = sys.argv[1:4]
CP = "-o ControlMaster=auto -o ControlPersist=120 -o ControlPath=/tmp/archivirt-cm-%h"
MON = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={kh} {CP} ubuntu@10.0.3.10"
T03 = f"ssh -o BatchMode=yes {CP} ubuntu@10.0.2.13"
MON_CMD = ("awk '/^MemAvailable:/{print \"mem_kb=\"$2}' /proc/meminfo; head -1 /proc/stat | awk '{print \"cpu=\"$2\",\"$3\",\"$4\",\"$5\",\"$6\",\"$7\",\"$8\",\"$9}'; "
           "for i in ens4 ens5 ens6 ens7; do echo \"${i}_rx=$(cat /sys/class/net/$i/statistics/rx_bytes) ${i}_drop=$(cat /sys/class/net/$i/statistics/rx_dropped)\"; done | tr ' ' '\\n'; "
           "if [ -r /proc/net/netfilter/nfnetlink_queue ] || sudo -n test -e /proc/net/netfilter/nfnetlink_queue; then sudo -n cat /proc/net/netfilter/nfnetlink_queue | awk '$1==0{print \"nfq_qdrop=\"$6; print \"nfq_udrop=\"$7}'; else echo nfq=NA; fi")
T03_CMD = "awk '/^MemAvailable:/{print \"mem_kb=\"$2}' /proc/meminfo"

def run(cmd, remote):
    try:
        r = subprocess.run(cmd.split() + [remote], capture_output=True, text=True, timeout=4)
        if r.returncode != 0: return None
        return dict(l.split("=", 1) for l in r.stdout.split() if "=" in l)
    except Exception:
        return None

def host_mem():
    try:
        for l in open("/proc/meminfo"):
            if l.startswith("MemAvailable:"): return int(l.split()[1]) // 1024
    except Exception:
        return None

with open(out, "a") as f:
    while not os.path.exists(stopf):
        t0 = time.time(); s = {"ts": round(t0, 3), "v": {}, "st": {}}
        m = run(MON, MON_CMD)
        if m is None:
            for k in ("monitor_mem_avail_mib", "monitor_cpu", "ens4_rx", "ens5_rx", "ens6_drop", "ens7_drop"): s["st"][k] = "ERROR"
        else:
            def put(k, src, conv=int):
                if src in m:
                    try: s["v"][k] = conv(m[src]); s["st"][k] = "MEASURED"
                    except ValueError: s["st"][k] = "ERROR"
                else: s["st"][k] = "MISSING"
            put("monitor_mem_avail_mib", "mem_kb", lambda x: int(x) // 1024)
            put("monitor_cpu", "cpu", lambda x: [int(y) for y in x.split(",")])
            for i in ("ens4", "ens5", "ens6", "ens7"):
                put(f"{i}_rx", f"{i}_rx"); put(f"{i}_drop", f"{i}_drop")
            if m.get("nfq") == "NA":
                s["st"]["nfq_qdrop"] = s["st"]["nfq_udrop"] = "NOT_APPLICABLE"
            else:
                put("nfq_qdrop", "nfq_qdrop"); put("nfq_udrop", "nfq_udrop")
        t = run(T03, T03_CMD)
        if t is None or "mem_kb" not in t: s["st"]["target03_mem_avail_mib"] = "ERROR" if t is None else "MISSING"
        else: s["v"]["target03_mem_avail_mib"] = int(t["mem_kb"]) // 1024; s["st"]["target03_mem_avail_mib"] = "MEASURED"
        h = host_mem()
        if h is None: s["st"]["host_mem_avail_mib"] = "ERROR"
        else: s["v"]["host_mem_avail_mib"] = h; s["st"]["host_mem_avail_mib"] = "MEASURED"
        f.write(json.dumps(s) + "\n"); f.flush()
        time.sleep(max(0, 1 - (time.time() - t0)))
