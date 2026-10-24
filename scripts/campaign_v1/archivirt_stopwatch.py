#!/usr/bin/env python3
"""ARCHIVIRT — stop-criteria recorder v2 (PROPOSAL C1.3). Read-only on the lab.

Every interval: host metrics from /proc; remote metrics from --remote-cmd (prints KEY=<int>|NA|ERR);
per metric a status MEASURED|MISSING|NOT_APPLICABLE|ERROR (mode-aware from --params).
Criteria flagged "immediate" are evaluated live: on confirmation an ABORT file (JSON) is written
atomically; recording continues until SIGTERM. Always writes a final {"end": true} record.
Usage: archivirt_stopwatch.py --out F --run-id ID --mode M --params P [--remote-cmd C] [--abort-file A] [--proc D]
"""
import argparse, datetime, json, os, signal, subprocess, sys, time
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p2_stopcriteria import load_params, applicable, CriterionState

REMOTE = ("monitor_mem_available_mib", "target03_mem_available_mib", "ens6_rx_dropped", "ens7_rx_dropped",
          "nfq_queue_dropped", "nfq_user_dropped")

def read_host(proc):
    v, st = {}, {}
    try:
        mi = {l.split(":")[0]: int(l.split()[1]) for l in open(os.path.join(proc, "meminfo"))}
        v["host_mem_available_mib"] = mi["MemAvailable"] // 1024
        v["host_swap_used_mib"] = (mi["SwapTotal"] - mi["SwapFree"]) // 1024
    except Exception:
        st["host_mem_available_mib"] = st["host_swap_used_mib"] = "ERROR"
    try:
        vm = {l.split()[0]: int(l.split()[1]) for l in open(os.path.join(proc, "vmstat"))}
        v["_pswpin"], v["_oom"] = vm["pswpin"], vm["oom_kill"]
    except Exception:
        st["host_swapin_pages_per_s"] = st["host_oom_kill_delta"] = "ERROR"
    try:
        full = [l for l in open(os.path.join(proc, "pressure", "memory")) if l.startswith("full")][0].split()
        v["host_psi_full_avg10"] = float(full[1].split("=")[1]); v["host_psi_full_avg60"] = float(full[2].split("=")[1])
    except Exception:
        st["host_psi_full_avg10"] = st["host_psi_full_avg60"] = "ERROR"
    return v, st

def read_remote(cmd):
    raw, ok = {}, True
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=4)
        raw = dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)
        ok = r.returncode == 0
    except Exception:
        ok = False
    out = {}
    for k in REMOTE:
        t = raw.get(k, "ERR" if not ok else "MISSING").strip()
        out[k] = int(t) if t.lstrip("-").isdigit() else ("NA" if t == "NA" else ("MISSING" if t == "MISSING" else "ERR"))
    return out

def main():
    ap = argparse.ArgumentParser()
    for a in ("--out", "--run-id", "--mode", "--params"): ap.add_argument(a, required=True)
    ap.add_argument("--remote-cmd", default=""); ap.add_argument("--abort-file", default="")
    ap.add_argument("--proc", default="/proc"); ap.add_argument("--max-samples", type=int, default=0)
    ap.add_argument("--interval", type=float)
    a = ap.parse_args()
    params = load_params(open(a.params, "rb").read())
    interval = a.interval or params["interval_s"]
    gap = params["gap_policy"]["value"]
    live = {n: CriterionState(n, c, gap) for n, c in params["criteria"].items()
            if c.get("immediate") and applicable(params, c["metric"], a.mode)}
    stop = {"flag": False}
    for s in (signal.SIGTERM, signal.SIGINT): signal.signal(s, lambda *_: stop.update(flag=True))
    base, prev, seq, aborted = {}, None, 0, False
    with open(a.out, "a", buffering=1) as fh:
        while not stop["flag"]:
            t = time.time()
            hv, hs = read_host(a.proc)
            rv = read_remote(a.remote_cmd) if a.remote_cmd else {k: "MISSING" for k in REMOTE}
            values, status = {}, {}
            for m in params["metrics"]:
                if not applicable(params, m, a.mode):
                    status[m] = "NOT_APPLICABLE"; continue
                if m in hs:
                    status[m] = hs[m]; continue
                if m in hv:
                    values[m], status[m] = hv[m], "MEASURED"
                elif m == "host_swapin_pages_per_s":
                    if prev is None or "_pswpin" not in prev or "_pswpin" not in hv:
                        status[m] = "NOT_APPLICABLE" if prev is None else "MISSING"
                    else:
                        values[m] = round((hv["_pswpin"] - prev["_pswpin"]) / max(t - prev["_t"], 1e-3), 1); status[m] = "MEASURED"
                elif m == "host_oom_kill_delta":
                    if "_oom" in hv:
                        base.setdefault("oom", hv["_oom"]); values[m], status[m] = hv["_oom"] - base["oom"], "MEASURED"
                    else: status[m] = "ERROR"
                elif m in ("monitor_mem_available_mib", "target03_mem_available_mib"):
                    x = rv[m]
                    if isinstance(x, int): values[m], status[m] = x, "MEASURED"
                    else: status[m] = {"NA": "NOT_APPLICABLE", "ERR": "ERROR"}.get(x, "MISSING")
                elif m in ("capture_iface_drops_delta", "nfq_queue_dropped_delta"):
                    keys = ("ens6_rx_dropped", "ens7_rx_dropped") if m.startswith("capture") else ("nfq_queue_dropped", "nfq_user_dropped")
                    xs = [rv[k] for k in keys]
                    if all(isinstance(x, int) for x in xs):
                        tot = sum(xs); base.setdefault(m, tot); values[m], status[m] = tot - base[m], "MEASURED"
                    else:
                        status[m] = "ERROR" if "ERR" in xs else "MISSING"
                else:
                    status[m] = "MISSING"
            hv["_t"] = t
            rec = {"seq": seq, "ts_epoch": round(t, 3), "run_id": a.run_id, "mode": a.mode,
                   "ts_iso": datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat(),
                   "values": values, "status": status}
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
            for st in live.values():
                m = st.c["metric"]; st.feed(rec["ts_epoch"], status.get(m), values.get(m))
                if st.hit and not aborted and a.abort_file:
                    tmp = a.abort_file + ".tmp"
                    with open(tmp, "w") as f: json.dump({"abort": True, "criterion": st.hit, "run_id": a.run_id}, f)
                    os.replace(tmp, a.abort_file); aborted = True
            prev, seq = hv, seq + 1
            if a.max_samples and seq >= a.max_samples: break
            end = t + interval
            while not stop["flag"] and time.time() < end: time.sleep(0.1)
        fh.write(json.dumps({"end": True, "run_id": a.run_id, "samples": seq, "aborted": aborted,
                             "ts_epoch": round(time.time(), 3)}) + "\n")

if __name__ == "__main__":
    main()
