#!/usr/bin/env python3
"""ARCHIVIRT mission — analysis of one validation experiment (offline, reads the run directory only).
Usage: analyze_experiment.py <run_dir> <engine> <mode> <run_id> <params.json>
Writes <run_dir>/experiment_result.json and <run_dir>/metrics.lp (InfluxDB line protocol); prints the result.
Rules: a missing value is MISSING (never 0); NOT_APPLICABLE is explicit per mode; any violated criterion
=> run_status INVALID with every reason listed."""
import json, os, re, statistics, sys

d, eng, mode, run_id, pfile = sys.argv[1:6]
P = json.load(open(pfile)); inv = P["invalidation"]; exp = P["expected"][mode]
reasons, metrics, status = [], {}, {}

def pct(vals, q):
    v = sorted(vals); return v[min(len(v) - 1, int(round(q * (len(v) - 1))))] if v else None

# ---- samples
S = [json.loads(l) for l in open(os.path.join(d, "samples.jsonl"))] if os.path.exists(os.path.join(d, "samples.jsonl")) else []
t0 = float(open(os.path.join(d, "load_start.txt")).read()); t1 = float(open(os.path.join(d, "load_end.txt")).read())
mandatory = ["monitor_mem_avail_mib", "monitor_cpu", "target03_mem_avail_mib", "host_mem_avail_mib"]
mandatory += ["ens6_drop", "ens7_drop"] if mode == "ids" else ["nfq_qdrop", "nfq_udrop"]
for k in mandatory:
    n = len(S); bad = sum(1 for s in S if s["st"].get(k) != "MEASURED")
    frac = (bad / n) if n else 1.0
    status[k] = {"samples": n, "not_measured": bad, "fraction": round(frac, 3)}
    if frac > inv["missing_sample_fraction_max"]:
        reasons.append("mandatory metric %s not measured in %.0f%% of samples" % (k, 100 * frac))

def series(k): return [(s["ts"], s["v"][k]) for s in S if s["st"].get(k) == "MEASURED"]
for k, lim, name in (("monitor_mem_avail_mib", inv["monitor_mem_available_min_mib"], "monitor"),
                     ("target03_mem_avail_mib", inv["target03_mem_available_min_mib"], "target-03"),
                     ("host_mem_avail_mib", inv["host_mem_available_min_mib"], "host")):
    v = [x for _, x in series(k)]
    metrics[k + "_min"] = min(v) if v else "MISSING"
    if v and min(v) < lim: reasons.append("%s MemAvailable %d MiB < %d" % (name, min(v), lim))

cpu = series("monitor_cpu"); cpct = []
for (ta, a), (tb, b) in zip(cpu, cpu[1:]):
    tot = sum(b) - sum(a); idle = (b[3] + b[4]) - (a[3] + a[4])
    if tot > 0: cpct.append((tb, 100.0 * (tot - idle) / tot))
win = [p for t, p in cpct if t0 <= t <= t1 + 1]
metrics["monitor_cpu_pct_avg"] = round(statistics.mean(win), 1) if win else "MISSING"
metrics["monitor_cpu_pct_max"] = round(max(win), 1) if win else "MISSING"
run_sat = best = 0
for p in win:
    run_sat = run_sat + 1 if p >= inv["monitor_cpu_saturation_pct"] else 0; best = max(best, run_sat)
if best >= inv["monitor_cpu_saturation_max_consecutive_s"]: reasons.append("monitor CPU >= %d%% for %d consecutive s" % (inv["monitor_cpu_saturation_pct"], best))

def delta(k):
    v = series(k)
    return (v[-1][1] - v[0][1]) if len(v) >= 2 else "MISSING"
if mode == "ids":
    for k in ("ens6_drop", "ens7_drop"):
        metrics[k + "_delta"] = delta(k)
        if metrics[k + "_delta"] != "MISSING" and metrics[k + "_delta"] > inv["capture_iface_drops_max"]: reasons.append("capture interface %s dropped %d packets" % (k[:4], metrics[k + "_delta"]))
    metrics["nfq_drops"] = "NOT_APPLICABLE"
else:
    for k in ("nfq_qdrop", "nfq_udrop"):
        metrics[k + "_delta"] = delta(k)
        if metrics[k + "_delta"] != "MISSING" and metrics[k + "_delta"] > inv["nfq_drops_max"]: reasons.append("NFQUEUE %s = %d" % (k, metrics[k + "_delta"]))
    metrics["capture_iface_drops"] = "NOT_APPLICABLE"

# forwarded volume through the monitor during the load window (ens5 = attack side, ens4 = target side)
def window_delta(k):
    v = [(t, x) for t, x in series(k) if t0 - 1.5 <= t <= t1 + 1.5]
    return (v[-1][1] - v[0][1], v[-1][0] - v[0][0]) if len(v) >= 2 else (None, None)
b5, dt5 = window_delta("ens5_rx"); b4, dt4 = window_delta("ens4_rx")
metrics["fwd_rx_mbit_s"] = round(8 * (b5 + b4) / dt5 / 1e6, 3) if b5 is not None and b4 is not None and dt5 else "MISSING"

# ---- load: latency and failures
L = [l.split() for l in open(os.path.join(d, "load.txt")) if len(l.split()) >= 5]
ok = [float(x[3]) * 1000 for x in L if x[2] == "200"]; fails = [x for x in L if x[2] != "200"]
metrics.update({"http_requests": len(L), "http_ok": len(ok), "http_failures": len(fails),
                "latency_ms_p50": round(pct(ok, .5), 2) if ok else "MISSING", "latency_ms_p95": round(pct(ok, .95), 2) if ok else "MISSING",
                "latency_ms_max": round(max(ok), 2) if ok else "MISSING",
                "goodput_mbit_s": round(8 * sum(int(x[4]) for x in L if x[2] == "200") / (t1 - t0) / 1e6, 3),
                "load_duration_s": round(t1 - t0, 2)})
if len(L) != P["load"]["http_requests"]: reasons.append("load incomplete: %d/%d requests" % (len(L), P["load"]["http_requests"]))
if len(fails) > inv["legit_http_failure_max"]: reasons.append("%d legitimate HTTP requests failed" % len(fails))

# ---- engine counters
if eng == "suricata":
    last = {}
    sp = os.path.join(d, "logs", "stats.log")
    for line in open(sp) if os.path.exists(sp) else []:
        m = re.match(r"^(\S+)\s+\|\s+Total\s+\|\s+(\d+)", line)
        if m: last[m.group(1)] = int(m.group(2))
    if mode == "ids":
        metrics["engine_kernel_packets"] = last.get("capture.kernel_packets", "MISSING")
        metrics["engine_kernel_drops"] = last.get("capture.kernel_drops", "MISSING")
        if metrics["engine_kernel_drops"] == "MISSING": reasons.append("engine capture.kernel_drops MISSING")
        elif metrics["engine_kernel_drops"] > inv["engine_kernel_drops_max"]: reasons.append("engine kernel drops %d" % metrics["engine_kernel_drops"])
    else:
        metrics["engine_kernel_drops"] = "NOT_APPLICABLE"
        metrics["ips_accepted"] = last.get("ips.accepted", "MISSING"); metrics["ips_blocked"] = last.get("ips.blocked", "MISSING")
else:
    eo = open(os.path.join(d, "logs", "engine.out"), errors="replace").read()
    daq = eo.split("Packet Statistics", 1)[-1].split("Module Statistics", 1)[0]
    g = lambda k: (int(re.search(r"^\s+%s:\s+(\d+)" % k, daq, re.M).group(1)) if re.search(r"^\s+%s:\s+(\d+)" % k, daq, re.M) else None)
    rec, ana, drp = g("received"), g("analyzed"), g("dropped")
    if rec is None or ana is None: metrics["engine_kernel_drops"] = "MISSING"; reasons.append("Snort DAQ received/analyzed MISSING")
    else:
        # Snort prints only non-zero counters: 'dropped' absent with received == analyzed is a measured 0 (derived)
        metrics["engine_received"] = rec; metrics["engine_analyzed"] = ana
        metrics["engine_kernel_drops"] = (drp if drp is not None else 0) + (rec - ana)
        metrics["engine_drops_derivation"] = "daq.dropped (absent = 0, Snort omits zero counters) + (received - analyzed)"
        if metrics["engine_kernel_drops"] > inv["engine_kernel_drops_max"]: reasons.append("Snort DAQ drops %d" % metrics["engine_kernel_drops"])
    for k in ("allow", "block", "blacklist"): metrics["daq_" + k] = g(k) if g(k) is not None else 0

# ---- detection / prevention vs ground truth
txt = open(os.path.join(d, "summary.txt")).read(); det = json.loads(txt[txt.index("{"): txt.rindex("}") + 1])
a = {int(k): v for k, v in det["alerts_by_sid"].items()}
http_sid = {"suricata": {"ids": 9100001, "ips": 9100011}, "snort3": {"ids": 9200001, "ips": 9200011}}[eng][mode]
icmp_sid = http_sid + 1
metrics.update({"canary_http_events": a.get(http_sid, 0), "canary_icmp_events": a.get(icmp_sid, 0), "unexpected_alerts": det["unexpected_alerts"]})
if a.get(http_sid, 0) != exp["canary_http_alerts"]: reasons.append("HTTP marker events %d != %d" % (a.get(http_sid, 0), exp["canary_http_alerts"]))
if a.get(icmp_sid, 0) < exp["canary_icmp_alerts_min"]: reasons.append("ICMP marker events %d < %d" % (a.get(icmp_sid, 0), exp["canary_icmp_alerts_min"]))
if det["unexpected_alerts"]: reasons.append("%d unexpected alerts on legitimate traffic" % det["unexpected_alerts"])
blocked = all(c == "000" for c in det["canary_http_codes"])
if exp["canary_http_must_be_blocked"] != blocked: reasons.append("HTTP marker %s but %s expected" % ("blocked" if blocked else "delivered", "blocking" if exp["canary_http_must_be_blocked"] else "delivery"))
if any(c != "200" for c in det["legit_http_codes"]): reasons.append("legitimate ground-truth HTTP failed")

res = {"run_id": run_id, "series": P["series"], "engine": eng, "mode": mode, "params_status": P["status"],
       "run_status": "INVALID" if reasons else "VALID", "invalid_reasons": reasons, "metrics": metrics, "metric_status": status}
json.dump(res, open(os.path.join(d, "experiment_result.json"), "w"), indent=1)

# ---- InfluxDB line protocol (only MEASURED numeric values are written; MISSING/NOT_APPLICABLE are omitted, never 0)
tags = "series=%s,engine=%s,mode=%s,run_id=%s" % (P["series"], eng, mode, run_id)
num = {k: v for k, v in metrics.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}
lines = ["archivirt_val_run,%s %s,run_valid=%di %d" % (tags, ",".join("%s=%s" % (k, float(v)) for k, v in sorted(num.items())), 0 if reasons else 1, int(t1 * 1e9))]
for (t, p) in cpct:
    lines.append("archivirt_val_sample,%s monitor_cpu_pct=%.2f %d" % (tags, p, int(t * 1e9)))
for s in S:
    f = ["%s=%s" % (k, float(s["v"][k])) for k in ("monitor_mem_avail_mib", "target03_mem_avail_mib", "host_mem_avail_mib") if s["st"].get(k) == "MEASURED"]
    if f: lines.append("archivirt_val_sample,%s %s %d" % (tags, ",".join(f), int(s["ts"] * 1e9)))
open(os.path.join(d, "metrics.lp"), "w").write("\n".join(lines) + "\n")
print(json.dumps({k: res[k] for k in ("run_id", "run_status", "invalid_reasons")}, indent=1))
print(json.dumps(metrics, indent=1))
