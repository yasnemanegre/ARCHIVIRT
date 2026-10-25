#!/usr/bin/env python3
"""ARCHIVIRT - T-A criteria evaluator for a diagnostic arm (D0I). PREPARED, NOT INTEGRATED in the repository.

Read-only on its inputs. Evaluates, per run and for the series, the criteria of ta_criteria.*.json (sourced, status
PROPOSED until decision M-6; r1 = D-B2-2 applied): (a) effective AF_PACKET geometry + no zero-copy, (b) per-RX drops in drop runs,
(c) residual kernel_packets - kernel_drops - decoder.pkts in drop runs, plus coverage / collection / guards.
Fail-safe: anything missing, truncated, invalid, contradictory or incomplete gives NOT_EVALUABLE, never a favourable
verdict. Engine totals and coverage are read with the TESTED fail-safe parser PATCH-1r1+2r1 (vendor/, sha checked).

Run layout expected (campaign_v1.sh with PATCH-5r1/6): <series>/ids/<scenario>/<RUN>/ with stats.log, eve.json,
attack_times.txt, engine_stop.txt, perf_start.txt, perf_end.txt, engine_extra/{ENGINE_EXTRA_STATUS,
ENGINE_EXTRA_SHA256SUMS, capture_geometry.json, suricata.log}.
Usage: ta_evaluator.py --series DIR --scenario SCN-001 --criteria ta_criteria.json --emergency-flush disabled|enabled|unknown --out FILE
Exit: 0 DEMONSTRATED with APPROVED criteria; 5 DEMONSTRATED but criteria not approved (provisional);
      3 REFUTED or NOT_MET; 4 NOT_EVALUABLE; 2 usage / integrity error. The output file is never inside the series."""
import argparse, glob, hashlib, importlib.util, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR_SHA = {"archivirt_stopwatch_eval.py": "fc1864af9bce27d80310271a17c6cc3f6b69696e47fb79a2f792ed5fbf86853e",
              "p2_stopcriteria.py": "d5296127c18d60eaaa9f2739d56879031f47c3b58a51ec9b5fa089871775f326",
              "stop_criteria_v3.1-A.APPROVED.json": "bf4662913109225d8ca9f1fc1731cb819b96ceb57c2288a1d4340ef41027e68c"}
NE, MET, NOT_MET, REF, NA = "NOT_EVALUABLE", "MET", "NOT_MET", "REFUTED", "NOT_APPLICABLE"
RX_NAME = re.compile(r"RX#\d+(?:-[A-Za-z0-9._]+)?")      # single interface: RX#nn without suffix (suricata.sh l.84-88)
DIG = re.compile(r"[0-9]+")

def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()

def load_vendor():
    for f, h in VENDOR_SHA.items():
        p = os.path.join(HERE, "vendor", f)
        if not os.path.isfile(p) or sha(p) != h:
            raise RuntimeError("vendor integrity: %s" % f)
    sys.dont_write_bytecode = True
    sys.path.insert(0, os.path.join(HERE, "vendor"))
    sp = importlib.util.spec_from_file_location("ev", os.path.join(HERE, "vendor", "archivirt_stopwatch_eval.py"))
    m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m); sys.path.pop(0)
    rule = json.load(open(os.path.join(HERE, "vendor", "stop_criteria_v3.1-A.APPROVED.json")))["engine_drops"]
    return m, rule

def uint(s):
    return int(s) if isinstance(s, str) and DIG.fullmatch(s) else None

def last_record_total(stats_log, counter):
    """Total of <counter> in the LAST Date: record; None if absent/ambiguous/invalid (complete last line required)."""
    try: text = open(stats_log).read()
    except Exception: return None, "unreadable"
    if not text.endswith("\n"): return None, "truncated"
    recs = re.split(r"(?m)^Date:.*$", text)
    if len(recs) < 2: return None, "no record"
    vals = set()
    for line in recs[-1].splitlines():
        f = [x.strip() for x in line.split("|")]
        if len(f) == 3 and f[0] == counter and f[1] == "Total":
            v = uint(f[2])
            if v is None: return None, "invalid value"
            vals.add(v)
    if len(vals) != 1: return None, "absent" if not vals else "duplicated with different values"
    return vals.pop(), None

def read_extra(run):
    """Collection status + integrity of engine_extra files against ENGINE_EXTRA_SHA256SUMS."""
    ex = os.path.join(run, "engine_extra"); out = {"status": None, "problems": [], "verified": set()}
    try: st = open(os.path.join(ex, "ENGINE_EXTRA_STATUS")).read().strip()
    except Exception: out["problems"].append("ENGINE_EXTRA_STATUS absent"); return out
    out["status"] = st
    if st != "COMPLETE": out["problems"].append("collection " + st)
    try:
        for line in open(os.path.join(ex, "ENGINE_EXTRA_SHA256SUMS")):
            m = re.fullmatch(r"([0-9a-f]{64})  (\S+)\n?", line)
            if not m: continue
            p = os.path.join(ex, m.group(2))
            if os.path.isfile(p) and sha(p) == m.group(1): out["verified"].add(m.group(2))
            else: out["problems"].append("sha mismatch or missing: " + m.group(2))
    except Exception: out["problems"].append("ENGINE_EXTRA_SHA256SUMS unreadable")
    return out

def per_rx_from_log(text):
    rows, bad = {}, []
    for name, pk, dr in re.findall(r"\((" + RX_NAME.pattern + r")\) Kernel: Packets (\S+), dropped (\S+)", text):
        pk, dr = uint(pk.rstrip(",")), uint(dr)
        if pk is None or dr is None or dr > pk: bad.append(name); continue
        if name in rows and rows[name] != (pk, dr): bad.append(name + " duplicated"); continue
        rows[name] = (pk, dr)
    return rows, bad

def per_rx_from_eve(eve_path):
    last = None
    try:
        for line in open(eve_path):
            if '"event_type":"stats"' in line: last = json.loads(line)
    except Exception as e: return None, "eve unreadable (%s)" % type(e).__name__
    if last is None or "threads" not in last.get("stats", {}): return None, "no per-thread stats in eve"
    rows = {}
    for name, t in last["stats"]["threads"].items():
        if not RX_NAME.fullmatch(name): continue
        c = t.get("capture") or {}
        pk, dr = c.get("kernel_packets"), c.get("kernel_drops")
        if not (isinstance(pk, int) and isinstance(dr, int)) or pk < 0 or dr < 0 or dr > pk: return None, "invalid per-thread counters " + name
        rows[name] = (pk, dr)
    return (rows or None), (None if rows else "no RX thread in eve stats")

def thr_deltas(run):
    """PATCH-6 descriptive deltas (exploratory, no threshold)."""
    def load(p):
        d = {}
        try:
            for l in open(p):
                k, _, v = l.strip().partition("=")
                if k.startswith("thr_") and DIG.fullmatch(v): d[k] = int(v)
        except Exception: return None
        return d
    s, e = load(os.path.join(run, "perf_start.txt")), load(os.path.join(run, "perf_end.txt"))
    if not s or not e: return None
    out = {}
    for k in e:
        m = re.fullmatch(r"thr_(rx_\d+(?:_\w+)?)_(run_ns|wait_ns|vcs|ncs)", k)
        if m and k in s and e[k] >= s[k]: out.setdefault(m.group(1), {})[m.group(2)] = e[k] - s[k]
    return out or None

def eval_run(run, ev, rule, crit, flush):
    r = {"run": os.path.basename(run), "reasons": [], "flags": []}
    # --- engine totals + coverage (tested PATCH-1r1+2r1) ---
    stats = os.path.join(run, "stats.log")
    s, why, tot = ev.engine_drops(stats, rule)
    if s != NE:
        cov = ev.engine_drops_coverage(stats, tot)
        if cov: s, why = NE, cov
    r["engine_drops"] = {"status": s, "detail": why}
    totals_ok = s != NE
    kp = tot.get("capture.kernel_packets") if totals_ok else None
    kd = tot.get("capture.kernel_drops") if totals_ok else None
    r["drop_run"] = (kd > 0) if totals_ok else None
    if not totals_ok: r["reasons"].append("engine totals: " + why)
    # --- stop status ---
    try: stop = open(os.path.join(run, "engine_stop.txt")).read()
    except Exception: stop = None
    if stop is None or "STOPPED_CLEAN" not in stop:
        r["reasons"].append("engine stop status " + ("absent" if stop is None else "not STOPPED_CLEAN"))
        if stop and "STOPPED_FORCED" in stop: r["flags"].append("STOPPED_FORCED: no final stats dump, no exit statistics")
    stop_ok = stop is not None and "STOPPED_CLEAN" in stop
    # --- collection ---
    x = read_extra(run); r["collection"] = {"status": x["status"], "problems": x["problems"]}
    extra_ok = x["status"] == "COMPLETE" and not x["problems"]
    if not extra_ok: r["reasons"].append("collection incomplete: " + "; ".join(x["problems"]))
    log = None
    if extra_ok and "suricata.log" in x["verified"]:
        log = open(os.path.join(run, "engine_extra", "suricata.log"), errors="replace").read()
        if log and not log.endswith("\n"): log = None; r["reasons"].append("suricata.log truncated")
    # --- (a) geometry ---
    g = crit["TA_a_geometry"]; a = NE; geo = None
    if extra_ok and "capture_geometry.json" in x["verified"]:
        try: geo = json.load(open(os.path.join(run, "engine_extra", "capture_geometry.json")))
        except Exception: geo = None; r["reasons"].append("capture_geometry.json invalid")
    if geo is not None and log is not None:
        socks = geo.get("sockets") if geo.get("status") == "OK" else None
        if not socks: r["reasons"].append("geometry status %s" % geo.get("status"))
        elif any(sk.get("layout") not in ("TPACKET_V2", "TPACKET_V3") for sk in socks):
            r["reasons"].append("geometry UNDETERMINED on a socket")
        else:
            rp = [int(v) for v in re.findall(r"AF_PACKET (?:V3 )?RX Ring params: [^\n]*frame_nr=(\d+)", log)]
            frames = [sk.get("frames") for sk in socks]
            if rp and sorted(rp) != sorted(f for f in frames if f is not None):
                r["reasons"].append("ring params logged %s != probe %s (contradiction)" % (rp, frames))
            else:
                r["ring_params_logged"] = bool(rp)
                if len(socks) < g["sockets"]:   # D-B2-2 (M-6): an absent required socket may be a probe miss -> NOT_EVALUABLE, never REFUTED
                    r["reasons"].append("required socket absent: %d observed < %d required (D-B2-2)" % (len(socks), g["sockets"]))
                else:
                    good = (len(socks) == g["sockets"] and all(sk["layout"] == g["layout"] and sk.get("frames") == g["frames_per_socket"] for sk in socks))
                    if not good: a = REF
                    elif g["zero_copy_message_must_be_absent"] and re.search(r"enabling zero copy mode", log): a = NOT_MET
                    else: a = MET
        r["geometry"] = {"sockets": [(sk.get("layout"), sk.get("frame_size"), sk.get("block_size"), sk.get("frames")) for sk in (geo.get("sockets") or [])]}
    elif geo is not None and log is None: r["reasons"].append("suricata.log unavailable (zero-copy check impossible)")
    r["TA_a"] = a
    # --- (b) per-RX ---
    b = NA
    if r["drop_run"] is None: b = NE
    elif r["drop_run"]:
        b = NE; src = {}
        if log is not None and stop_ok:
            rows, bad = per_rx_from_log(log)
            if bad: r["reasons"].append("invalid per-RX log lines: %s" % bad)
            elif rows: src["log"] = rows
        e_rows, e_why = per_rx_from_eve(os.path.join(run, "eve.json"))
        if e_rows: src["eve"] = e_rows
        elif e_why: r["flags"].append("eve per-RX: " + e_why)
        if not src: r["reasons"].append("no per-RX source")
        elif len(src) == 2 and src["log"] != src["eve"]: r["reasons"].append("per-RX sources disagree (log vs eve)")
        else:
            rows = next(iter(src.values())); r["per_rx"] = {k: {"packets": v[0], "dropped": v[1]} for k, v in sorted(rows.items())}
            nsock = len((geo or {}).get("sockets") or [])
            if len(rows) != crit["TA_a_geometry"]["sockets"] or (nsock and nsock != len(rows)):
                r["reasons"].append("RX count %d != sockets %d" % (len(rows), nsock or crit["TA_a_geometry"]["sockets"]))
            elif sum(v[1] for v in rows.values()) != kd:
                r["reasons"].append("sum(RX dropped)=%d != Total kernel_drops=%d (contradiction)" % (sum(v[1] for v in rows.values()), kd))
            elif all(v[1] > 0 for v in rows.values()): b = MET
            else: b = REF
    r["TA_b"] = b
    # --- (c) residual ---
    dec, dwhy = last_record_total(stats, "decoder.pkts")
    resid = (kp - kd - dec) if (totals_ok and dec is not None) else None
    r["residual"] = resid
    if totals_ok and dec is None: r["reasons"].append("decoder.pkts: " + dwhy)
    if resid is not None and resid < 0: r["reasons"].append("negative residual %d (contradiction)" % resid); resid = None
    c = NA
    if r["drop_run"] is None: c = NE
    elif r["drop_run"]:
        if flush != "disabled": c = NE; r["reasons"].append("residual prerequisite: emergency flush %s" % flush)
        elif log is not None and re.search(r"Enabling ring emergency flush", log): c = NE; r["reasons"].append("flush declared disabled but logged enabled (contradiction)")
        elif resid is None: c = NE
        else: c = MET if resid == 0 else REF
    r["TA_c"] = c
    # --- guards (flags only) ---
    try:
        at = open(os.path.join(run, "attack_times.txt")).read().split()
        st, en = ev._iso_epoch(at[0]), ev._iso_epoch(at[1])
        w = crit["guards"]["M3_stats_write_window_s"]
        for l in open(os.path.join(run, "eve.json")):
            if '"event_type":"stats"' in l:
                t = ev._iso_epoch(json.loads(l)["timestamp"])
                if st - w["before_attack_start"] <= t <= en + w["after_attack_end"]: r["flags"].append("M3: stats write inside the burst window")
    except Exception as e:
        r["flags"].append("M3 guard not evaluable (%s)" % type(e).__name__)
    r["contention_patch6"] = thr_deltas(run)
    # a run whose own evidence is incomplete supports neither a favourable criterion nor a refutation
    if r["reasons"]:
        for k in ("TA_a", "TA_b", "TA_c"):
            if r[k] in (MET, REF, NOT_MET): r[k + "_if_evidence_complete"] = r[k]; r[k] = NE
    return r

def series_verdict(runs, crit):
    why = []
    if not runs: return NE, ["no run"]
    refuted = [(r["run"], k) for r in runs for k in ("TA_a", "TA_b", "TA_c") if r[k] == REF]
    if refuted: return REF, ["sourced refutation: %s" % refuted]
    drops = [r for r in runs if r["drop_run"]]
    if any(r["TA_a"] == NE for r in runs): why.append("(a) not evaluable in %s" % [r["run"] for r in runs if r["TA_a"] == NE])
    if any(r["drop_run"] is None for r in runs): why.append("drop status unknown in %s" % [r["run"] for r in runs if r["drop_run"] is None])
    if not drops and crit["TA_series"]["requires_at_least_one_drop_run"]: why.append("no drop run: mechanism not observable")
    for k in ("TA_b", "TA_c"):
        if any(r[k] == NE for r in drops): why.append("(%s) not evaluable in %s" % (k[-1], [r["run"] for r in drops if r[k] == NE]))
    if why: return NE, why
    if any(r["TA_a"] == NOT_MET for r in runs): return NOT_MET, ["zero-copy message present (a)"]
    return "DEMONSTRATED", ["all IDS runs (a) MET; every drop run (b) and (c) MET"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--series", required=True); ap.add_argument("--scenario", required=True); ap.add_argument("--criteria", required=True)
    ap.add_argument("--emergency-flush", required=True, choices=("disabled", "enabled", "unknown")); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    try: ev, rule = load_vendor()
    except Exception as e: print("INTEGRITY_ERROR: %s" % e, file=sys.stderr); return 2
    try: crit = json.load(open(a.criteria)); assert crit.get("schema") == "archivirt-ta-criteria/1"
    except Exception: print("USAGE_ERROR: criteria unreadable or wrong schema", file=sys.stderr); return 2
    series = os.path.realpath(a.series); out = os.path.realpath(a.out)
    if not os.path.isdir(series): print("USAGE_ERROR: series dir", file=sys.stderr); return 2
    if out == series or out.startswith(series + os.sep): print("REFUSED: output inside the series (evidence untouched)", file=sys.stderr); return 2
    if os.path.exists(out): print("REFUSED: output exists (never overwritten)", file=sys.stderr); return 2
    runs = [eval_run(d, ev, rule, crit, a.emergency_flush) for d in sorted(glob.glob(os.path.join(series, "ids", a.scenario, a.scenario + "-RUN-*"))) if os.path.isdir(d)]
    verdict, why = series_verdict(runs, crit)
    res = {"tool": "ta_evaluator/1", "series": series, "scenario": a.scenario, "criteria_sha256": sha(a.criteria),
           "criteria_status": crit.get("status"), "provisional": crit.get("status") != "APPROVED", "emergency_flush_declared": a.emergency_flush,
           "verdict": verdict, "why": why, "runs": runs,
           "non_drop_runs_residual_informational": {r["run"]: r["residual"] for r in runs if r["drop_run"] is False},
           "undefined": [k for k, v in crit["guards"].items() if str(v.get("status", "")).startswith("UNDEFINED")]}
    with open(out, "x") as f: json.dump(res, f, indent=1, sort_keys=True, default=list)
    print(json.dumps({k: res[k] for k in ("verdict", "why", "criteria_status", "provisional")}))
    if verdict == "DEMONSTRATED": return 0 if not res["provisional"] else 5
    return 3 if verdict in (REF, NOT_MET) else 4

if __name__ == "__main__":
    sys.exit(main())
