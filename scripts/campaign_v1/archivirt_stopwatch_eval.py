#!/usr/bin/env python3
"""ARCHIVIRT — stop-criteria evaluator v2 (PROPOSAL C1.3). Offline; pure function of its inputs.

Per criterion: CONFIRMED | NOT_EXCEEDED | NOT_APPLICABLE (by mode) | NOT_EVALUABLE.
Run verdict: INVALID if any criterion CONFIRMED or NOT_EVALUABLE, if the recorder did not end
cleanly, if an immediate-abort file exists, or if engine drops are confirmed/not evaluable;
otherwise VALID. Absent values are NEVER converted to 0.
--remote-jsonl: optional second stream (agent) providing remote metrics; host metrics always
come from --jsonl. --result-json (+ --repo) writes a "stop_criteria" block (always) and sets
run_status=INVALID when INVALID; the directory must pass results_guard.py (frozen data untouchable).
Exit: 0 VALID, 3 INVALID, 2 params/usage error, 4 refused write.
"""
import argparse, datetime, hashlib, json, os, re, subprocess, sys
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p2_stopcriteria import load_params, applicable, CriterionState, ParamsError

REMOTE_METRICS = {"monitor_mem_available_mib", "target03_mem_available_mib", "capture_iface_drops_delta", "nfq_queue_dropped_delta"}

def read_stream(path):
    rows, bad, end = [], 0, None
    try:
        for line in open(path):
            line = line.strip()
            if not line: continue
            try: r = json.loads(line)
            except Exception: bad += 1; continue
            if r.get("end"): end = r; continue
            rows.append(r)
    except FileNotFoundError:
        return None, 0, None
    return rows, bad, end

ENGINE_COUNTERS = ("capture.kernel_packets", "capture.kernel_drops")

def engine_drops(stats_log, rule):
    """Fail-safe reading of the engine counters (P1). Only the LAST "Date:" record of stats.log is evaluated and both
    counters must come from that same record; any doubt (absent, truncated, mixed, duplicated, decreasing or
    impossible values, no packet captured) gives NOT_EVALUABLE - never a favourable verdict.
    r1 (2026-10-22 final review): a value must be ASCII digits only (int() also accepted "6_150", "+6150" and non-ASCII
    digits), and the file must end with a complete line (a cut inside the last value could lower kernel_drops)."""
    if stats_log is None or not os.path.isfile(stats_log):
        return "NOT_EVALUABLE", "stats.log absent", None
    recs = []                                    # one dict per "Date:" record
    line = ""
    try:
        for line in open(stats_log):
            if line.startswith("Date:"):
                recs.append({}); continue
            f = [x.strip() for x in line.split("|")]
            if len(f) == 3 and f[1] == "Total" and f[0] in ENGINE_COUNTERS:
                if not recs:
                    return "NOT_EVALUABLE", "%s outside any stats record" % f[0], None
                if f[2][:1] == "-" and f[2][1:].isdigit():
                    return "NOT_EVALUABLE", "%s negative" % f[0], recs[-1]
                if not (f[2].isascii() and f[2].isdigit()):
                    return "NOT_EVALUABLE", "%s not a non-negative integer" % f[0], recs[-1]
                v = int(f[2])
                if recs[-1].get(f[0], v) != v:
                    return "NOT_EVALUABLE", "%s duplicated with different values in one record" % f[0], recs[-1]
                recs[-1][f[0]] = v
    except Exception as e:
        return "NOT_EVALUABLE", "stats.log unreadable (%s)" % type(e).__name__, None
    if line and not line.endswith("\n"):
        return "NOT_EVALUABLE", "stats.log truncated (last line incomplete)", recs[-1] if recs else None
    if not recs:
        return "NOT_EVALUABLE", "no stats record", None
    tot = recs[-1]                               # never completed from an earlier record (R1, E12)
    for k in ENGINE_COUNTERS:                    # engine restart or counter reset (E13)
        seen = [r[k] for r in recs if k in r]
        if any(b < a for a, b in zip(seen, seen[1:])):
            return "NOT_EVALUABLE", "%s decreases between stats records (reset)" % k, tot
    pk, dr = tot.get("capture.kernel_packets"), tot.get("capture.kernel_drops")
    pol = rule["absent_counter_policy"]["value"]
    if pk is None:                               # includes per-thread rows without a Total row (R8)
        return "NOT_EVALUABLE", "capture.kernel_packets absent", tot
    if dr is None:
        if pol == "zero_if_family_present": dr = 0
        else: return "NOT_EVALUABLE", "capture.kernel_drops absent (policy: missing)", tot
    if pk == 0:                                  # nothing captured: absence of drops is not evidenced
        return "NOT_EVALUABLE", "capture.kernel_packets = 0 (capture not evidenced)", tot
    if dr > pk:                                  # kernel_packets already includes the drops
        return "NOT_EVALUABLE", "kernel_drops=%d > kernel_packets=%d (inconsistent)" % (dr, pk), tot
    bad = dr > rule["abs_max"] if pk < rule["abs_max_below_packets"] else (dr / pk) > rule["rel_max_above"]
    return ("CONFIRMED" if bad else "NOT_EXCEEDED"), "kernel_drops=%d kernel_packets=%d" % (dr, pk), tot

def _iso_epoch(s):
    s = s.strip().replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", s): s = s[:-2] + ":" + s[-2:]
    m = re.match(r"(.*\.\d{6})\d*(.*)$", s)
    t = datetime.datetime.fromisoformat(m.group(1) + m.group(2) if m else s)
    if t.tzinfo is None:                          # r1: never read a naive timestamp in the evaluator's local zone
        raise ValueError("timestamp without UTC offset")
    return t.timestamp()

def engine_drops_coverage(stats_log, tot):
    """Coverage guard (P2): the evaluated record must be the engine's own last stats dump, written AFTER the attack.
    Source: the "stats" events of eve.json (ISO timestamps with explicit offset) next to stats.log, cross-checked
    against the stats.log record, and attack_times.txt (attack end). Any doubt -> reason string (NOT_EVALUABLE)."""
    d = os.path.dirname(os.path.abspath(stats_log))
    try:
        at = open(os.path.join(d, "attack_times.txt")).read().split()
        if len(at) != 2: return "attack_times.txt incomplete"
        end = _iso_epoch(at[1])
        last = None
        for line in open(os.path.join(d, "eve.json")):
            if '"event_type":"stats"' not in line: continue
            e = json.loads(line); last = e
        if last is None: return "no stats event in eve.json"
        cap = last["stats"]["capture"]
        if (cap.get("kernel_packets"), cap.get("kernel_drops")) != (tot.get("capture.kernel_packets"), tot.get("capture.kernel_drops")):
            return "last eve.json stats event differs from the last stats.log record"
        if _iso_epoch(last["timestamp"]) < end:
            return "last stats record precedes the attack end (traffic not covered)"
    except Exception as e:
        return "coverage unreadable (%s)" % type(e).__name__
    return None

def evaluate(params, mode, rows, bad, end, remote_rows, stats_log, abort):
    res, reasons = {}, []
    if rows is None: return "INVALID", {"_recorder": "NOT_EVALUABLE"}, ["NOT_EVALUABLE: recorder output absent"]
    if end is None: reasons.append("NOT_EVALUABLE: recorder did not end cleanly (no end record)")
    if not rows: reasons.append("NOT_EVALUABLE: no samples")
    if abort: reasons.append("STOP_IMMEDIATE: %s" % abort.get("criterion", {}).get("criterion"))
    def stream_for(m):
        return remote_rows if (remote_rows is not None and m in REMOTE_METRICS) else rows
    gap = params["gap_policy"]["value"]
    # missing fraction per applicable metric
    for m, spec in params["metrics"].items():
        if not applicable(params, m, mode): continue
        s = stream_for(m) or []
        n = len(s) + bad
        miss = sum(1 for i, r in enumerate(s) if r.get("status", {}).get(m) in (None, "MISSING", "ERROR"))
        nas = sum(1 for r in s if r.get("status", {}).get(m) == "NOT_APPLICABLE")
        denom = max(n - nas, 1)
        if s and (miss + bad) / denom > params["max_missing_fraction"]:
            reasons.append("NOT_EVALUABLE: metric %s missing in %.1f%% of samples" % (m, 100.0 * (miss + bad) / denom))
    for name, c in params["criteria"].items():
        m = c["metric"]
        if not applicable(params, m, mode):
            res[name] = {"status": "NOT_APPLICABLE", "reason": params["metrics"][m].get("not_applicable_reason", "mode %s" % mode)}; continue
        st = CriterionState(name, c, gap)
        for r in (stream_for(m) or []):
            st.feed(r["ts_epoch"], r.get("status", {}).get(m), r.get("values", {}).get(m))
        if st.hit:
            res[name] = {"status": "CONFIRMED", **st.hit}; reasons.append("STOP_CRITERIA: %s (%s %s %s)" % (name, m, c["op"], c["value"]))
        elif st.unknown:
            res[name] = {"status": "NOT_EVALUABLE", "reason": "gap inside an exceeding run (gap_policy=%s)" % gap}
            reasons.append("NOT_EVALUABLE: %s gap inside an exceeding run" % name)
        else:
            res[name] = {"status": "NOT_EXCEEDED"}
    ed = params.get("engine_drops")
    if ed:
        if mode in ed["modes"]:
            s, why, tot = engine_drops(stats_log, ed)
            if s != "NOT_EVALUABLE":
                cov = engine_drops_coverage(stats_log, tot)
                if cov: s, why = "NOT_EVALUABLE", cov
            res["engine_drops"] = {"status": s, "detail": why, "counters": tot}
            if s == "CONFIRMED": reasons.append("STOP_CRITERIA: engine_drops (%s)" % why)
            if s == "NOT_EVALUABLE": reasons.append("NOT_EVALUABLE: engine_drops (%s)" % why)
        else:
            res["engine_drops"] = {"status": "NOT_APPLICABLE", "reason": ed.get("not_applicable_reason")}
    return ("INVALID" if reasons else "VALID"), res, reasons

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", required=True); ap.add_argument("--params", required=True); ap.add_argument("--mode", required=True)
    ap.add_argument("--remote-jsonl"); ap.add_argument("--stats-log"); ap.add_argument("--abort-file")
    ap.add_argument("--result-json"); ap.add_argument("--repo"); ap.add_argument("--protect", action="append", default=[])
    a = ap.parse_args()
    try:
        raw = open(a.params, "rb").read(); params = load_params(raw)
    except (OSError, ValueError, ParamsError) as e:
        print("PARAMS_ERROR: %s" % e, file=sys.stderr); return 2
    if a.mode not in ("ids", "ips", "baseline"):
        print("USAGE_ERROR: mode", file=sys.stderr); return 2
    rows, bad, end = read_stream(a.jsonl)
    remote = read_stream(a.remote_jsonl)[0] if a.remote_jsonl else None
    if a.remote_jsonl and remote is None: remote = []
    abort = None
    if a.abort_file and os.path.isfile(a.abort_file):
        try: abort = json.load(open(a.abort_file))
        except Exception: abort = {"criterion": {"criterion": "unreadable abort file"}}
    verdict, res, reasons = evaluate(params, a.mode, rows, bad, end, remote, a.stats_log, abort)
    block = {"evaluated": True, "verdict": verdict, "reasons": reasons, "criteria": res, "mode": a.mode,
             "samples": len(rows or []), "unreadable_lines": bad, "params_status": params.get("status"),
             "params_version": params.get("version"), "params_sha256": hashlib.sha256(raw).hexdigest()}
    print(json.dumps(block, indent=2, sort_keys=True))
    if a.result_json:
        guard = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_guard.py")
        cmd = [sys.executable, guard, "--repo", a.repo or "", "--dest", os.path.dirname(os.path.abspath(a.result_json))]
        for x in a.protect: cmd += ["--protect", x]
        if not a.repo or subprocess.run(cmd, capture_output=True).returncode != 0:
            print("REFUSED: result.json directory is protected (or --repo missing) - not modified", file=sys.stderr); return 4
        try: r = json.load(open(a.result_json))
        except FileNotFoundError: r = {"run_status": "INVALID", "invalid_reason": "result.json absent (interrupted run)"}
        r["stop_criteria"] = block
        if verdict == "INVALID":
            prev = r.get("invalid_reason") or ""
            r["run_status"] = "INVALID"
            r["invalid_reason"] = "; ".join(x for x in (prev, "; ".join(reasons)) if x)
        tmp = a.result_json + ".tmp"
        with open(tmp, "w") as f: json.dump(r, f, indent=2)
        os.replace(tmp, a.result_json)
    return 0 if verdict == "VALID" else 3

if __name__ == "__main__":
    sys.exit(main())
