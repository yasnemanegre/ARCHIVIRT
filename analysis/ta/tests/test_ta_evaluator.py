#!/usr/bin/env python3
"""Isolated tests of ta_evaluator.py (copies of D0 runs + synthetic engine_extra artifacts; no lab, no network).
A synthetic D0I-like series is built from verified copies: RUN-001 (no drop) and RUN-002 (458 drops, residual set to 0
by editing decoder.pkts of the LAST record of the COPY), plus the PATCH-5r1/PATCH-6 artifacts the campaign would add.
Each case mutates one aspect and checks the series verdict / per-run statuses. A counter-proof runs the nominal and
key cases against deliberately weakened copies of the evaluator: each weakening must be detected.
Usage: test_ta_evaluator.py <ta_evaluator_dir> <srccopy_series_dir> <workdir> <out_json>"""
import json, os, re, shutil, subprocess, sys, hashlib
EVD, SRC, WK, OUT = [os.path.abspath(x) for x in sys.argv[1:5]]
CRIT = os.path.join(EVD, "ta_criteria.D0I.PROPOSED.json")
shutil.rmtree(WK, ignore_errors=True); os.makedirs(WK)
results = []
def rec(tid, desc, ok, detail=""):
    results.append({"id": tid, "desc": desc, "result": "PASS" if ok else "FAIL", "detail": detail}); print("%-4s %s %s %s" % (tid, "PASS" if ok else "FAIL", desc, detail[:200]))
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()

GEOM = {"status": "OK", "pid": 4242, "sockets": [{"socket": "socket:[1]", "layout": "TPACKET_V2", "frame_size": 1600, "block_size": 32768, "frames_per_block": 20, "frames": 2060},
                                                  {"socket": "socket:[2]", "layout": "TPACKET_V2", "frame_size": 1600, "block_size": 32768, "frames_per_block": 20, "frames": 2060}]}
def slog(rx, ring=True, extra=""):
    L = ["22/10/2026 -- 18:33:28 - <Info> - Running in live mode, activating unix socket"]
    if ring: L += ["22/10/2026 -- 18:33:28 - <Perf> - AF_PACKET RX Ring params: block_size=32768 block_nr=103 frame_size=1600 frame_nr=2060"] * 2
    L += ["22/10/2026 -- 18:33:45 - <Perf> - (%s) Kernel: Packets %d, dropped %d" % (n, p, d) for n, (p, d) in rx.items()]
    return "\n".join(L) + "\n" + extra
def build(name, base, rx=None, geom=GEOM, log=None, status="COMPLETE", stop="ARCHIVIRT_ENGINE=STOPPED_CLEAN\n", eve_rx=None, residual0=True, perf=True, eve_shift=0, eve_dup=None):
    if eve_rx is None and rx is not None: eve_rx = rx          # r2 (D-TA-3 A): a D0I run carries BOTH sources by default
    if eve_rx == "NOEVE": eve_rx = None
    run = os.path.join(WK, name, "ids", "SCN-001", base); shutil.copytree(os.path.join(SRC, base), run)
    if residual0 and base != "SCN-001-RUN-001":     # D0 copies have flush residual 8/70/7; D0I (3b) expects 0
        st = open(run + "/stats.log").read(); recs = re.split(r"(?m)(?=^-{10,}\nDate:)", st)
        kp = int(re.findall(r"capture\.kernel_packets\s+\|\s+Total\s+\|\s+(\d+)", recs[-1])[0]); kd = int(re.findall(r"capture\.kernel_drops\s+\|\s+Total\s+\|\s+(\d+)", recs[-1])[0])
        recs[-1] = re.sub(r"(decoder\.pkts\s+\|\s+Total\s+\|\s+)\d+", lambda m: m.group(1) + str(kp - kd), recs[-1]); open(run + "/stats.log", "w").write("".join(recs))
    ex = os.path.join(run, "engine_extra"); os.makedirs(ex)
    files = {}
    if geom is not None: files["capture_geometry.json"] = geom if isinstance(geom, str) else json.dumps(geom) + "\n"
    if log is None and rx is not None: log = slog(rx)
    if log is not None: files["suricata.log"] = log
    for f, c in files.items(): open(os.path.join(ex, f), "w").write(c)
    open(os.path.join(ex, "ENGINE_EXTRA_SHA256SUMS"), "w").write("".join("%s  %s\n" % (sha(os.path.join(ex, f)), f) for f in files))
    if status is not None: open(os.path.join(ex, "ENGINE_EXTRA_STATUS"), "w").write(status + "\n")
    if stop is not None: open(os.path.join(run, "engine_stop.txt"), "w").write(stop)
    if eve_rx is not None:
        L = open(run + "/eve.json").readlines(); i = max(k for k, l in enumerate(L) if '"event_type":"stats"' in l)
        e = json.loads(L[i]); e["stats"]["threads"] = {n: {"capture": {"kernel_packets": p, "kernel_drops": d}} for n, (p, d) in eve_rx.items()}
        if eve_shift:
            import datetime as _dt
            ts = _dt.datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z") + _dt.timedelta(seconds=eve_shift); e["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
        L[i] = json.dumps(e, separators=(",", ":")) + "\n"
        if eve_dup is not None:
            e2 = json.loads(L[i]); e2["stats"]["threads"] = {n: {"capture": {"kernel_packets": p, "kernel_drops": d}} for n, (p, d) in eve_dup.items()}; L.insert(i + 1, json.dumps(e2, separators=(",", ":")) + "\n")
        open(run + "/eve.json", "w").writelines(L)
    if perf:
        for t, base_v in (("start", 0), ("end", 1)):
            open(os.path.join(run, "perf_%s.txt" % t), "w").write("wall_ns=1\nthr_rx_01_run_ns=%d\nthr_rx_01_wait_ns=%d\nthr_rx_02_run_ns=%d\nthr_rx_02_wait_ns=%d\n" % (10 + 50 * base_v, 5 + 90 * base_v, 10 + 60 * base_v, 5 + 80 * base_v))
    return os.path.join(WK, name)
OK_RX = {"RX#01": (3075, 200), "RX#02": (3075, 258)}         # 200 + 258 = 458 (RUN-002 Total); unsuffixed names (single iface)
NODROP = {"RX#01": (3081, 0), "RX#02": (3081, 0)}           # RUN-001: 6162 packets, 0 drops
def series(name, mods=None, nodrop_mods=None, drop_base="SCN-001-RUN-002", with_nodrop=True, with_drop=True):
    mods = mods or {}; nodrop_mods = nodrop_mods or {}
    if with_nodrop: build(name, "SCN-001-RUN-001", **dict({"rx": NODROP}, **nodrop_mods))
    if with_drop: build(name, drop_base, **dict({"rx": OK_RX}, **mods))
    return os.path.join(WK, name)
def run_ev(ser, flush="disabled", evaluator=None, crit=CRIT, out=None):
    out = out or os.path.join(WK, "out_%s_%d.json" % (os.path.basename(ser), len(os.listdir(WK))))
    p = subprocess.run([sys.executable, "-I", evaluator or os.path.join(EVD, "ta_evaluator.py"), "--series", ser, "--scenario", "SCN-001", "--criteria", crit,
                        "--emergency-flush", flush, "--out", out], capture_output=True, text=True)
    res = json.load(open(out)) if os.path.exists(out) else None
    return p.returncode, res, p.stderr
def V(res): return res and res["verdict"]
def runst(res, run, k): return [r[k] for r in res["runs"] if r["run"] == run][0]

CASES = []   # (id, desc, series builder kwargs, flush, expected verdict, expected rc, extra check)
def case(tid, desc, ser, exp, rc, flush="disabled", check=None): CASES.append((tid, desc, ser, flush, exp, rc, check))
case("N01", "nominal: geometry OK, both RX drop, sum == Total, residual 0", lambda: series("N01"), "DEMONSTRATED", 5,
     check=lambda r: r["provisional"] and runst(r, "SCN-001-RUN-002", "TA_b") == "MET" and runst(r, "SCN-001-RUN-002", "TA_c") == "MET")
case("N02", "nominal with suffixed thread names RX#01-ens7", lambda: series("N02", mods={"rx": {"RX#01-ens7": (3075, 200), "RX#02-ens7": (3075, 258)}}), "DEMONSTRATED", 5)
case("N03", "r2: eve per-RX present but NO exit lines in log (clean stop) -> corroboration missing -> NOT_EVALUABLE", lambda: series("N03", mods={"rx": None, "log": slog({}), "eve_rx": OK_RX}), "NOT_EVALUABLE", 4)
case("N04", "per-RX log and eve agree", lambda: series("N04", mods={"eve_rx": OK_RX}), "DEMONSTRATED", 5)
case("N05", "two drop runs (002 and 009) both consistent", lambda: (series("N05"), build("N05", "SCN-001-RUN-009", rx={"RX#01": (3080, 30), "RX#02": (3080, 35)}))[0], "DEMONSTRATED", 5)
case("Z01", "no drop run at all -> mechanism not observable", lambda: series("Z01", with_drop=False), "NOT_EVALUABLE", 4)
case("Z02", "empty series", lambda: (os.makedirs(os.path.join(WK, "Z02", "ids", "SCN-001")), os.path.join(WK, "Z02"))[1], "NOT_EVALUABLE", 4)
case("A01", "geometry TPACKET_V3 -> sourced refutation (a)", lambda: series("A01", mods={"geom": dict(GEOM, sockets=[dict(s, layout="TPACKET_V3") for s in GEOM["sockets"]])}), "REFUTED", 3)
case("A02", "geometry 8200 frames (wrong ring for D0I) -> refutation (a)", lambda: series("A02", mods={"geom": dict(GEOM, sockets=[dict(s, frames=8200) for s in GEOM["sockets"]]), "log": slog(OK_RX, ring=False)}), "REFUTED", 3)
case("A03", "geometry UNDETERMINED -> NOT_EVALUABLE", lambda: series("A03", mods={"geom": dict(GEOM, sockets=[{"layout": "UNDETERMINED"}, GEOM["sockets"][1]])}), "NOT_EVALUABLE", 4)
case("A04", "geometry NO_INSTANCE -> NOT_EVALUABLE", lambda: series("A04", mods={"geom": {"status": "NO_INSTANCE"}}), "NOT_EVALUABLE", 4)
case("A05", "geometry file absent", lambda: series("A05", mods={"geom": None}), "NOT_EVALUABLE", 4)
case("A06", "zero copy message in log -> NOT_MET (not a sourced refutation)", lambda: series("A06", mods={"log": slog(OK_RX, extra="x - <Perf> - ens7: enabling zero copy mode by using data release call\n")}), "NOT_MET", 3)
case("A07", "ring params logged 2048 vs probe 2060 -> contradiction", lambda: series("A07", mods={"log": slog(OK_RX).replace("frame_nr=2060", "frame_nr=2048")}), "NOT_EVALUABLE", 4)
case("A08", "only one socket in geometry", lambda: series("A08", mods={"geom": dict(GEOM, sockets=GEOM["sockets"][:1])}), "NOT_EVALUABLE", 4,
     check=lambda r: runst(r, "SCN-001-RUN-002", "TA_b") == "NOT_EVALUABLE")
def _run(r, name="SCN-001-RUN-002"): return [x for x in r["runs"] if x["run"] == name][0]
case("A10", "r1 D-B2-2: one socket + one RX thread -> NOT_EVALUABLE with explicit 'required socket absent' reason and NO latent refutation",
     lambda: series("A10", mods={"geom": dict(GEOM, sockets=GEOM["sockets"][:1]), "log": slog({"RX#01": (4150, 458)}, ring=False, extra="22/10/2026 -- 18:33:28 - <Perf> - AF_PACKET RX Ring params: block_size=32768 block_nr=103 frame_size=1600 frame_nr=2060\n")}), "NOT_EVALUABLE", 4,
     check=lambda r: _run(r)["TA_a"] == "NOT_EVALUABLE" and "TA_a_if_evidence_complete" not in _run(r) and any("required socket absent" in x for x in _run(r)["reasons"]))
case("A11", "r1: three sockets (more than required) -> latent sourced refutation kept (TA_a_if_evidence_complete = REFUTED)",
     lambda: series("A11", mods={"geom": dict(GEOM, sockets=GEOM["sockets"] + [dict(GEOM["sockets"][0], socket="socket:[3]")]), "log": slog({"RX#01": (2000, 150), "RX#02": (2000, 150), "RX#03": (2150, 158)}, ring=False, extra="22/10/2026 -- 18:33:28 - <Perf> - AF_PACKET RX Ring params: block_size=32768 block_nr=103 frame_size=1600 frame_nr=2060\n"*3)}), "NOT_EVALUABLE", 4,
     check=lambda r: _run(r).get("TA_a_if_evidence_complete") == "REFUTED")
case("A09", "geometry JSON truncated (sha recorded on the truncated file)", lambda: series("A09", mods={"geom": json.dumps(GEOM)[:40]}), "NOT_EVALUABLE", 4)
case("B01", "drops on one RX only -> sourced refutation (b)", lambda: series("B01", mods={"rx": {"RX#01": (3075, 458), "RX#02": (3075, 0)}}), "REFUTED", 3)
case("B02", "sum(RX) != Total -> contradiction NOT_EVALUABLE", lambda: series("B02", mods={"rx": {"RX#01": (3075, 200), "RX#02": (3075, 250)}}), "NOT_EVALUABLE", 4)
case("B10", "r2: exit packets > snapshot packets, drops equal -> accepted (packets after the last snapshot)", lambda: series("B10", mods={"eve_rx": {"RX#01": (3000, 200), "RX#02": (3070, 258)}}), "DEMONSTRATED", 5)
case("B11", "r2: exit packets < snapshot packets -> contradiction -> NOT_EVALUABLE", lambda: series("B11", mods={"eve_rx": {"RX#01": (3100, 200), "RX#02": (3075, 258)}}), "NOT_EVALUABLE", 4)
case("B12", "r2: eve per-RX only in an event NOT simultaneous with the final stats.log record -> NOT_EVALUABLE", lambda: series("B12", mods={"eve_shift": 8}), "NOT_EVALUABLE", 4)
case("B13", "r2: log per-RX only (no eve threads) -> primary source missing -> NOT_EVALUABLE", lambda: series("B13", mods={"eve_rx": "NOEVE"}), "NOT_EVALUABLE", 4)
case("B14", "r2: two simultaneous eve events with different per-RX values -> NOT_EVALUABLE", lambda: series("B14", mods={"eve_dup": {"RX#01": (3075, 201), "RX#02": (3075, 257)}}), "NOT_EVALUABLE", 4)
case("B03", "log and eve per-RX disagree", lambda: series("B03", mods={"eve_rx": {"RX#01": (3075, 210), "RX#02": (3075, 248)}}), "NOT_EVALUABLE", 4)
case("B04", "no per-RX source at all", lambda: series("B04", mods={"rx": None, "log": slog({})}), "NOT_EVALUABLE", 4)
case("B05", "per-RX value non-ASCII / invalid", lambda: series("B05", mods={"rx": None, "log": slog({}) + "x - <Perf> - (RX#01) Kernel: Packets 3075, dropped ٢٠٠\nx - <Perf> - (RX#02) Kernel: Packets 3075, dropped 258\n"}), "NOT_EVALUABLE", 4)
case("B06", "per-RX duplicated with different values", lambda: series("B06", mods={"rx": None, "log": slog(OK_RX) + "x - <Perf> - (RX#01) Kernel: Packets 3075, dropped 199\n"}), "NOT_EVALUABLE", 4)
case("B07", "per-RX dropped > packets", lambda: series("B07", mods={"rx": {"RX#01": (100, 200), "RX#02": (3075, 258)}}), "NOT_EVALUABLE", 4)
case("B08", "three RX threads (count != sockets)", lambda: series("B08", mods={"rx": {"RX#01": (2000, 150), "RX#02": (2000, 150), "RX#03": (2150, 158)}}), "NOT_EVALUABLE", 4)
case("C01", "residual > 0 with flush disabled -> sourced refutation (c)", lambda: series("C01", mods={"residual0": False}), "REFUTED", 3)
case("C02", "flush declared enabled -> (c) NOT_EVALUABLE", lambda: series("C02"), "NOT_EVALUABLE", 4, flush="enabled")
case("C03", "flush unknown -> (c) NOT_EVALUABLE", lambda: series("C03"), "NOT_EVALUABLE", 4, flush="unknown")
case("C04", "flush declared disabled but log says enabled -> contradiction", lambda: series("C04", mods={"log": slog(OK_RX, extra="x - <Info> - Enabling ring emergency flush on iface ens7\n")}), "NOT_EVALUABLE", 4)
case("C05", "negative residual (decoder > kp - kd)", lambda: (series("C05"), _edit_dec("C05", +5))[0], "NOT_EVALUABLE", 4)
case("C06", "decoder.pkts absent from last record", lambda: (series("C06"), _edit_dec("C06", None))[0], "NOT_EVALUABLE", 4)
case("K01", "collection INCOMPLETE", lambda: series("K01", mods={"status": "INCOMPLETE absent:suricata.log"}), "NOT_EVALUABLE", 4)
case("K02", "ENGINE_EXTRA_STATUS absent", lambda: series("K02", mods={"status": None}), "NOT_EVALUABLE", 4)
case("K03", "file altered after collection (sha mismatch)", lambda: (series("K03"), _append("K03", "engine_extra/suricata.log", "tampered\n"))[0], "NOT_EVALUABLE", 4)
case("K04", "engine_stop STOPPED_FORCED", lambda: series("K04", mods={"stop": "ARCHIVIRT_ENGINE=STOPPED_FORCED\n"}), "NOT_EVALUABLE", 4,
     check=lambda r: any("STOPPED_FORCED" in f for f in [x for rr in r["runs"] for x in rr["flags"]]))
case("K05", "engine_stop.txt absent", lambda: series("K05", mods={"stop": None}), "NOT_EVALUABLE", 4)
case("K07", "stop status absent although per-RX available from eve -> NOT_EVALUABLE (evidence incomplete)", lambda: series("K07", mods={"stop": None, "rx": None, "log": slog({}), "eve_rx": OK_RX}), "NOT_EVALUABLE", 4)
case("K06", "suricata.log truncated (no final newline)", lambda: series("K06", mods={"log": slog(OK_RX).rstrip("\n")}), "NOT_EVALUABLE", 4)
case("S01", "stats.log truncated (PATCH-1r1)", lambda: (series("S01"), _trunc("S01", "stats.log"))[0], "NOT_EVALUABLE", 4)
case("S02", "coverage: last stats before attack end (PATCH-2r1)", lambda: (series("S02"), _write("S02", "attack_times.txt", "2026-10-22T18:33:37.7Z\n2026-10-22T18:33:59.0Z\n"))[0], "NOT_EVALUABLE", 4)
case("S03", "eve.json absent (coverage + eve per-RX)", lambda: (series("S03"), _rm("S03", "eve.json"))[0], "NOT_EVALUABLE", 4)
case("S04", "no-drop run with incomplete evidence still blocks (a)", lambda: series("S04", nodrop_mods={"status": "INCOMPLETE ansible_rc=4"}), "NOT_EVALUABLE", 4)
case("G01", "M3 guard: stats write inside burst window -> FLAG only", lambda: (series("G01"), _eve_ts("G01"))[0], "DEMONSTRATED", 5,
     check=lambda r: any(f.startswith("M3") for rr in r["runs"] for f in rr["flags"]))
case("H01", "historical D0 copies as-is (no engine_extra) never favourable", lambda: _hist("H01"), "NOT_EVALUABLE", 4)

def _run_dir(name, base="SCN-001-RUN-002"): return os.path.join(WK, name, "ids", "SCN-001", base)
def _edit_dec(name, delta):
    p = os.path.join(_run_dir(name), "stats.log"); st = open(p).read(); recs = re.split(r"(?m)(?=^-{10,}\nDate:)", st)
    if delta is None: recs[-1] = re.sub(r"(?m)^decoder\.pkts\s+\|\s+Total.*\n", "", recs[-1])
    else: recs[-1] = re.sub(r"(decoder\.pkts\s+\|\s+Total\s+\|\s+)(\d+)", lambda m: m.group(1) + str(int(m.group(2)) + delta), recs[-1])
    open(p, "w").write("".join(recs))
def _append(name, f, s): open(os.path.join(_run_dir(name), f), "a").write(s)
def _trunc(name, f): p = os.path.join(_run_dir(name), f); t = open(p).read(); open(p, "w").write(t[:-3])
def _write(name, f, s): open(os.path.join(_run_dir(name), f), "w").write(s)
def _rm(name, f): os.remove(os.path.join(_run_dir(name), f))
def _eve_ts(name):
    p = os.path.join(_run_dir(name), "eve.json"); at = open(os.path.join(_run_dir(name), "attack_times.txt")).read().split()
    L = open(p).readlines(); i = min(k for k, l in enumerate(L) if '"event_type":"stats"' in l)
    e = json.loads(L[i]); e["timestamp"] = at[0][:19] + ".900000+0000"; L[i] = json.dumps(e, separators=(",", ":")) + "\n"; open(p, "w").writelines(L)
def _hist(name):
    for b in ("SCN-001-RUN-001", "SCN-001-RUN-002", "SCN-001-RUN-008", "SCN-001-RUN-009"):
        shutil.copytree(os.path.join(SRC, b), os.path.join(WK, name, "ids", "SCN-001", b))
    return os.path.join(WK, name)

src_before = {os.path.join(dp, f): sha(os.path.join(dp, f)) for dp, _, fs in os.walk(SRC) for f in fs}
built = {}
for tid, desc, mk, flush, exp, rc, check in CASES:
    ser = mk(); built[tid] = (ser, flush)
    got_rc, res, err = run_ev(ser, flush)
    ok = V(res) == exp and got_rc == rc and (check is None or check(res))
    rec(tid, desc + " -> expected %s/rc%d" % (exp, rc), ok, "got %s/rc%d %s" % (V(res), got_rc, (res or {}).get("why", err)))

# ---- output / evidence safety ----
ser = built["N01"][0]
rc, _, err = run_ev(ser, out=os.path.join(ser, "ids", "out.json"))
rec("O01", "refuses an output path inside the series", rc == 2 and not os.path.exists(os.path.join(ser, "ids", "out.json")), err.strip())
o = os.path.join(WK, "exists.json"); open(o, "w").write("{}")
rc, _, err = run_ev(ser, out=o)
rec("O02", "never overwrites an existing output", rc == 2 and open(o).read() == "{}", err.strip())
before = {os.path.join(dp, f): sha(os.path.join(dp, f)) for dp, _, fs in os.walk(ser) for f in fs}
run_ev(ser); after = {os.path.join(dp, f): sha(os.path.join(dp, f)) for dp, _, fs in os.walk(ser) for f in fs}
rec("O03", "series files unchanged by an evaluation", before == after)
bad = os.path.join(WK, "badcrit.json"); open(bad, "w").write('{"schema":"x"}')
rc, _, _ = run_ev(ser, crit=bad); rec("O04", "criteria with wrong schema -> usage error rc 2", rc == 2)
appr = os.path.join(WK, "approved_copy.json"); c = json.load(open(CRIT)); c["status"] = "APPROVED"; json.dump(c, open(appr, "w"))
rc, res, _ = run_ev(ser, crit=appr); rec("O05", "rc 0 only when criteria APPROVED (copy for test) and DEMONSTRATED", rc == 0 and res["provisional"] is False)
ev2 = os.path.join(WK, "evcopy"); shutil.copytree(EVD, ev2, ignore=shutil.ignore_patterns("tests", "__pycache__")); open(os.path.join(ev2, "vendor", "archivirt_stopwatch_eval.py"), "a").write("# x\n")
rc, _, err = run_ev(ser, evaluator=os.path.join(ev2, "ta_evaluator.py")); rec("O06", "altered vendored parser -> INTEGRITY_ERROR rc 2", rc == 2 and "INTEGRITY" in err)
res = run_ev(built["N01"][0])[1]; d = runst(res, "SCN-001-RUN-002", "contention_patch6")
rec("O07", "PATCH-6 deltas reported descriptively (no verdict effect)", d == {"rx_01": {"run_ns": 50, "wait_ns": 90}, "rx_02": {"run_ns": 60, "wait_ns": 80}}, str(d))
src_after = {os.path.join(dp, f): sha(os.path.join(dp, f)) for dp, _, fs in os.walk(SRC) for f in fs}
rec("O08", "source copies unchanged by the whole suite", src_before == src_after)

# ---- counter-proof: weakened evaluators must be detected ----
def mutant(old, new):
    d = os.path.join(WK, "mut%d" % len([x for x in os.listdir(WK) if x.startswith("mut")])); shutil.copytree(EVD, d, ignore=shutil.ignore_patterns("tests", "__pycache__"))
    p = os.path.join(d, "ta_evaluator.py"); s = open(p).read(); assert s.count(old) == 1, old; open(p, "w").write(s.replace(old, new)); return p
MUTANTS = {
    "missing evidence ignored (no downgrade)": ('    if r["reasons"]:\n        for k in', '    if False:\n        for k in'),
    "no-drop series accepted": ('crit["TA_series"]["requires_at_least_one_drop_run"]: why', 'False: why'),
    "sum(RX) check removed": ('elif sum(v[1] for v in rows.values()) != kd:', 'elif False:'),
    "one-RX drop accepted": ('elif all(v[1] > 0 for v in rows.values()): b = MET', 'elif any(v[1] > 0 for v in rows.values()): b = MET'),
    "flush prerequisite ignored": ('if flush != "disabled": c = NE;', 'if False: c = NE;'),
    "collection status ignored": ('extra_ok = x["status"] == "COMPLETE" and not x["problems"]', 'extra_ok = True'),
    "sha verification skipped": ('if os.path.isfile(p) and sha(p) == m.group(1): out["verified"]', 'if os.path.isfile(p): out["verified"]'),   # attempt 1 left an orphan else (syntax error = trivially caught)
    "zero-copy check removed": ('elif g["zero_copy_message_must_be_absent"] and re.search(r"enabling zero copy mode", log): a = NOT_MET', 'elif False: a = NOT_MET'),
    "r2 per-RX drop disagreement ignored": ('elif any(l_rows[n][1] != e_rows[n][1] for n in e_rows):', 'elif False:'),
    "r2 non-simultaneous eve accepted": ('            if t == target_epoch: found.append(e)', '            found.append(e)'),
    "r2 exit packets < snapshot accepted": ('elif any(l_rows[n][0] < e_rows[n][0] for n in e_rows):', 'elif False:'),
    "stop status ignored": ('if stop is None or "STOPPED_CLEAN" not in stop:', 'if False:'),
    "provisional treated as approved": ('return 0 if not res["provisional"] else 5', 'return 0'),
}
KEY = [c for c in CASES if c[0] not in ("O",)]
for name, (old, new) in MUTANTS.items():
    mp = mutant(old, new); caught = []
    comp = subprocess.run([sys.executable, "-I", "-c", "import ast,sys; ast.parse(open(sys.argv[1]).read())", mp]).returncode
    if comp: rec("CP", "mutant is valid Python: %s" % name, False, "syntax error in mutant (test defect)"); continue
    for tid, desc, mk, flush, exp, rc, check in KEY:
        ser, fl = built[tid]; got_rc, res, _ = run_ev(ser, fl, evaluator=mp)
        if not (V(res) == exp and got_rc == rc and (check is None or check(res))): caught.append(tid)
    rec("CP", "weakened evaluator detected: %s" % name, bool(caught), "caught by %s" % caught[:6])

json.dump(results, open(OUT, "w"), indent=1)
nf = sum(r["result"] == "FAIL" for r in results); print("TOTAL %d tests: %d PASS, %d FAIL" % (len(results), len(results) - nf, nf)); sys.exit(1 if nf else 0)
