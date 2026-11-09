#!/usr/bin/env python3
"""Isolated tests of the PASS / FAIL / NOT_EVALUATED verdict of campaign_acceptance.py (P1, 2026-10-28; no lab, no network).
Synthetic campaigns are built in a temporary directory. Invariants checked on every case: ACCEPTED iff every rule PASS;
NOT_ACCEPTED iff at least one rule FAIL; a missing or partial input never yields PASS. A counter-proof runs the cases against
deliberately weakened copies of the evaluator: each weakening must be detected.
Usage: test_acceptance_tristate.py <campaign_acceptance.py> [out_json]   -> rc 0 iff all PASS"""
import json, os, subprocess, sys, tempfile
sys.dont_write_bytecode = True
EV = os.path.abspath(sys.argv[1]); OUT = sys.argv[2] if len(sys.argv) > 2 else None
results = []
def rec(tid, desc, ok, detail=""):
    results.append({"id": tid, "desc": desc, "result": "PASS" if ok else "FAIL", "detail": detail}); print("%-4s %s %s %s" % (tid, "PASS" if ok else "FAIL", desc, detail[:200]))

MEM = {"archivirt-monitor-ids": 2048, "archivirt-attacker": 1024}
EGRESS, FILES = "e" * 64, {"/etc/suricata/suricata.yaml": "a" * 64}

def run_json(oom="NOT_EXCEEDED", status="VALID", reason=None):
    r = {"run_status": status, "mode": "ids", "classification": "TP",
         "stop_criteria": {"evaluated": True, "verdict": status, "criteria": {"host_oom_kill": {"status": oom}} if oom else {}}}
    if reason: r["invalid_reason"] = reason
    return r

def build(root, runs, lab=True, prov=True, runs2=None):
    cd = os.path.join(root, "camp"); os.makedirs(cd)
    for scn, rs in (("SCN-001", runs), ("SCN-002", runs2 or [])):
        for i, r in enumerate(rs, 1):
            d = os.path.join(cd, "ids", scn, "%s-RUN-%03d" % (scn, i)); os.makedirs(d)
            if r == "UNREADABLE": open(os.path.join(d, "result.json"), "w").write("{not json")
            elif r is not None: json.dump(r, open(os.path.join(d, "result.json"), "w"))
    if lab is True: lab = {"domains": {d: {"current_mib": m} for d, m in MEM.items()}, "egress_policy": {"sha256_without_counters": EGRESS},
                           "clock_check": {"status": "OK"}}
    if lab: json.dump(lab, open(os.path.join(cd, "lab_state.json"), "w"))
    if prov: json.dump({"ids_deployed": prov if isinstance(prov, dict) else {"files": FILES}}, open(os.path.join(cd, "provenance_v2.json"), "w"))
    return cd

FULL = ["--manual", "frozen_guard=PASS:sha ok", "--declared-mem", ",".join("%s=%d" % kv for kv in MEM.items()), "--egress-sha", EGRESS]

def evaluate(ev, runs, args=FULL, ids_after=True, lab=True, prov=True, rule=(13, 10, 2), runs2=None):
    with tempfile.TemporaryDirectory() as t:
        cd = build(t, runs, lab, prov, runs2); extra = list(args)
        if ids_after:
            p = os.path.join(t, "ids_after.json"); json.dump(ids_after if isinstance(ids_after, dict) else {"files": FILES}, open(p, "w")); extra += ["--ids-after", p]
        out = os.path.join(t, "acc.json")
        cp = subprocess.run([sys.executable, "-B", "-I", ev, cd, "--max-runs", str(rule[0]), "--min-valid", str(rule[1]), "--max-invalid", str(rule[2]),
                             "--out", out] + extra, capture_output=True, text=True)
        return cp.returncode, (json.load(open(out)) if os.path.exists(out) else None)

def invariants(d):
    st = list(d["rules"].values())
    exp = "NOT_ACCEPTED" if "FAIL" in st else ("NOT_EVALUATED" if any(s != "PASS" for s in st) else "ACCEPTED")
    return d["campaign_verdict"] == exp and sorted(k for k, v in d["rules"].items() if v == "FAIL") == d["rules_failed"]

V10 = [run_json() for _ in range(10)]
# (id, description, kwargs, expected verdict, {rule: expected status})
CASES = [
    ("T1", "all evidence present and conforming", dict(runs=V10), "ACCEPTED", {"other:no_host_oom": "PASS"}),
    ("T2", "campaign_v1.sh l.548 call (no manual/ids/mem/egress args)", dict(runs=V10, args=[], ids_after=False), "NOT_EVALUATED",
     {"other:frozen_guard": "NOT_EVALUATED", "other:declared_memory": "NOT_EVALUATED", "other:egress_policy": "NOT_EVALUATED", "other:ids_deployed_unchanged": "NOT_EVALUATED"}),
    ("T3", "a FAIL is never hidden by NOT_EVALUATED rules", dict(runs=V10 + [run_json(status="INVALID")] * 3, args=[], ids_after=False), "NOT_ACCEPTED",
     {"scenario_conformity": "FAIL", "other:frozen_guard": "NOT_EVALUATED"}),
    ("T4", "ids_deployed: no files on either side (old code: None == None -> PASS)", dict(runs=V10, ids_after={"x": 1}, prov={"y": 1}), "NOT_EVALUATED",
     {"other:ids_deployed_unchanged": "NOT_EVALUATED"}),
    ("T5", "ids_deployed: files differ", dict(runs=V10, ids_after={"files": {"/etc/suricata/suricata.yaml": "b" * 64}}), "NOT_ACCEPTED",
     {"other:ids_deployed_unchanged": "FAIL"}),
    ("T6", "one run without host_oom_kill evidence (old code: PASS)", dict(runs=V10[:9] + [run_json(oom=None)]), "NOT_EVALUATED",
     {"other:no_host_oom": "NOT_EVALUATED"}),
    ("T7", "one run with OOM NOT_EVALUABLE", dict(runs=V10[:9] + [run_json(oom="NOT_EVALUABLE", status="INVALID")] + [run_json()]), "NOT_EVALUATED",
     {"other:no_host_oom": "NOT_EVALUATED", "scenario_conformity": "PASS"}),
    ("T8", "OOM CONFIRMED on one run", dict(runs=V10 + [run_json(oom="CONFIRMED", status="INVALID")]), "NOT_ACCEPTED", {"other:no_host_oom": "FAIL"}),
    ("T9", "unreadable result.json: fn_not_masked cannot be decided", dict(runs=V10 + ["UNREADABLE"]), "NOT_EVALUATED",
     {"other:fn_not_masked": "NOT_EVALUATED", "other:no_host_oom": "NOT_EVALUATED", "scenario_conformity": "PASS"}),
    ("T10", "FN counted as non-valid", dict(runs=V10 + [run_json(status="INVALID", reason="attack scenario produced no matching EVE alert")]), "NOT_ACCEPTED",
     {"other:fn_not_masked": "FAIL"}),
    ("T11", "egress declared, lab_state absent (old code: FAIL)", dict(runs=V10, lab=None), "NOT_EVALUATED",
     {"other:egress_policy": "NOT_EVALUATED", "other:declared_memory": "NOT_EVALUATED", "other:clock": "NOT_EVALUATED"}),
    ("T12", "egress hash differs", dict(runs=V10, args=FULL[:4] + ["--egress-sha", "f" * 64]), "NOT_ACCEPTED", {"other:egress_policy": "FAIL"}),
    ("T13", "declared memory: one domain not observed", dict(runs=V10, lab={"domains": {"archivirt-monitor-ids": {"current_mib": 2048}},
     "egress_policy": {"sha256_without_counters": EGRESS}, "clock_check": {"status": "OK"}}), "NOT_EVALUATED", {"other:declared_memory": "NOT_EVALUATED"}),
    ("T14", "declared memory: mismatch", dict(runs=V10, lab={"domains": {"archivirt-monitor-ids": {"current_mib": 1536}},
     "egress_policy": {"sha256_without_counters": EGRESS}, "clock_check": {"status": "OK"}}), "NOT_ACCEPTED", {"other:declared_memory": "FAIL"}),
    ("T15", "frozen_guard=FAIL:... is a FAIL (old code: NOT_EVALUATED)", dict(runs=V10, args=["--manual", "frozen_guard=FAIL:hash differs"] + FULL[2:]),
     "NOT_ACCEPTED", {"other:frozen_guard": "FAIL"}),
    ("T16", "frozen_guard=PASS: without evidence", dict(runs=V10, args=["--manual", "frozen_guard=PASS:"] + FULL[2:]), "NOT_EVALUATED",
     {"other:frozen_guard": "NOT_EVALUATED"}),
    ("T17", "empty campaign is never ACCEPTED", dict(runs=[]), "NOT_EVALUATED",
     {"scenario_conformity": "NOT_EVALUATED", "c1_campaign_rate": "NOT_EVALUATED", "other:no_host_oom": "NOT_EVALUATED"}),
    ("T18", "single scenario 10 valid + 2 invalid: C1 campaign rate not applicable (D-C1 option A)", dict(runs=V10 + [run_json(status="INVALID")] * 2),
     "ACCEPTED", {"scenario_conformity": "PASS", "c1_campaign_rate": None, "c1_scenario_rate:ids/SCN-001": "PASS"}),
    ("T18b", "single scenario 10 valid + 3 invalid: still refused", dict(runs=V10 + [run_json(status="INVALID")] * 3),
     "NOT_ACCEPTED", {"scenario_conformity": "FAIL", "c1_campaign_rate": None, "c1_scenario_rate:ids/SCN-001": "FAIL"}),
    ("T18c", "two scenarios: C1 campaign rate still applies (4/24 > 0.10)", dict(runs=V10 + [run_json(status="INVALID")] * 2, runs2=V10 + [run_json(status="INVALID")] * 2),
     "NOT_ACCEPTED", {"scenario_conformity": "PASS", "c1_campaign_rate": "FAIL"}),
    ("T18d", "two scenarios within the C1 campaign rate (2/22 <= 0.10)", dict(runs=V10 + [run_json(status="INVALID")], runs2=V10 + [run_json(status="INVALID")]),
     "ACCEPTED", {"c1_campaign_rate": "PASS"}),
]

def run_cases(ev, quiet=False):
    bad = []
    for tid, desc, kw, verdict, exp in CASES:
        rc, d = evaluate(ev, **kw)
        why = []
        if d is None: why.append("no output (rc %d)" % rc)
        else:
            if d["campaign_verdict"] != verdict: why.append("verdict %s != %s" % (d["campaign_verdict"], verdict))
            why += ["%s=%s != %s" % (k, d["rules"].get(k), v) for k, v in exp.items() if d["rules"].get(k) != v]
            if not invariants(d): why.append("verdict/rules invariant broken")
        if not quiet: rec(tid, desc, not why, "; ".join(why))
        if why: bad.append(tid)
    return bad

run_cases(EV)
with tempfile.TemporaryDirectory() as t:
    a = os.path.join(t, "a.json")
    cp = subprocess.run([sys.executable, "-B", "-I", EV, t, "--max-runs", "13", "--min-valid", "10", "--max-invalid", "2", "--out", a, "--declared-mem", "x=abc"],
                        capture_output=True, text=True)
    rec("T19", "malformed --declared-mem is a usage error (rc 2, no output)", cp.returncode == 2 and not os.path.exists(a), "rc %d" % cp.returncode)

# Counter-proof: each weakening of the evaluator must make at least one case fail.
SRC = open(EV).read()
WEAK = [("W1", "NOT_EVALUATED counted as PASS in the verdict", 'not_eval = sorted(k for k, v in rules.items() if v != "PASS" and v != "FAIL")', "not_eval = []"),
        ("W2", "NOT_EVALUATED wins over FAIL", 'verdict = "NOT_ACCEPTED" if failed else ("NOT_EVALUATED" if not_eval else "ACCEPTED")',
         'verdict = "NOT_EVALUATED" if not_eval else ("NOT_ACCEPTED" if failed else "ACCEPTED")'),
        ("W3", "OOM without evidence counted as PASS", '("NOT_EVALUATED" if oom_unk or not all_runs else "PASS")', '"PASS"'),
        ("W4", "ids_deployed None == None", '("PASS" if fa == fb else "FAIL") if fa and fb else "NOT_EVALUATED"', '"PASS" if fa == fb else "FAIL"'),
        ("W5", "frozen guard FAIL ignored", '("FAIL" if g.startswith("FAIL:") else "NOT_EVALUATED")', '"NOT_EVALUATED"'),
        ("W6", "unreadable runs ignored by fn_not_masked", '("NOT_EVALUATED" if unknown or not all_runs else "PASS")', '"PASS"'),
        ("W7", "C1 campaign rate exempted for every campaign", 'if len(per) == 1: c1_campaign.update', 'if True: c1_campaign.update'),
        ("W8", "C1 campaign rate never exempted", 'if len(per) == 1: c1_campaign.update', 'if False: c1_campaign.update')]
for wid, desc, old, new in WEAK:
    if SRC.count(old) != 1: rec(wid, "counter-proof: " + desc, False, "weakening anchor not found"); continue
    with tempfile.TemporaryDirectory() as t:
        p = os.path.join(t, "campaign_acceptance.py"); open(p, "w").write(SRC.replace(old, new))
        caught = run_cases(p, quiet=True)
    rec(wid, "counter-proof: " + desc, bool(caught), "detected by " + ",".join(caught))

n_fail = sum(1 for r in results if r["result"] != "PASS")
print("%d/%d PASS" % (len(results) - n_fail, len(results)))
if OUT: json.dump({"evaluator": EV, "results": results, "pass": len(results) - n_fail, "total": len(results)}, open(OUT, "x"), indent=1)
sys.exit(0 if n_fail == 0 else 1)
