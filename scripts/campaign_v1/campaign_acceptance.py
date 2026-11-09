#!/usr/bin/env python3
"""ARCHIVIRT P2-VAL2 — per-scenario conformity and campaign acceptance (PROPOSED v2; target: scripts/campaign_v1/campaign_acceptance.py).

Read-only on the campaign directory. Writes ONE new file (--out, refused if it exists) and, optionally, a
"primary view" directory (--primary-view, new, outside the campaign directory) holding COPIES of result.json /
perf.json of the primary runs, so that the unchanged analyze.py can run on the primary selection only.

Approved rule (owner decision 2026-10-21):
  per scenario: at most --max-runs runs (13); CONFORM iff  valid >= --min-valid (10)  AND  non_valid <= --max-invalid (2).
  A run is VALID only if result.json run_status == "VALID" AND its stop_criteria block was evaluated with verdict VALID.
  Every other run (INVALID, PREREQUISITE_MISSING, unreadable, no stop_criteria) is NON-VALID and counts against --max-invalid.
  Primary analysis = the first --min-valid VALID runs in run-number order; later VALID runs = supplementary (reported apart).
C1 rate rules are evaluated SEPARATELY and reported as such (never merged with the count rule):
  c1_scenario_rate: non_valid / runs <= 20 % per scenario;  c1_campaign_rate: non_valid / runs <= 10 % over the campaign.
  Owner decision D-C1 (2026-11-09, option A, not retroactive): with exactly one scenario c1_campaign_rate is NOT_APPLICABLE and leaves
  the verdict rules (10 % would otherwise mean "at most 1 non-valid of 13" and contradict the approved 13/10/2); the rate stays reported.
Other campaign rules (C1 §4): frozen guard (manual), ids_deployed, declared memory, egress hash, clock, OOM.
Every rule status is PASS, FAIL or NOT_EVALUATED (P1, 2026-10-28). PASS needs positive evidence: a rule whose input is
absent, unreadable or partial is NOT_EVALUATED, never PASS. campaign_verdict: NOT_ACCEPTED if any rule FAILs (a FAIL is
never hidden by a missing rule), else NOT_EVALUATED if any rule is NOT_EVALUATED, else ACCEPTED; the lists rules_failed /
rules_not_evaluated say which. The rules and thresholds themselves are unchanged.
Also: fn_not_masked — FAIL if any NON-VALID run is non-valid ONLY because an observed attack was not detected
(validate_run reason "attack scenario produced no matching EVE alert"; happens with ARCHIVIRT_SCORING=article2).
--count SCENARIO_DIR prints "<valid> <non_valid>" for one scenario directory (same validity definition) and exits;
campaign_v1.sh uses it for the adaptive stop.
Exit: 0 every scenario CONFORM, 3 otherwise, 2 usage error.
"""
import argparse, json, os, re, shutil, sys
from collections import defaultdict

RUN_RE = re.compile(r"^(SCN-\d{3})-RUN-(\d{3})$")
FN_AS_INVALID = "attack scenario produced no matching EVE alert"

def is_valid(r):
    if not isinstance(r, dict): return False
    sc = r.get("stop_criteria") if isinstance(r.get("stop_criteria"), dict) else {}
    return r.get("run_status") == "VALID" and sc.get("evaluated") is True and sc.get("verdict") == "VALID"

def oom_status(r):
    sc = r.get("stop_criteria") if isinstance(r, dict) and isinstance(r.get("stop_criteria"), dict) else {}
    return ((sc.get("criteria") or {}).get("host_oom_kill") or {}).get("status")    # CONFIRMED / NOT_EXCEEDED / NOT_EVALUABLE / NOT_APPLICABLE / None

def count_dir(d):
    v = nv = 0
    for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if RUN_RE.match(name) and os.path.isdir(os.path.join(d, name)):
            if is_valid(load(os.path.join(d, name, "result.json"))): v += 1
            else: nv += 1
    return v, nv

def load(p):
    try: return json.load(open(p))
    except Exception: return None

def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--count":
        print("%d %d" % count_dir(sys.argv[2])); return 0
    ap = argparse.ArgumentParser()
    ap.add_argument("campaign_dir")
    ap.add_argument("--max-runs", type=int, required=True); ap.add_argument("--min-valid", type=int, required=True)
    ap.add_argument("--max-invalid", type=int, required=True)
    ap.add_argument("--scenario-rate-max", type=float, default=0.20); ap.add_argument("--campaign-rate-max", type=float, default=0.10)
    ap.add_argument("--declared-mem"); ap.add_argument("--egress-sha"); ap.add_argument("--ids-after")
    ap.add_argument("--manual", action="append", default=[])
    ap.add_argument("--out", required=True); ap.add_argument("--primary-view")
    a = ap.parse_args()
    try: dec_mem = {k.strip(): int(x) for k, x in (i.split("=") for i in a.declared_mem.split(","))} if a.declared_mem else None
    except ValueError: print("USAGE_ERROR: --declared-mem must be domain=MiB[,domain=MiB...]", file=sys.stderr); return 2
    if not (1 <= a.min_valid <= a.max_runs and 0 <= a.max_invalid and a.min_valid + a.max_invalid <= a.max_runs):
        print("USAGE_ERROR: need 1 <= min_valid <= max_runs and min_valid + max_invalid <= max_runs", file=sys.stderr); return 2
    cd = os.path.realpath(a.campaign_dir)
    if os.path.exists(a.out): print("REFUSED: %s exists (never overwritten)" % a.out, file=sys.stderr); return 2
    if a.primary_view:
        pv = os.path.realpath(a.primary_view)
        if os.path.exists(pv) or pv == cd or pv.startswith(cd + os.sep):
            print("REFUSED: --primary-view must be a new directory outside the campaign directory", file=sys.stderr); return 2

    scen = defaultdict(list)      # (mode, scenario) -> runs
    for root, dirs, files in os.walk(cd):
        m = RUN_RE.match(os.path.basename(root))
        if not m: continue
        r = load(os.path.join(root, "result.json"))
        sc = (r.get("stop_criteria") if isinstance(r, dict) else None) or {}
        status = (r or {}).get("run_status", "MISSING_RESULT") if isinstance(r, dict) else "UNREADABLE_RESULT"
        valid = is_valid(r)
        reason = None if valid else ((r or {}).get("invalid_reason") if isinstance(r, dict) else None) or (
            "stop_criteria not evaluated / verdict %s" % sc.get("verdict") if status == "VALID" else status)
        mode = (r or {}).get("mode") if isinstance(r, dict) else None
        mode = mode or os.path.basename(os.path.dirname(os.path.dirname(root)))
        scen[(mode, m.group(1))].append({"run_id": os.path.basename(root), "index": int(m.group(2)), "path": os.path.relpath(root, cd),
                                           "run_status": status, "valid": valid, "reason": reason,
                                           "stop_criteria_verdict": sc.get("verdict"), "params_sha256": sc.get("params_sha256"),
                                           "classification": (r or {}).get("classification") if isinstance(r, dict) else None})
    per, all_ok, tot_runs, tot_nonvalid = {}, True, 0, 0
    for (mode, s), runs in sorted(scen.items()):
        if mode == "baseline": continue
        runs.sort(key=lambda x: x["index"])
        v = [x for x in runs if x["valid"]]; nv = [x for x in runs if not x["valid"]]
        idx = [x["index"] for x in runs]
        reasons = []
        if len(runs) > a.max_runs: reasons.append("more runs (%d) than --max-runs %d" % (len(runs), a.max_runs))
        if len(set(idx)) != len(idx): reasons.append("duplicate run index")
        if len(v) < a.min_valid: reasons.append("insufficient valid runs: %d < %d" % (len(v), a.min_valid))
        if len(nv) > a.max_invalid: reasons.append("too many non-valid runs: %d > %d" % (len(nv), a.max_invalid))
        conform = not reasons
        all_ok &= conform; tot_runs += len(runs); tot_nonvalid += len(nv)
        rate = len(nv) / len(runs) if runs else None
        per["%s/%s" % (mode, s)] = {
            "status": "CONFORM" if conform else "NON_CONFORM", "reasons": reasons, "runs": len(runs), "valid": len(v), "non_valid": len(nv),
            "primary_runs": [x["run_id"] for x in v[:a.min_valid]] if conform else [],          # only a CONFORM scenario feeds the primary analysis
            "supplementary_valid_runs": [x["run_id"] for x in v[a.min_valid:]] if conform else [],
            "first_valid_runs_for_information": [x["run_id"] for x in v[:a.min_valid]],
            "non_valid_runs": [{"run_id": x["run_id"], "run_status": x["run_status"], "reason": x["reason"]} for x in nv],
            "c1_scenario_rate": {"non_valid_rate": round(rate, 4) if rate is not None else None, "max": a.scenario_rate_max,
                                 "status": "NOT_EVALUATED" if rate is None else ("PASS" if rate <= a.scenario_rate_max else "FAIL")},
            "runs_detail": runs}
    if not per: all_ok = False
    camp_rate = tot_nonvalid / tot_runs if tot_runs else None
    prov = load(os.path.join(cd, "provenance_v2.json")) or {}; lab = load(os.path.join(cd, "lab_state.json")) or prov.get("lab_state") or {}
    man = dict(m.split("=", 1) for m in a.manual if "=" in m); g = man.get("frozen_guard", "")
    other = {"frozen_guard": {"status": "PASS" if g.startswith("PASS:") and len(g) > 5 else ("FAIL" if g.startswith("FAIL:") else "NOT_EVALUATED"),
                              "evidence": g[5:] or None}}
    if a.ids_after:
        after, before = load(a.ids_after), prov.get("ids_deployed")
        fa, fb = (after or {}).get("files") if isinstance(after, dict) else None, (before or {}).get("files") if isinstance(before, dict) else None
        other["ids_deployed_unchanged"] = {"status": ("PASS" if fa == fb else "FAIL") if fa and fb else "NOT_EVALUATED",
                                           "before_recorded": bool(fb), "after_readable": bool(fa)}
    else: other["ids_deployed_unchanged"] = {"status": "NOT_EVALUATED"}
    if dec_mem is not None:
        got = {d: v.get("current_mib") if isinstance(v, dict) else None for d, v in (lab.get("domains") or {}).items()}
        bad = {d: [got[d], m] for d, m in dec_mem.items() if got.get(d) is not None and got[d] != m}
        missing = sorted(d for d in dec_mem if got.get(d) is None)
        other["declared_memory"] = {"status": "FAIL" if bad else ("NOT_EVALUATED" if missing or not dec_mem else "PASS"),
                                    "mismatch_found_declared": bad, "not_observed": missing}
    else: other["declared_memory"] = {"status": "NOT_EVALUATED"}
    eg = (lab.get("egress_policy") or {}).get("sha256_without_counters")
    other["egress_policy"] = {"status": ("PASS" if eg == a.egress_sha else "FAIL") if a.egress_sha and eg else "NOT_EVALUATED", "found": eg, "declared": a.egress_sha}
    cc = lab.get("clock_check") or {}
    other["clock"] = {"status": "PASS" if cc.get("status") == "OK" else ("FAIL" if cc.get("status") else "NOT_EVALUATED"),
                      "clock_check": cc.get("status"), "worst_abs_offset_ms": cc.get("worst_abs_offset_ms"), "max_abs_offset_ms": cc.get("max_abs_offset_ms")}
    all_runs = [x for runs in scen.values() for x in runs]
    oom = {x["run_id"]: oom_status(load(os.path.join(cd, x["path"], "result.json"))) for x in all_runs}
    oom_hit = sorted(k for k, v in oom.items() if v == "CONFIRMED"); oom_unk = sorted(k for k, v in oom.items() if v != "NOT_EXCEEDED" and v != "CONFIRMED")
    other["no_host_oom"] = {"status": "FAIL" if oom_hit else ("NOT_EVALUATED" if oom_unk or not all_runs else "PASS"),
                            "oom_runs": oom_hit, "runs_without_oom_evidence": oom_unk}
    masked = [x["run_id"] for x in all_runs if not x["valid"] and FN_AS_INVALID in (x["reason"] or "")]
    unknown = sorted(x["run_id"] for x in all_runs if x["run_status"] in ("MISSING_RESULT", "UNREADABLE_RESULT"))   # reason unknowable
    other["fn_not_masked"] = {"status": "FAIL" if masked else ("NOT_EVALUATED" if unknown or not all_runs else "PASS"),
                              "fn_runs_counted_as_non_valid": masked, "runs_without_result": unknown}
    for k, v in per.items():
        cls = lambda ids: {c: sum(1 for x in v["runs_detail"] if x["run_id"] in ids and x["classification"] == c) for c in ("TP", "FN", "TN", "FP")}
        v["classification_primary"] = cls(set(v["primary_runs"])); v["classification_all_valid"] = cls({x["run_id"] for x in v["runs_detail"] if x["valid"]})
    c1_campaign = {"non_valid_rate": round(camp_rate, 4) if camp_rate is not None else None, "max": a.campaign_rate_max,
                   "status": "NOT_EVALUATED" if camp_rate is None else ("PASS" if camp_rate <= a.campaign_rate_max else "FAIL")}
    if len(per) == 1: c1_campaign.update(status="NOT_APPLICABLE", reason="single-scenario campaign (owner decision D-C1, option A, 2026-11-09)")
    rules = {"scenario_conformity": "NOT_EVALUATED" if not per else ("PASS" if all_ok else "FAIL")}
    if c1_campaign["status"] != "NOT_APPLICABLE": rules["c1_campaign_rate"] = c1_campaign["status"]
    rules.update(("c1_scenario_rate:" + k, v["c1_scenario_rate"]["status"]) for k, v in per.items())
    rules.update(("other:" + k, v["status"]) for k, v in other.items())
    failed = sorted(k for k, v in rules.items() if v == "FAIL")
    not_eval = sorted(k for k, v in rules.items() if v != "PASS" and v != "FAIL")      # anything not PASS/FAIL counts as NOT_EVALUATED
    verdict = "NOT_ACCEPTED" if failed else ("NOT_EVALUATED" if not_eval else "ACCEPTED")
    doc = {"schema": "archivirt-campaign-acceptance/3-PROPOSED", "campaign_dir": cd,
           "rule": {"max_runs": a.max_runs, "min_valid": a.min_valid, "max_invalid": a.max_invalid,
                    "valid_definition": "run_status VALID and stop_criteria evaluated with verdict VALID",
                    "primary": "first min_valid VALID runs in run-number order; later VALID runs are supplementary"},
           "scenarios": per, "all_scenarios_conform": all_ok,
           "c1_rate_rules": {"scenario_rate_max": a.scenario_rate_max, "campaign": c1_campaign,
                             "scenarios_failing_rate": sorted(k for k, v in per.items() if v["c1_scenario_rate"]["status"] != "PASS")},
           "other_rules": other, "stop_criteria": prov.get("stop_criteria"),
           "rules": rules, "rules_failed": failed, "rules_not_evaluated": not_eval,
           "verdict_definition": "NOT_ACCEPTED if any rule FAIL; else NOT_EVALUATED if any rule NOT_EVALUATED; else ACCEPTED",
           "campaign_verdict": verdict}
    with open(a.out, "x") as f: json.dump(doc, f, indent=1, sort_keys=True); f.write("\n")
    if a.primary_view:
        os.makedirs(pv)
        for k, v in per.items():
            for rid in v["primary_runs"]:
                src = os.path.join(cd, next(x["path"] for x in scen[tuple(k.split("/"))] if x["run_id"] == rid))
                dst = os.path.join(pv, os.path.relpath(src, cd)); os.makedirs(dst)
                for fn in ("result.json", "perf.json"):
                    if os.path.exists(os.path.join(src, fn)): shutil.copy2(os.path.join(src, fn), dst)
        with open(os.path.join(pv, "PRIMARY_VIEW.json"), "x") as f:
            json.dump({"source_campaign": cd, "acceptance": os.path.abspath(a.out), "primary_runs": {k: v["primary_runs"] for k, v in per.items()}}, f, indent=1)
    print(json.dumps({"all_scenarios_conform": all_ok, "campaign_verdict": verdict, "rules_failed": failed, "rules_not_evaluated": not_eval,
                      "scenarios": {k: [v["status"], v["valid"], v["non_valid"]] for k, v in per.items()}}))
    return 0 if all_ok else 3

if __name__ == "__main__":
    sys.exit(main())
