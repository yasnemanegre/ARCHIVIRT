#!/usr/bin/env python3
"""ARCHIVIRT campaign_v1 — campaign outcome record (PROPOSED 2026-10-21; target scripts/campaign_v1/).

Written by campaign_v1.sh cleanup() on EVERY exit path once the campaign directory exists:
<campaign_dir>/campaign_outcome.json (never overwritten). Outcome classes:
  COMPLETED                  normal end, every run VALID
  COMPLETED_WITH_INVALID_RUNS normal end, >= 1 non-valid run (each recorded; conformity in campaign_acceptance.json)
  ABORTED_BY_CAMPAIGN        controlled abort decided by the campaign (stop_immediate, recorder failure, ...) after its normal tail
  REFUSED_PRECONDITION       explicit refusal BEFORE the lab is modified (--phase precondition + abort reason: offline gate,
                             lab state, clock, provenance); no run was started (P2-DIAG1 D0, 2026-10-22)
  INTERRUPTED_BY_SIGNAL      SIGINT / SIGTERM / SIGHUP
  ABNORMAL_EXIT              any other exit (set -e error, explicit exit N before the tail)
recovery: the recovery.json status (RECOVERED / RECOVERY_FAILED), NOT_NEEDED for a normal end; without recovery.json:
  TIMED_OUT (campaign_recover.sh exit 124), INCOMPLETE (it ran, other exit status), NOT_RUN (--recovery-rc none),
  MISSING (exit status unknown: caller without --recovery-rc). INCONSISTENT if recovery.json disagrees with the exit status
  (campaign_recover.sh exits 0 iff RECOVERED). recovery_exit_status records that exit status (null if not run / unknown).
Usage: campaign_outcome.py --campaign-dir D --done 0|1 --rc N [--abort-reason R] [--signal S] [--reached-tail 0|1]
       [--phase precondition|runs] [--recovery-rc N|none]
"""
import argparse, json, os, re, sys, datetime

RUN_RE = re.compile(r"^SCN-\d{3}-RUN-\d{3}$")

def runs(cd):
    v = nv = 0
    for root, dirs, files in os.walk(cd):
        if RUN_RE.match(os.path.basename(root)):
            try: r = json.load(open(os.path.join(root, "result.json")))
            except Exception: r = None
            sc = r.get("stop_criteria") if isinstance(r, dict) and isinstance(r.get("stop_criteria"), dict) else {}
            if isinstance(r, dict) and r.get("run_status") == "VALID" and sc.get("evaluated") is True and sc.get("verdict") == "VALID": v += 1
            else: nv += 1
    return v, nv

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign-dir", required=True); ap.add_argument("--done", required=True, choices=("0", "1"))
    ap.add_argument("--rc", required=True, type=int); ap.add_argument("--abort-reason", default=""); ap.add_argument("--signal", default="")
    ap.add_argument("--reached-tail", default="0", choices=("0", "1"))
    ap.add_argument("--phase", default="", choices=("", "precondition", "runs")); ap.add_argument("--recovery-rc", default="")
    a = ap.parse_args()
    out = os.path.join(a.campaign_dir, "campaign_outcome.json")
    if os.path.exists(out): print("REFUSED: %s exists" % out, file=sys.stderr); return 2
    v, nv = runs(a.campaign_dir)
    if a.done == "1": outcome = "COMPLETED_WITH_INVALID_RUNS" if nv else "COMPLETED"
    elif a.signal: outcome = "INTERRUPTED_BY_SIGNAL"
    elif a.abort_reason and a.reached_tail == "1": outcome = "ABORTED_BY_CAMPAIGN"
    elif a.abort_reason and a.phase == "precondition" and v + nv == 0: outcome = "REFUSED_PRECONDITION"
    else: outcome = "ABNORMAL_EXIT"
    rec = os.path.join(a.campaign_dir, "recovery.json")
    rrc = int(a.recovery_rc) if a.recovery_rc.isdigit() else None
    if a.done == "1": recovery = "NOT_NEEDED"
    elif os.path.exists(rec):
        try: recovery = json.load(open(rec)).get("status", "UNREADABLE")
        except Exception: recovery = "UNREADABLE"
        if rrc is not None and recovery in ("RECOVERED", "RECOVERY_FAILED") and (rrc == 0) != (recovery == "RECOVERED"): recovery = "INCONSISTENT"
    elif rrc == 124: recovery = "TIMED_OUT"
    elif rrc is not None: recovery = "INCOMPLETE"
    elif a.recovery_rc == "none": recovery = "NOT_RUN"
    else: recovery = "MISSING"
    doc = {"schema": "archivirt-campaign-outcome/1", "outcome": outcome, "exit_status": a.rc, "signal": a.signal or None,
           "abort_reason": a.abort_reason or None, "runs_valid": v, "runs_non_valid": nv, "recovery": recovery,
           "recovery_exit_status": rrc, "phase": a.phase or None, "ts": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}
    with open(out, "x") as f: json.dump(doc, f, indent=1)
    print("ARCHIVIRT_OUTCOME=%s recovery=%s recovery_rc=%s runs_valid=%d runs_non_valid=%d%s" % (outcome, recovery,
          "-" if rrc is None else rrc, v, nv, (" abort_reason=" + a.abort_reason) if a.abort_reason else ""))
    return 0

if __name__ == "__main__":
    sys.exit(main())
