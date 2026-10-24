#!/usr/bin/env python3
"""ARCHIVIRT — series provenance v2 (PROPOSAL C1.3). Wraps the UNCHANGED v1 provenance.json.

Refuses (case-insensitive) ARTICLE*/UNSET series and ARTICLE* campaign ids, any campaign
directory in a protected zone (results_guard), and any missing/incomplete mandatory input (exit 5):
  <cdir>/provenance.json (v1), <cdir>/lab_state.json, <cdir>/monitor_ids_provenance.json,
  --stop-criteria (schema archivirt-stop-criteria/2), --manifest (v1 or v2, schema recorded),
  --metrics-source (ssh|telegraf|agent|none).
Records hashes of what is deployed (monitor), of the selected manifest and stop criteria,
and of the campaign scripts/rules. Stop criteria are recorded as PARAMETERS: whether they were
APPLIED to each run is recorded per run in result.json["stop_criteria"] (evaluator), not here.
"""
import argparse, glob, hashlib, json, os, subprocess, sys
sys.dont_write_bytecode = True

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(65536), b""): h.update(b)
    return h.hexdigest()

def die(msg, code=5):
    print("PROVENANCE_ERROR: " + msg, file=sys.stderr); sys.exit(code)

def main():
    ap = argparse.ArgumentParser()
    for x in ("--repo", "--cdir", "--series", "--stop-criteria", "--manifest", "--metrics-source"): ap.add_argument(x, required=True)
    ap.add_argument("--protect", action="append", default=[])
    a = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    g = [sys.executable, "-B", os.path.join(here, "results_guard.py"), "--repo", a.repo, "--dest", a.cdir] + sum([["--protect", x] for x in a.protect], [])
    if subprocess.run(g, capture_output=True).returncode != 0: die("campaign directory %s is in a protected zone" % a.cdir, 4)
    s = a.series.strip()
    if not s or s.casefold() == "unset" or s.casefold().startswith("article"): die("invalid series label %r" % s)
    cid = os.path.basename(os.path.normpath(a.cdir))
    if cid.casefold().startswith("article"): die("campaign id %r uses the reserved Article-2 prefix" % cid)
    if a.metrics_source not in ("ssh", "telegraf", "agent", "none"): die("invalid metrics source")
    req = {}
    for name in ("provenance.json", "lab_state.json", "monitor_ids_provenance.json"):
        p = os.path.join(a.cdir, name)
        if not os.path.isfile(p): die("missing %s" % name)
        try: req[name] = json.load(open(p))
        except Exception as e: die("unreadable %s: %s" % (name, e))
    v1 = req["provenance.json"]
    for k in ("campaign_id", "engine", "mode", "git_commit", "artifact_sha256", "host_facts"):
        if k not in v1 or v1[k] in (None, "", {}): die("v1 field %r missing/empty" % k)
    if v1["campaign_id"] != cid: die("v1 campaign_id %r != directory %r" % (v1["campaign_id"], cid))
    lab = req["lab_state.json"]
    if lab.get("schema") != "archivirt-lab-state/1" or len(lab.get("domains", {})) != 6: die("lab_state incomplete")
    for d, v in lab["domains"].items():
        for k in ("state", "max_mib", "current_mib"):
            if v.get(k) in (None, ""): die("lab_state %s.%s missing" % (d, k))
    if lab.get("egress_policy", {}).get("state") not in ("present", "absent"): die("egress_policy state missing")
    mon = req["monitor_ids_provenance.json"]
    if mon.get("schema") != "archivirt-ids-provenance/1" or not mon.get("files") or not mon.get("suricata_version"): die("monitor provenance incomplete")
    if mon.get("series") != s: die("monitor provenance series %r != campaign series %r (re-run the role for a new series). Required action "
                                   "(owner-authorised, modifies the monitor): ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/deploy_ids_direct.yml "
                                   "-e archivirt_experiment_series=%s -e ids_mode=<mode> (first with --check --diff), then "
                                   "scripts/campaign_v1/ids_provenance_check.sh --series %s" % (mon.get("series"), s, s, s))
    try:
        sc = json.load(open(a.stop_criteria)); assert sc.get("schema") == "archivirt-stop-criteria/2"
    except Exception: die("stop criteria missing or not archivirt-stop-criteria/2")
    try:
        m = json.load(open(a.manifest))
        mschema = 2 if m.get("schema") == "archivirt-offline-manifest/2" else (1 if m.get("manifest_version") == "1.0" and "schema" not in m else None)
        assert mschema
    except Exception: die("offline manifest missing or of unknown schema")
    extra = {}
    for pat in ("scripts/campaign_v1/*.sh", "scripts/campaign_v1/*.py", "campaign_v1/rules/*", "campaign_v1/stop_criteria/*"):
        for p in sorted(glob.glob(os.path.join(a.repo, pat))): extra[os.path.relpath(p, a.repo)] = sha(p)
    if not extra: die("no repository artifacts hashed")
    doc = {"schema": "archivirt-provenance/2", "series": s, "campaign_id": cid,
           "v1": v1, "v1_sha256": sha(os.path.join(a.cdir, "provenance.json")),
           "artifact_sha256_extra": extra, "ids_deployed": mon, "lab_state": lab,
           "offline_manifest": {"path": os.path.abspath(a.manifest), "schema": mschema, "sha256": sha(a.manifest)},
           "stop_criteria": {"path": os.path.abspath(a.stop_criteria), "sha256": sha(a.stop_criteria), "status": sc.get("status"),
                             "version": sc.get("version"), "applied_per_run": "see result.json['stop_criteria'] of each run"},
           "metrics_source": a.metrics_source}
    out = os.path.join(a.cdir, "provenance_v2.json"); tmp = out + ".tmp"
    with open(tmp, "w") as f: json.dump(doc, f, indent=2)
    os.replace(tmp, out); print(out)

if __name__ == "__main__":
    main()
