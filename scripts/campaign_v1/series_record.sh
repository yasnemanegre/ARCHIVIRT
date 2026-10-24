#!/bin/bash
# ARCHIVIRT P2-VAL2 — record the series configuration BEFORE the launch. PROPOSED, read-only.
# Writes <evidence dir>/series_config.json: the campaign environment actually exported, sha256 of the stop criteria,
# parameter file, campaign scripts and rules, git state, tool and Python library versions (+ dist-info sha), and the
# Vault check (vault readable with ANSIBLE_VAULT_PASSWORD_FILE: yes/no only; no secret is printed or copied).
# campaign_v1.sh itself records ENGINE/MODE/IDS_IFACES (capture_scope.txt) but not RUNS, SCENARIOS_LIST or libraries.
# Usage: (same environment as the launch) series_record.PROPOSED.sh <evidence dir> <parameter file>
set -u
E="${1:?evidence dir}"; PARAMS="${2:?parameter file}"; [ -d "$E" ] || { echo "REFUSED: $E missing"; exit 2; }
[ -e "$E/series_config.json" ] && { echo "REFUSED: series_config.json exists"; exit 2; }
R="${ARCHIVIRT_ROOT:?ARCHIVIRT_ROOT}"
vault=no; (cd "$R" && timeout 60 ansible archivirt-monitor-ids -i ansible/inventory/hosts.ini -m command -a true \
  --ssh-extra-args='-o StrictHostKeyChecking=no -o ConnectTimeout=10' >/dev/null 2>&1) && vault=yes
python3 - "$E/series_config.json" "$R" "$PARAMS" "$vault" <<'PY'
import hashlib, json, os, subprocess, sys, glob, importlib.metadata as md, datetime
out, root, params, vault = sys.argv[1:5]
def sha(p):
    try: return hashlib.sha256(open(p, "rb").read()).hexdigest()
    except OSError: return None
def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()
env = {k: os.environ.get(k) for k in ("ARCHIVIRT_ROOT", "ARCHIVIRT_RESULTS_ROOT", "ARCHIVIRT_EXPERIMENT_SERIES", "ARCHIVIRT_CAMPAIGN_PREFIX",
       "ARCHIVIRT_STOP_CRITERIA", "ARCHIVIRT_OFFLINE_MANIFEST", "ARCHIVIRT_METRICS_SOURCE", "MODE", "ENGINE", "IDS_IFACES", "RUNS", "MIN_VALID_RUNS", "MAX_INVALID_RUNS", "ARCHIVIRT_SCORING", "SCENARIOS_LIST")}
env["ANSIBLE_VAULT_PASSWORD_FILE"] = "set" if os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE") else "UNSET"   # path existence only, never content
libs = {}
for name in ("numpy", "scipy", "matplotlib"):
    try:
        d = md.distribution(name); rec = d.read_text("RECORD") or ""
        libs[name] = {"version": d.version, "location": str(d.locate_file("")), "RECORD_sha256": hashlib.sha256(rec.encode()).hexdigest()}
    except Exception as e: libs[name] = {"version": None, "error": type(e).__name__}
art = {os.path.relpath(p, root): sha(p) for pat in ("scripts/campaign_v1/*.sh", "scripts/campaign_v1/*.py", "campaign_v1/rules/*", "campaign_v1/stop_criteria/*", "campaign_v1/scenarios/*", "campaign_v1/engines/*")
       for p in sorted(glob.glob(os.path.join(root, pat)))}
doc = {"schema": "archivirt-series-config/1-PROPOSED", "ts": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "env": env,
       "stop_criteria_sha256": sha(env["ARCHIVIRT_STOP_CRITERIA"] or ""), "offline_manifest_sha256": sha(env["ARCHIVIRT_OFFLINE_MANIFEST"] or ""),
       "parameter_file": {"path": os.path.abspath(params), "sha256": sha(params)},
       "git": {"head": sh("git -C %s rev-parse HEAD" % root), "dirty_paths": len(sh("git -C %s status --porcelain" % root).splitlines()),
               "article2_frozen_v1": sh("git -C %s rev-parse 'article2-frozen-v1^{commit}'" % root)},
       "tools": {"python3": sh("python3 --version"), "ansible": sh("ansible --version | head -1"), "terraform": sh("terraform -version 2>/dev/null | head -1")},
       "python_libs": libs, "vault_usable_with_ansible_vault_password_file": vault == "yes", "artifact_sha256": art}
json.dump(doc, open(out, "w"), indent=1, sort_keys=True); print(out)
PY
