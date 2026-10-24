#!/bin/bash
# ARCHIVIRT campaign_v1 — pre-series IDS provenance check (P2-DIAG1 D0, 2026-10-22). READ-ONLY on the lab, writes nothing.
# D0 was refused by provenance_v2.py only after the 35-min memory gate (manager stopped): the monitor's
# /etc/archivirt/ids-provenance.json still carried the previous series. Run this in P0, before any gate, with the series the
# campaign will use (ARCHIVIRT_EXPERIMENT_SERIES). It applies the same rule as provenance_v2.py (series equality, never
# ARTICLE*/UNSET) and also checks that the recorded files are still byte-identical on the monitor and the IDS mode.
# Exit 0 PROVENANCE_OK, 5 PROVENANCE_MISMATCH / incomplete / stale, 3 monitor unreachable, 2 usage.
# Usage: ids_provenance_check.sh --series S [--mode ids]
# Test hooks: ARCHIVIRT_SSH, ARCHIVIRT_INVENTORY
set -uo pipefail
SERIES=""; MODE="ids"
while [ $# -gt 0 ]; do case "$1" in
  --series) SERIES="$2"; shift 2;; --mode) MODE="$2"; shift 2;;
  *) echo "usage: ids_provenance_check.sh --series S [--mode ids|ips]" >&2; exit 2;; esac; done
[[ "$SERIES" =~ ^[A-Za-z0-9._-]+$ && "$MODE" =~ ^(ids|ips)$ ]] || { echo "usage: ids_provenance_check.sh --series S [--mode ids|ips]" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
INV="${ARCHIVIRT_INVENTORY:-$(realpath -m "$HERE/../../ansible/inventory/hosts.ini")}"
SSH="${ARCHIVIRT_SSH:-ssh -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=2}"
MON=$(awk '$1=="archivirt-monitor-ids" {for(i=2;i<=NF;i++) if($i ~ /^ansible_host=/){sub("ansible_host=","",$i); print $i; exit}}' "$INV")
[ -n "$MON" ] || { echo "PROVENANCE_CHECK_ERROR: monitor address not found in $INV" >&2; exit 2; }
fix="Required action (owner-authorised, modifies the monitor): ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/deploy_ids_direct.yml -e archivirt_experiment_series=$SERIES -e ids_mode=$MODE (first with --check --diff), then re-run this check"
prov=$($SSH "ubuntu@$MON" 'cat /etc/archivirt/ids-provenance.json' 2>/dev/null) || { echo "PROVENANCE_UNREACHABLE: cannot read /etc/archivirt/ids-provenance.json on $MON" >&2; exit 3; }
files=$(python3 -I - "$SERIES" "$prov" <<'PY'
import json, re, sys
s, raw = sys.argv[1], sys.argv[2]
def bad(m): print("PROVENANCE_MISMATCH: " + m, file=sys.stderr); sys.exit(5)
if not s.strip() or s.casefold() == "unset" or s.casefold().startswith("article"): bad("invalid series label %r" % s)
try: d = json.loads(raw)
except Exception as e: bad("ids-provenance.json unreadable: %s" % e)
if d.get("schema") != "archivirt-ids-provenance/1" or not d.get("files") or not d.get("suricata_version"): bad("ids-provenance.json incomplete or wrong schema")
if d.get("series") != s: bad("monitor provenance series %r != campaign series %r" % (d.get("series"), s))
f = sorted(d["files"])
if not all(re.fullmatch(r"/[A-Za-z0-9._/-]+", x) for x in f): bad("unexpected file path in ids-provenance.json")
print(" ".join(f))
PY
) || { echo "$fix" >&2; exit 5; }
got=$($SSH "ubuntu@$MON" "sudo -n sha256sum $files; echo mode=\$(cat /etc/archivirt/ids-mode 2>/dev/null)" 2>/dev/null) || { echo "PROVENANCE_UNREACHABLE: sha256sum on $MON failed" >&2; exit 3; }
python3 -I - "$prov" "$got" "$MODE" <<'PY' || { echo "$fix" >&2; exit 5; }
import json, sys
exp = json.loads(sys.argv[1])["files"]; lines = sys.argv[2].splitlines(); mode = sys.argv[3]
got = {l.split()[1]: l.split()[0] for l in lines if len(l.split()) == 2}
diff = ["%s:%s" % (k, (got.get(k) or "unreadable")[:12]) for k in sorted(exp) if got.get(k) != exp[k]]
m = next((l[5:] for l in lines if l.startswith("mode=")), "")
if diff: print("PROVENANCE_MISMATCH: deployed files differ from ids-provenance.json (stale record):", " ".join(diff), file=sys.stderr); sys.exit(5)
if m != mode: print("PROVENANCE_MISMATCH: /etc/archivirt/ids-mode %r != requested mode %r" % (m, mode), file=sys.stderr); sys.exit(5)
PY
echo "PROVENANCE_OK series=$SERIES mode=$MODE files=$(wc -w <<<"$files") identical"
