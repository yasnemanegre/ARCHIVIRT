#!/bin/bash
# ARCHIVIRT campaign_v1 — end-of-campaign IDS file evidence for campaign_acceptance.py --ids-after (P1, 2026-11-09). READ-ONLY on the lab.
# Re-hashes on the monitor the files listed in <campaign_dir>/monitor_ids_provenance.json (recorded before the runs) and writes
# <campaign_dir>/ids_deployed_after.json. The hashes are LIVE: re-reading /etc/archivirt/ids-provenance.json would only repeat the
# deployment record and could never reveal a change. Any missing input, unreachable monitor or unreadable file: no output, non-zero
# exit, so the rule stays NOT_EVALUATED. A differing hash is written as observed: the evaluator reports it as FAIL.
# Exit 0 written, 5 incomplete evidence, 2 usage / output exists.
# Usage: collect_ids_after.sh <campaign_dir>
# Test hooks: ARCHIVIRT_SSH, ARCHIVIRT_INVENTORY
set -uo pipefail
CD="${1:?usage: collect_ids_after.sh <campaign_dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
INV="${ARCHIVIRT_INVENTORY:-$(realpath -m "$HERE/../../ansible/inventory/hosts.ini")}"
SSH="${ARCHIVIRT_SSH:-ssh -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=2}"
OUT="$CD/ids_deployed_after.json"
fail() { echo "IDS_AFTER_ERROR: $*" >&2; exit 5; }
[ ! -e "$OUT" ] || { echo "IDS_AFTER_ERROR: $OUT exists (never overwritten)" >&2; exit 2; }
BEFORE="$CD/monitor_ids_provenance.json"
MON=$(awk '$1=="archivirt-monitor-ids" {for(i=2;i<=NF;i++) if($i ~ /^ansible_host=/){sub("ansible_host=","",$i); print $i; exit}}' "$INV")
[ -n "$MON" ] || fail "monitor address not found in $INV"
files=$(python3 -B -I - "$BEFORE" <<'PY'
import json, re, sys
f = sorted(json.load(open(sys.argv[1]))["files"])
if not f or not all(re.fullmatch(r"/[A-Za-z0-9._/-]+", x) for x in f): sys.exit(1)
print(" ".join(f))
PY
) || fail "recorded file list unreadable or invalid: $BEFORE"
got=$($SSH "ubuntu@$MON" "sudo -n sha256sum $files" 2>/dev/null) || fail "sha256sum on $MON failed or a file is unreadable"
python3 -B -I - "$BEFORE" "$got" "$OUT" <<'PY' || fail "incomplete hash list"
import json, re, sys
want = set(json.load(open(sys.argv[1]))["files"])
files = {}
for line in sys.argv[2].splitlines():
    m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(/\S+)", line.strip())
    if not m: sys.exit(1)
    files[m.group(2)] = m.group(1)
if set(files) != want: sys.exit(1)
with open(sys.argv[3], "x") as o:
    json.dump({"schema": "archivirt-ids-after/1", "source": "live sha256sum on the monitor", "files": files}, o, indent=1, sort_keys=True); o.write("\n")
PY
echo "ids_deployed_after.json -> $OUT"
