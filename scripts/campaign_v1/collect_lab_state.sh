#!/bin/bash
# ARCHIVIRT — lab-state collector (PROPOSAL C1.3, B3 + F-12/F-13). READ-ONLY on the lab.
# Writes <out>/lab_state.json and <out>/monitor_ids_provenance.json; exit 5 on any missing input;
# exit 4 if <out> is refused by results_guard.py (checked BEFORE any write).
# Host addresses come from the Ansible inventory (single source; no duplicated table).
# Usage: collect_lab_state.sh <out_dir> <repo_root>
# Test hooks: ARCHIVIRT_VIRSH, ARCHIVIRT_SSH, ARCHIVIRT_NFT, ARCHIVIRT_PROC, ARCHIVIRT_INVENTORY, ARCHIVIRT_PROTECT
set -uo pipefail
OUT="${1:?usage: collect_lab_state.sh <out_dir> <repo_root>}"; REPO="${2:?repo root}"
HERE="$(cd "$(dirname "$0")" && pwd)"
VIRSH="${ARCHIVIRT_VIRSH:-sudo -n virsh}"; SSH="${ARCHIVIRT_SSH:-ssh -o BatchMode=yes -o ConnectTimeout=5}"
NFT="${ARCHIVIRT_NFT:-sudo -n nft}"; PROC="${ARCHIVIRT_PROC:-/proc}"
INV="${ARCHIVIRT_INVENTORY:-$REPO/ansible/inventory/hosts.ini}"
fail() { echo "COLLECT_ERROR: $*" >&2; exit 5; }
OUT=$(python3 -B "$HERE/results_guard.py" --repo "$REPO" --dest "$OUT" --protect "${ARCHIVIRT_PROTECT:-$HOME/archivirt-backup}" --create) || exit 4
DOMAINS="archivirt-manager archivirt-monitor-ids archivirt-attacker archivirt-target-01 archivirt-target-02 archivirt-target-03"
ip_of() { awk -v h="$1" '$1==h {for(i=2;i<=NF;i++) if($i ~ /^ansible_host=/){sub("ansible_host=","",$i); print $i; exit}}' "$INV"; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
MON=$(ip_of archivirt-monitor-ids); [ -n "$MON" ] || fail "monitor address not found in $INV"
$SSH "ubuntu@$MON" 'cat /etc/archivirt/ids-provenance.json' > "$tmp/mon.json" 2>/dev/null || fail "monitor ids-provenance.json unreadable"
python3 -B -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d.get("schema")=="archivirt-ids-provenance/1" and d.get("files") and d.get("series") and d.get("suricata_version")' "$tmp/mon.json" \
  || fail "monitor ids-provenance.json incomplete or wrong schema"
: > "$tmp/dom.tsv"
for d in $DOMAINS; do
  ip=$(ip_of "$d"); [ -n "$ip" ] || fail "address of $d not found in inventory"
  info=$($VIRSH dominfo "$d" 2>/dev/null) || fail "virsh dominfo $d"
  st=$(awk -F: '/^State/{gsub(/^ +/,"",$2);print $2}' <<<"$info")
  mx=$(awk '/^Max memory/{print int($3/1024)}' <<<"$info"); cu=$(awk '/^Used memory/{print int($3/1024)}' <<<"$info")
  [ -n "$st" ] && [ -n "$mx" ] && [ -n "$cu" ] || fail "dominfo $d incomplete"
  t0=$(date +%s.%N); v=$($SSH "ubuntu@$ip" 'date +%s.%N' 2>/dev/null) || v=""; t1=$(date +%s.%N)
  # Clock reference = the guest's NTP view (timesyncd; its server is the host): the ssh-date midpoint above is biased
  # by the SSH handshake (~rtt/2, ~0.3 s) and is kept for information only. Output is key=value tokens; tabs/CR removed.
  n=$($SSH "ubuntu@$ip" 'echo "sync=$(timedatectl show -p NTPSynchronized --value)"; timedatectl timesync-status 2>/dev/null | sed -n "s/^ *Server: *\([^ ]*\).*/server=\1/p; s/^ *Offset: */offset=/p"' 2>/dev/null | tr -d '\t\r' | tr '\n' ' ') || n=""
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$d" "$st" "$mx" "$cu" "$t0" "${v:-null}" "$t1" "${n:-null}" >> "$tmp/dom.tsv"
done
grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' "$PROC/meminfo" > "$tmp/mem" || fail "meminfo"
if tbl=$($NFT list table inet archivirt_egress 2>/dev/null) && [ -n "$tbl" ]; then
  egstate=present; eg=$(sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/' <<<"$tbl" | sha256sum | cut -d' ' -f1)
else egstate=absent; eg=""; fi
python3 -B - "$tmp" "$OUT" "$eg" "$egstate" <<'PY' || fail "assembling lab_state.json"
import json, os, re, sys
tmp, out, eg, egstate = sys.argv[1:5]
CLOCK_MAX_MS = 10.0   # clock_offset_max_ms of the P2-VAL2 parameters (PROPOSED); recorded, not enforced here
UNIT_MS = {"ns": 1e-6, "us": 1e-3, "\u00b5s": 1e-3, "ms": 1.0, "s": 1000.0, "min": 60000.0}
def ntp(field):
    """'sync=yes server=10.0.2.1 offset=+49us' -> (True, '10.0.2.1', 0.049). Anything unparsable -> None (never 0)."""
    kv = dict(t.split("=", 1) for t in field.split() if "=" in t)
    sync = {"yes": True, "no": False}.get(kv.get("sync"))
    m = re.fullmatch(r"([+-]?[0-9]+(?:\.[0-9]+)?)(ns|us|\u00b5s|ms|s|min)", kv.get("offset", ""))
    return sync, kv.get("server"), (round(float(m.group(1)) * UNIT_MS[m.group(2)], 3) if m else None)
doms = {}
for line in open(os.path.join(tmp, "dom.tsv")):
    d, st, mx, cu, t0, v, t1, n = line.rstrip("\n").split("\t")
    try: off = None if v == "null" else round(float(v) - (float(t0) + float(t1)) / 2, 3)
    except ValueError: off = None
    sync, srv, noff = ntp("" if n == "null" else n)
    doms[d] = {"state": st, "max_mib": int(mx), "current_mib": int(cu), "clock_offset_s": off,
               "clock_rtt_s": round(float(t1) - float(t0), 3), "clock_offset_uncertainty_s": round((float(t1) - float(t0)) / 2, 3),
               "clock_offset_method": "ssh_date_midpoint (biased by the SSH handshake; informative only)",
               "ntp_synchronized": sync, "ntp_server": srv, "ntp_offset_ms": noff, "ntp_raw": (n if n != "null" else None) and n[:120].strip()}
run = {d: v for d, v in doms.items() if v["state"] == "running"}
bad = sorted(d for d, v in run.items() if v["ntp_synchronized"] is not True or v["ntp_offset_ms"] is None)
worst = max((abs(v["ntp_offset_ms"]) for d, v in run.items() if d not in bad), default=None)
clock_check = {"source": "guest timesyncd offset (server = host)", "max_abs_offset_ms": CLOCK_MAX_MS,
               "evaluated": sorted(d for d in run if d not in bad), "not_evaluable": bad,
               "not_running": sorted(d for d in doms if d not in run), "worst_abs_offset_ms": worst,
               "status": "NOT_EVALUABLE" if (bad or not run) else ("EXCEEDED" if worst > CLOCK_MAX_MS else "OK")}
mem = {l.split(":")[0]: int(l.split()[1]) // 1024 for l in open(os.path.join(tmp, "mem"))}
doc = {"schema": "archivirt-lab-state/1", "domains": doms, "host_mem_mib": mem, "clock_check": clock_check,
       "egress_policy": {"nft_table": "inet archivirt_egress", "state": egstate,
                         "sha256_without_counters": eg or None}}
tmpf = os.path.join(out, "lab_state.json.tmp"); json.dump(doc, open(tmpf, "w"), indent=2); os.replace(tmpf, os.path.join(out, "lab_state.json"))
PY
cp "$tmp/mon.json" "$OUT/monitor_ids_provenance.json" || fail "copy monitor provenance"
echo "lab_state.json + monitor_ids_provenance.json -> $OUT"
