#!/bin/bash
# ARCHIVIRT campaign_v1 — recovery after an ABNORMAL end of a campaign (PROPOSED 2026-10-21; target scripts/campaign_v1/).
# Called by campaign_v1.sh cleanup() when the campaign did not complete; can also be run by hand with the same arguments.
# Runs on the HOST. Steps (each recorded, never skipped silently):
#   1 save_logs      : copy the in-progress run's engine logs from the monitor into <run_dir>/engine_logs.recovery.tgz
#   2 stop_engine    : stop.sh on /var/log/archivirt/article/<campaign_id> = ONLY this campaign's engine instances
#                      (never the systemd service: its command line has no "-l"), then verify that none is left
#   3 restore_service: (ids) systemctl start suricata, then verify: active, ids-mode=ids, capture unit active, 0 NFQUEUE,
#                      no campaign instance, one capture thread per requested interface (RX#nn-<if> / W#nn-<if>)
#   4 checks         : VM states == campaign start (lab_state.json; the manager may be stopped by design, M3),
#                      manager services if it runs, NTP on running VMs (synchronised, |offset| <= 10 ms),
#                      egress policy hash == campaign start, attacker -> monitor:22 blocked
#   5 ids_config     : (final review 2026-10-21) sha256 of the monitor's IDS reference files == monitor_ids_provenance.json
#                      recorded at campaign start (suricata.yaml, rules, ids-mode, capture unit/script, service drop-in)
# Steps 2-3 are NOT_NEEDED when no engine was ever started (the service was never stopped); their checks still run.
# Writes <campaign_dir>/recovery.json (never overwritten; --tag T writes recovery.T.json, e.g. a manual re-run). Exit 0 RECOVERED, 1 RECOVERY_FAILED, 2 usage.
# P2-DIAG1 D0 (2026-10-22): always runs WITHOUT a controlling terminal (re-exec under setsid): under `timeout` from a terminal,
# sudo/virsh/pkttyagent got SIGTTOU and stopped until the 600 s timeout, and no recovery.json was written. Local virsh/nft
# calls are bounded (30 s) so that one hung command fails its step instead of the whole record. One recovery at a time
# (flock on the engines directory: no lock file is created); an engine-started recovery is refused once RECOVERED.
# Test hooks: ARCHIVIRT_SSH, ARCHIVIRT_VIRSH, ARCHIVIRT_NFT, ARCHIVIRT_INVENTORY, ARCHIVIRT_ENGINES, ARCHIVIRT_RECOVERY_WAIT
set -uo pipefail
if [ -z "${ARCHIVIRT_RECOVER_DETACHED:-}" ] && { : </dev/tty; } 2>/dev/null; then
  ARCHIVIRT_RECOVER_DETACHED=1 exec setsid -w bash "$0" "$@" </dev/null
fi
CD=""; CID=""; MODE="ids"; IFACES="ens7"; STARTED=0; RUN_DIR=""; REMOTE_DIR=""; TAG=""
while [ $# -gt 0 ]; do case "$1" in
  --campaign-dir) CD="$2"; shift 2;; --campaign-id) CID="$2"; shift 2;; --mode) MODE="$2"; shift 2;; --ifaces) IFACES="$2"; shift 2;;
  --engine-started) STARTED="$2"; shift 2;; --run-dir) RUN_DIR="$2"; shift 2;; --remote-dir) REMOTE_DIR="$2"; shift 2;; --tag) TAG="$2"; shift 2;;
  *) echo "usage: campaign_recover.sh --campaign-dir D --campaign-id ID [--mode ids] [--ifaces ens7] [--engine-started 0|1] [--run-dir R] [--remote-dir RD] [--tag T]" >&2; exit 2;; esac; done
[ -d "$CD" ] && [[ "$CID" =~ ^[A-Za-z0-9._-]+$ ]] && [[ -z "$TAG" || "$TAG" =~ ^[A-Za-z0-9_-]{1,40}$ ]] || { echo "usage error: campaign dir / id / tag" >&2; exit 2; }
OUT="$CD/recovery${TAG:+.$TAG}.json"; [ -e "$OUT" ] && { echo "REFUSED: $OUT exists" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
ENGINES="${ARCHIVIRT_ENGINES:-$(realpath -m "$HERE/../../campaign_v1/engines")}"
{ exec 8<"$ENGINES" && flock -n 8; } 2>/dev/null || { echo "REFUSED: another campaign_recover.sh is running (lock on $ENGINES)" >&2; exit 2; }
if [ "$STARTED" = 1 ] && prev=$(python3 -I -c 'import glob,json,sys
for f in sorted(glob.glob(sys.argv[1] + "/recovery*.json")):
    try: s = json.load(open(f)).get("status")
    except Exception: continue
    if s == "RECOVERED": print(f); sys.exit(0)
sys.exit(1)' "$CD"); then
  echo "REFUSED: $prev is already RECOVERED - no second engine stop/service restart; re-run with --engine-started 0 (checks only)" >&2; exit 2
fi
INV="${ARCHIVIRT_INVENTORY:-$(realpath -m "$HERE/../../ansible/inventory/hosts.ini")}"
SSH="${ARCHIVIRT_SSH:-ssh -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=2}"; VIRSH="${ARCHIVIRT_VIRSH:-timeout 30 sudo -n virsh}"; NFT="${ARCHIVIRT_NFT:-timeout 30 sudo -n nft}"
WAIT="${ARCHIVIRT_RECOVERY_WAIT:-60}"
ip_of() { awk -v h="$1" '$1==h {for(i=2;i<=NF;i++) if($i ~ /^ansible_host=/){sub("ansible_host=","",$i); print $i; exit}}' "$INV"; }
MON=$(ip_of archivirt-monitor-ids); ATT=$(ip_of archivirt-attacker)
STEPS=$(mktemp); PART=""; trap 'rm -f "$STEPS" ${PART:+"$PART"}' EXIT; trap 'exit 143' TERM INT HUP   # temp files never left behind
rec() { printf '%s\t%s\t%s\n' "$1" "$2" "$(tr '\t\n' '  ' <<<"$3" | cut -c1-400)" >> "$STEPS"; }
BASE="/var/log/archivirt/article/$CID"

# 1 save_logs
if [ -n "$REMOTE_DIR" ] && [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ]; then
  f="$RUN_DIR/engine_logs.recovery${TAG:+.$TAG}.tgz"; PART="$f.part"
  if [ -e "$f" ] || [ -e "$PART" ]; then PART=""; rec save_logs FAILED "$f (or .part) exists (never overwritten)"
  elif $SSH "ubuntu@$MON" "sudo -n tar -C '$REMOTE_DIR' -czf - ." > "$PART" 2>/dev/null && [ -s "$PART" ] && mv -n "$PART" "$f" && [ ! -e "$PART" ]; then PART=""; rec save_logs OK "$f $(sha256sum "$f" | cut -c1-16)"
  else rm -f "$PART"; PART=""; rec save_logs FAILED "could not read $REMOTE_DIR on the monitor"; fi
else rec save_logs NOT_NEEDED "no run in progress"; fi

# 2 stop_engine (only this campaign's instances)
if [ "$STARTED" = 1 ]; then
  o=$($SSH "ubuntu@$MON" "bash -s -- '$BASE'" < "$ENGINES/stop.sh" 2>/dev/null | grep -oE 'ARCHIVIRT_ENGINE=[A-Z_]+' | tail -1)
  left=$($SSH "ubuntu@$MON" "pgrep -fc '[s]uricata .* -l $BASE' || true" 2>/dev/null)
  if [[ "$o" =~ STOPPED_(CLEAN|FORCED) ]] && [ "${left:-x}" = 0 ]; then rec stop_engine OK "$o; instances left: 0"
  else rec stop_engine FAILED "stop.sh: ${o:-no answer}; instances left: ${left:-unknown}"; fi
else rec stop_engine NOT_NEEDED "no engine was started by this campaign"; fi

# 3 restore_service (ids). The service is restarted only if an engine was started (the campaign stopped it).
if [ "$MODE" = ids ] || [ "$MODE" = baseline ]; then      # baseline: the reference IDS service must be intact too
  [ "$STARTED" = 1 ] && $SSH "ubuntu@$MON" "sudo -n systemctl start suricata" >/dev/null 2>&1
  ok=0; det="no answer"
  for _i in $(seq 1 "$WAIT"); do
    det=$($SSH "ubuntu@$MON" 'p=$(pgrep -x Suricata-Main | head -1); echo "active=$(systemctl is-active suricata) mode=$(cat /etc/archivirt/ids-mode 2>/dev/null) capture=$(systemctl is-active archivirt-capture-ifaces) nfq=$(sudo -n iptables -S 2>/dev/null | grep -c NFQUEUE) campaign=$(pgrep -fc "[s]uricata .* -l /var/log/archivirt" || true) threads=$( [ -n "$p" ] && ps -T -p "$p" -o comm= | grep -E "^(RX|W)#" | paste -sd, )"' 2>/dev/null) || det="monitor unreachable"
    good=1; for k in active=active mode=ids capture=active nfq=0 campaign=0; do grep -qw -- "$k" <<<"$det" || good=0; done
    IFS=',' read -ra _ifs <<< "$IFACES"; for _if in "${_ifs[@]}"; do grep -qE "(^|[ ,=])(RX|W)#[0-9]+-${_if}(,|$)" <<<"$det" || good=0; done
    [ $good = 1 ] && { ok=1; break; }; sleep 1
  done
  st=$([ $ok = 1 ] && echo OK || echo FAILED); [ "$STARTED" = 1 ] || det="(service not restarted: never stopped) $det"
  rec restore_service "$st" "$det"
else rec restore_service FAILED "mode $MODE: no automatic recovery (IPS is refused by campaign_v1.sh)"; fi

# 5 ids_config: the monitor's IDS reference files are byte-identical to the campaign start (read-only sha256sum)
PROV="$CD/monitor_ids_provenance.json"
if [ -f "$PROV" ] && files=$(python3 -I -c 'import json,re,sys; f=sorted(json.load(open(sys.argv[1]))["files"]); assert f and all(re.fullmatch(r"/[A-Za-z0-9._/-]+", x) for x in f); print(" ".join(f))' "$PROV" 2>/dev/null); then
  got=$($SSH "ubuntu@$MON" "sudo -n sha256sum $files" 2>/dev/null)
  bad=$(python3 -I -c 'import json,sys; exp=json.load(open(sys.argv[1]))["files"]; got={l.split()[1]: l.split()[0] for l in sys.argv[2].splitlines() if len(l.split()) == 2}; print(" ".join("%s:%s" % (k, (got.get(k) or "unreadable")[:12]) for k in sorted(exp) if got.get(k) != exp[k]))' "$PROV" "$got")
  [ -z "$bad" ] && rec ids_config OK "$(wc -w <<<"$files") files identical to monitor_ids_provenance.json" || rec ids_config FAILED "changed or unreadable:$bad"
else rec ids_config FAILED "monitor_ids_provenance.json absent or invalid: no IDS reference"; fi

# 4 checks against the campaign start (lab_state.json)
LAB="$CD/lab_state.json"
if [ -f "$LAB" ]; then
  exp=$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(" ".join("%s=%s" % (k, v["state"].replace(" ", "_")) for k, v in d["domains"].items())); print(d.get("egress_policy", {}).get("sha256_without_counters") or "")' "$LAB")
  vm_bad=""; running=""
  for kv in $(head -1 <<<"$exp"); do d=${kv%%=*}; e=${kv#*=}; s=$($VIRSH domstate "$d" 2>/dev/null | head -1 | tr ' ' '_'); [ "$s" = "$e" ] || vm_bad="$vm_bad $d:${s:-unknown}!=$e"; [ "$s" = running ] && running="$running $d"; done
  [ -z "$vm_bad" ] && rec vm_states OK "as at campaign start:$(head -1 <<<"$exp")" || rec vm_states FAILED "$vm_bad"
  if grep -qw archivirt-manager <<<"$running"; then
    m=$($SSH "ubuntu@$(ip_of archivirt-manager)" 'systemctl is-active influxdb grafana-server telegraf | paste -sd" "' 2>/dev/null)
    [ "$m" = "active active active" ] && rec manager_services OK "$m" || rec manager_services FAILED "${m:-unreachable}"
  else rec manager_services NOT_APPLICABLE "manager not running (stopped by the M3 gate): postseries_restart required"; fi
  ntp_bad=""
  for d in $running; do ip=$(ip_of "$d"); n=$($SSH "ubuntu@$ip" 'echo "$(timedatectl show -p NTPSynchronized --value) $(timedatectl timesync-status 2>/dev/null | sed -n "s/^ *Offset: *//p")"' 2>/dev/null)
    python3 -I -c 'import re,sys; p=sys.argv[1].split(); u={"ns":1e-6,"us":1e-3,"µs":1e-3,"ms":1.0,"s":1000.0}; m=re.fullmatch(r"([+-]?[0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s)", p[1]) if len(p) > 1 else None; sys.exit(0 if p and p[0] == "yes" and m and abs(float(m.group(1)) * u[m.group(2)]) <= 10.0 else 1)' "$n" 2>/dev/null || ntp_bad="$ntp_bad $d:[${n:-unreachable}]"; done
  [ -z "$ntp_bad" ] && rec ntp OK "synchronised, |offset| <= 10 ms:$running" || rec ntp FAILED "$ntp_bad"
  eg_exp=$(sed -n 2p <<<"$exp"); eg=$($NFT list table inet archivirt_egress 2>/dev/null | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/' | sha256sum | cut -d' ' -f1)
  [ -n "$eg_exp" ] && [ "$eg" = "$eg_exp" ] && rec egress_policy OK "$eg" || rec egress_policy FAILED "found $eg expected ${eg_exp:-none}"
  a=$($SSH "ubuntu@$ATT" 'timeout 4 bash -c "</dev/tcp/10.0.4.200/22" 2>/dev/null && echo OPEN || echo blocked' 2>/dev/null)
  [ "$a" = blocked ] && rec isolation_attacker_to_monitor_ssh OK blocked || rec isolation_attacker_to_monitor_ssh FAILED "${a:-unreachable}"
else rec checks FAILED "lab_state.json absent: no reference state"; fi

python3 -I - "$STEPS" "$OUT" "$CID" "$STARTED" <<'PY'
import json, sys, datetime
steps = [dict(zip(("step", "status", "detail"), l.rstrip("\n").split("\t", 2))) for l in open(sys.argv[1]) if l.strip()]
failed = [s["step"] for s in steps if s["status"] == "FAILED"]
doc = {"schema": "archivirt-recovery/1", "campaign_id": sys.argv[3], "engine_started": sys.argv[4] == "1",
       "status": "RECOVERY_FAILED" if failed else "RECOVERED", "failed_steps": failed, "steps": steps,
       "ts": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}
with open(sys.argv[2], "x") as f: json.dump(doc, f, indent=1)
print("ARCHIVIRT_RECOVERY=%s%s" % (doc["status"], (" failed=" + ",".join(failed)) if failed else ""))
sys.exit(1 if failed else 0)
PY
