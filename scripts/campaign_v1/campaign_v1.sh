#!/usr/bin/env bash
# ARCHIVIRT campaign_v1 orchestrator (Article 2).
#
# Single sources of truth:
#   * engine commands   -> campaign_v1/engines/{suricata,stop}.sh
#   * scenario commands -> campaign_v1/scenarios/SCN-*.sh
# Both are transferred to the relevant host and executed via `ansible -m script`,
# so this orchestrator never re-encodes an attack or an engine invocation.
#
# Ordering fix: the engine is stopped (graceful SIGTERM, flush) BEFORE eve.json
# is collected, so buffered EVE records reach disk and are captured.
set -euo pipefail

ROOT="/home/archivirt/ARCHIVIRT"
CAMPAIGN_DIR_SRC="$ROOT/campaign_v1"
ENGINES="$CAMPAIGN_DIR_SRC/engines"
SCENARIOS="$CAMPAIGN_DIR_SRC/scenarios"
PROCESSORS="$ROOT/scripts/campaign_v1"
RESULTS="$ROOT/results/campaign-v1"
INVENTORY="$ROOT/ansible/inventory/hosts.ini"

MONITOR="archivirt-monitor-ids"
ATTACKER="archivirt-attacker"

MODE="${MODE:-ids}"              # ids | ips
RUNS="${RUNS:-1}"
ENGINE="${ENGINE:-suricata-6.0.4}"   # label recorded in results (family[-version])
ENGINE_FAMILY="${ENGINE%%-*}"        # suricata | snort3  -> engines/<family>.sh
IDS_IFACES="${IDS_IFACES:-ens6,ens7}"
SCENARIO_LIST="${SCENARIOS_LIST:-SCN-001 SCN-002 SCN-003 SCN-004 SCN-005}"
ENFORCE_OFFLINE="${ENFORCE_OFFLINE:-1}"   # refuse to start if offline artifacts missing

CAMPAIGN_ID="ARTICLE-$(date -u +%Y%m%dT%H%M%SZ)"
CAMPAIGN_DIR="$RESULTS/$CAMPAIGN_ID"
mkdir -p "$CAMPAIGN_DIR"

ans() {
    ansible "$@" -i "$INVENTORY" \
        --ssh-extra-args='-o StrictHostKeyChecking=no -o ConnectTimeout=10'
}

log() { echo "[ARCHIVIRT] $*"; }

# Record the campaign manifest up front.
cat > "$CAMPAIGN_DIR/campaign.json" <<JSON
{
  "campaign_id": "$CAMPAIGN_ID",
  "engine": "$ENGINE",
  "mode": "$MODE",
  "runs_per_scenario": $RUNS,
  "scenarios": [$(echo "$SCENARIO_LIST" | sed 's/ /", "/g; s/^/"/; s/$/"/')]
}
JSON

# --- OFFLINE READINESS GATE ------------------------------------------------
# A campaign must never start on partially provisioned infrastructure, and must
# never fetch a missing dependency from the Internet (ARCHIVIRT-LAB is offline
# by design). The audit is read-only and writes readiness.json into the results.
offline_gate() {
    local sc_csv; sc_csv="$(echo "$SCENARIO_LIST" | tr ' ' ',')"
    log "Offline readiness audit (engine=$ENGINE_FAMILY scenarios=$sc_csv)"
    if bash "$PROCESSORS/offline_audit.sh" "$ENGINE_FAMILY" "$sc_csv" "$CAMPAIGN_DIR" >/dev/null 2>&1; then
        log "Offline readiness: all required artifacts READY"
        return 0
    fi
    log "ABORT: infrastructure not fully provisioned offline. Missing/invalid:"
    python3 -c 'import sys,json
r=json.load(open(sys.argv[1]))
for a in r["artifacts"]:
    if a["required"] and a["status"]!="READY":
        print("   - %s (%s): %s" % (a["id"], a.get("host") or "", a["status"]))' \
        "$CAMPAIGN_DIR/readiness.json" 2>/dev/null || true
    log "See $CAMPAIGN_DIR/readiness.json — no download attempted (offline policy)."
    return 2
}

# --- PROVENANCE ------------------------------------------------------------
# Record exactly which versions and artifacts a campaign ran with (reproducibility).
write_provenance() {
    python3 - "$CAMPAIGN_DIR/provenance.json" "$CAMPAIGN_DIR" "$ROOT" "$ENGINE" "$MODE" "$CAMPAIGN_ID" <<'PY'
import json, sys, subprocess, hashlib, os, glob
out, cdir, root, engine, mode, cid = sys.argv[1:7]
def sh(c):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception: return None
def sha(p):
    try:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for b in iter(lambda: fh.read(65536), b""): h.update(b)
        return h.hexdigest()
    except Exception: return None
facts = {}
for ff in ("monitor_facts.txt", "attacker_facts.txt"):
    p = os.path.join(cdir, ff)
    if os.path.exists(p):
        for line in open(p):
            line = line.strip().replace("\r", "")
            if "=" in line: k, _, v = line.partition("="); facts[k] = v
arts = {}
for pat in ("campaign_v1/scenarios/*.sh", "campaign_v1/engines/*.sh",
            "configs/suricata/suricata.yaml", "campaign_v1/manifest/offline_manifest.json"):
    for p in glob.glob(os.path.join(root, pat)):
        arts[os.path.relpath(p, root)] = sha(p)
json.dump({
    "campaign_id": cid, "engine": engine, "mode": mode,
    "git_commit": sh("git -C '%s' rev-parse HEAD" % root),
    "git_dirty": bool(sh("git -C '%s' status --porcelain" % root)),
    "terraform": sh("terraform -version 2>/dev/null | head -1"),
    "ansible": sh("ansible --version 2>/dev/null | head -1"),
    "host_facts": facts,
    "artifact_sha256": arts,
}, open(out, "w"), indent=2)
print(out)
PY
}

configure_mode() {
    log "Configuring mode=$MODE"
    # Always clear any prior NFQUEUE rules first.
    ans "$MONITOR" -m shell -a '
        sudo iptables -D FORWARD -s 10.0.4.0/24 -d 10.0.2.0/24 -j NFQUEUE --queue-num 0 2>/dev/null || true
        sudo iptables -D FORWARD -s 10.0.2.0/24 -d 10.0.4.0/24 -j NFQUEUE --queue-num 0 2>/dev/null || true
    '
    if [[ "$MODE" == "ips" ]]; then
        ans "$MONITOR" -m shell -a '
            sudo iptables -C FORWARD -s 10.0.4.0/24 -d 10.0.2.0/24 -j NFQUEUE --queue-num 0 2>/dev/null ||
              sudo iptables -I FORWARD 1 -s 10.0.4.0/24 -d 10.0.2.0/24 -j NFQUEUE --queue-num 0
            sudo iptables -C FORWARD -s 10.0.2.0/24 -d 10.0.4.0/24 -j NFQUEUE --queue-num 0 2>/dev/null ||
              sudo iptables -I FORWARD 1 -s 10.0.2.0/24 -d 10.0.4.0/24 -j NFQUEUE --queue-num 0
        '
        sudo ovs-vsctl --if-exists clear Bridge ovs-targets mirrors
        sudo ovs-vsctl --if-exists clear Bridge ovs-attack mirrors
    else
        sudo "$ROOT/scripts/archivirt_mirrors.sh"
    fi
}

start_engine() {
    local remote_dir="$1"
    # Common engine interface: engines/<family>.sh is the single source of truth.
    ans "$MONITOR" -m script -a "$ENGINES/${ENGINE_FAMILY}.sh $MODE '$remote_dir' $IDS_IFACES '$REMOTE_RULES'"
}

# Perf snapshot on the monitor: Suricata CPU jiffies + RSS, and mirror-interface
# packet/byte/drop counters. Printed as KEY=VALUE for compute_perf.py.
perf_snapshot() {
    local tag="$1" local_dir="$2"
    ans "$MONITOR" -m shell -a '
        echo "wall_ns=$(date +%s%N)"
        echo "clk_tck=$(getconf CLK_TCK)"
        pid=$(pgrep -f "[s]uricata .* -l /var/log/archivirt" | head -1)
        echo "suricata_pid=${pid:-NONE}"
        if [ -n "$pid" ]; then
            read -r _ _ _ _ _ _ _ _ _ _ _ _ _ ut st _ < /proc/$pid/stat 2>/dev/null
            echo "cpu_jiffies=$(( ${ut:-0} + ${st:-0} ))"
            echo "rss_kb=$(awk "/VmRSS/{print \$2}" /proc/$pid/status 2>/dev/null)"
        else echo "cpu_jiffies=NONE"; echo "rss_kb=NONE"; fi
        for i in ens6 ens7; do
            echo "${i}_rx_packets=$(cat /sys/class/net/$i/statistics/rx_packets 2>/dev/null || echo NONE)"
            echo "${i}_rx_bytes=$(cat /sys/class/net/$i/statistics/rx_bytes 2>/dev/null || echo NONE)"
            echo "${i}_rx_dropped=$(cat /sys/class/net/$i/statistics/rx_dropped 2>/dev/null || echo NONE)"
        done
    ' 2>/dev/null | grep -E '^[a-z0-9_]+=' > "$local_dir/perf_${tag}.txt"
}

stop_engine() {
    local remote_dir="$1"
    if [[ "$ENGINE_FAMILY" == "suricata" ]]; then
        ans "$MONITOR" -m script -a "$ENGINES/stop.sh '$remote_dir'"
    fi
}

# Resolve a scenario id (SCN-001) to its single source-of-truth script.
scenario_script() {
    local scenario="$1"
    ls "$SCENARIOS/${scenario}-"*.sh 2>/dev/null | head -1
}

run_attack() {
    local scenario="$1" local_dir="$2"
    local script
    script="$(scenario_script "$scenario")"
    if [[ -z "$script" ]]; then
        echo "ARCHIVIRT_PREREQUISITE_MISSING=scenario-script:$scenario" > "$local_dir/attack.log"
        : > "$local_dir/attack_times.txt"
        return 0
    fi

    # Scenario runs on the attacker; its stdout carries the markers + raw output.
    ans "$ATTACKER" -m script -a "$script" > "$local_dir/attack_raw.txt" 2>&1 || true
    cp "$local_dir/attack_raw.txt" "$local_dir/attack.log"

    # Extract the attacker-side START/END timestamps (real attack lifecycle).
    # Ansible returns CRLF inside a JSON wrapper, so match the ISO token itself
    # (…Z) and stop at it — never capturing trailing \r\n or command output.
    {
        grep -oE 'ARCHIVIRT_ATTACK_START=[0-9T:.+-]+Z' "$local_dir/attack_raw.txt" | head -1 | cut -d= -f2-
        grep -oE 'ARCHIVIRT_ATTACK_END=[0-9T:.+-]+Z'   "$local_dir/attack_raw.txt" | head -1 | cut -d= -f2-
    } | tr -d '\r' > "$local_dir/attack_times.txt"
}

collect_eve() {
    local remote_dir="$1" local_dir="$2"
    # Collect the real Suricata EVE + stats through base64 framing markers so
    # Ansible's own stdout header is never mistaken for EVE content.
    ans "$MONITOR" -m shell -a "
        echo '__ARCHIVIRT_EVE_BEGIN__'
        sudo base64 -w0 '$remote_dir/eve.json' 2>/dev/null || true
        echo
        echo '__ARCHIVIRT_EVE_END__'
        echo '__ARCHIVIRT_STATS_BEGIN__'
        sudo base64 -w0 '$remote_dir/stats.log' 2>/dev/null || true
        echo
        echo '__ARCHIVIRT_STATS_END__'
    " > "$local_dir/monitor_raw.txt"

    python3 - "$local_dir/monitor_raw.txt" "$local_dir/eve.json" "$local_dir/stats.log" <<'PY'
import base64, re, sys
from pathlib import Path
raw = Path(sys.argv[1]).read_text(errors="replace")
def extract(name):
    m = re.search(rf"__ARCHIVIRT_{name}_BEGIN__\s*(.*?)\s*__ARCHIVIRT_{name}_END__", raw, re.S)
    if not m:
        return b""
    try:
        return base64.b64decode(m.group(1).strip())
    except Exception:
        return b""
Path(sys.argv[2]).write_bytes(extract("EVE"))
Path(sys.argv[3]).write_bytes(extract("STATS"))
PY
}

if [[ "$ENFORCE_OFFLINE" == "1" ]]; then
    offline_gate || exit 2
else
    log "ENFORCE_OFFLINE=0 — skipping offline readiness gate (facts still recorded)"
    bash "$PROCESSORS/offline_audit.sh" "$ENGINE_FAMILY" "$(echo "$SCENARIO_LIST" | tr ' ' ',')" "$CAMPAIGN_DIR" >/dev/null 2>&1 || true
fi
write_provenance >/dev/null
log "Provenance: $CAMPAIGN_DIR/provenance.json"

# --- Select + deploy the Article-2 ruleset for this mode --------------------
REMOTE_RULES=""
if [[ "$MODE" != "baseline" && "$ENGINE_FAMILY" == "suricata" ]]; then
    local_rules="$CAMPAIGN_DIR_SRC/rules/archivirt-article2-${MODE}.rules"
    REMOTE_RULES="/etc/suricata/rules/archivirt-article2-${MODE}.rules"
    ans "$MONITOR" -m copy -a "src=$local_rules dest=$REMOTE_RULES mode=0644" --become >/dev/null 2>&1 \
        || log "WARN: could not deploy ruleset $local_rules"
    log "Ruleset deployed: $REMOTE_RULES ($(grep -c '^alert\|^drop' "$local_rules") sigs)"
fi

configure_mode

for scenario in $SCENARIO_LIST; do
    for n in $(seq 1 "$RUNS"); do
        RUN_ID="${scenario}-RUN-$(printf '%03d' "$n")"
        RUN_DIR="$CAMPAIGN_DIR/$MODE/$scenario/$RUN_ID"
        REMOTE_DIR="/var/log/archivirt/article/$CAMPAIGN_ID/$RUN_ID"
        mkdir -p "$RUN_DIR"

        log "$MODE $RUN_ID"

        if [[ "$MODE" != "baseline" ]]; then
            start_engine "$REMOTE_DIR"
        fi
        date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$RUN_DIR/experiment_start.txt"
        perf_snapshot start "$RUN_DIR"

        run_attack "$scenario" "$RUN_DIR"

        sleep 5                                  # let final packets reach the engine
        perf_snapshot end "$RUN_DIR"
        date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$RUN_DIR/experiment_end.txt"

        if [[ "$MODE" != "baseline" ]]; then
            stop_engine "$REMOTE_DIR"            # graceful flush BEFORE collection
            collect_eve "$REMOTE_DIR" "$RUN_DIR"
        else
            : > "$RUN_DIR/eve.json"              # baseline: no engine, no EVE by design
        fi

        python3 "$PROCESSORS/compute_perf.py" \
            "$RUN_DIR/perf_start.txt" "$RUN_DIR/perf_end.txt" > "$RUN_DIR/perf.json" 2>/dev/null || true

        python3 "$PROCESSORS/validate_run.py" \
            "$CAMPAIGN_ID" "$RUN_ID" "$ENGINE" "$MODE" "$scenario" \
            "$RUN_DIR/attack_times.txt" "$RUN_DIR/attack.log" \
            "$RUN_DIR/eve.json" "$RUN_DIR/stats.log" \
            > "$RUN_DIR/result.json"

        log "Completed $RUN_ID ($(python3 -c "import json;print(json.load(open('$RUN_DIR/result.json'))['run_status'])"))"
    done
done

python3 "$PROCESSORS/summarize.py" "$CAMPAIGN_DIR"

# Restore the baseline: hand capture back to the systemd-managed engine.
ans "$MONITOR" -m shell -a 'sudo systemctl start suricata 2>/dev/null || true' >/dev/null 2>&1 || true

log "CAMPAIGN COMPLETE"
log "RESULTS: $CAMPAIGN_DIR"
