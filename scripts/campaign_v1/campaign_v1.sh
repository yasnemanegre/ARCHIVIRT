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

# STEP2: explicit, validated code root - no hard-coded path. ARCHIVIRT_ROOT is mandatory and must be
# the ARCHIVIRT tree that contains THIS script (canonical paths); the root is only READ (code, inventory,
# rules). Every write goes through results_guard.py, which refuses any ARCHIVIRT tree (original
# repository, clones, worktrees), <home>/archivirt-backup (cycle/, backups), <home>/.archivirt.
SELF_ROOT="$(realpath -e -- "$(dirname -- "$(realpath -e -- "${BASH_SOURCE[0]}")")/../..")"
[[ -n "${ARCHIVIRT_ROOT:-}" ]] || { echo "[ARCHIVIRT] ABORT: ARCHIVIRT_ROOT is required (explicit code root, no default)" >&2; exit 4; }
ROOT="$(realpath -e -- "$ARCHIVIRT_ROOT" 2>/dev/null)" || { echo "[ARCHIVIRT] ABORT: ARCHIVIRT_ROOT does not exist: $ARCHIVIRT_ROOT" >&2; exit 4; }
[[ "$ROOT" == "$SELF_ROOT" ]] || { echo "[ARCHIVIRT] ABORT: ARCHIVIRT_ROOT ($ROOT) is not the tree containing this script ($SELF_ROOT)" >&2; exit 4; }
[[ -e "$ROOT/.git" && -f "$ROOT/ansible/inventory/hosts.ini" && -d "$ROOT/campaign_v1/engines" ]] \
    || { echo "[ARCHIVIRT] ABORT: $ROOT is not a complete ARCHIVIRT tree (.git, inventory, engines)" >&2; exit 4; }
export ARCHIVIRT_ROOT="$ROOT"
CAMPAIGN_DIR_SRC="$ROOT/campaign_v1"
ENGINES="$CAMPAIGN_DIR_SRC/engines"
SCENARIOS="$CAMPAIGN_DIR_SRC/scenarios"
PROCESSORS="$ROOT/scripts/campaign_v1"
# Phase-2 contract (proposal C1.3, F-01/F-03/F-08/F-09): every mandatory parameter is validated
# by p2_contract.py BEFORE any side effect (no default; owner decisions D-A1, D-A3, T1).
# The frozen Article-2 location (results/campaign-v1), the repository and ~/archivirt-backup are refused.
CONTRACT="$(python3 -B "$PROCESSORS/p2_contract.py" --repo "$ROOT" --protect "$HOME/archivirt-backup")" \
    || { echo "[ARCHIVIRT] ABORT: phase-2 campaign contract not satisfied (see CONTRACT_ERROR above)" >&2; exit 4; }
eval "$CONTRACT"      # RESULTS SERIES CAMPAIGN_PREFIX STOP_CRITERIA STOP_CRITERIA_STATUS ARCHIVIRT_OFFLINE_MANIFEST OFFLINE_MANIFEST_SCHEMA METRICS_SOURCE MODE (shlex-quoted)
export ARCHIVIRT_OFFLINE_MANIFEST
INVENTORY="$ROOT/ansible/inventory/hosts.ini"
export ARCHIVIRT_INVENTORY="$INVENTORY"   # STEP2: helpers (ssh adapter, lab-state collector) read THIS tree's inventory

MONITOR="archivirt-monitor-ids"
ATTACKER="archivirt-attacker"

MODE="${MODE:-ids}"              # ids | ips
RUNS="${RUNS:-1}"
ENGINE="${ENGINE:-suricata-6.0.4}"   # label recorded in results (family[-version])
ENGINE_FAMILY="${ENGINE%%-*}"        # suricata | snort3  -> engines/<family>.sh
IDS_IFACES="${IDS_IFACES:-ens6,ens7}"
SCENARIO_LIST="${SCENARIOS_LIST:-SCN-001 SCN-002 SCN-003 SCN-004 SCN-005}"
ENFORCE_OFFLINE=1                          # phase-2: the offline gate is mandatory (p2_contract refuses 0)
# STEP2: values that become path components or script names are validated BEFORE any side effect.
[[ "$ENGINE_FAMILY" == suricata || "$ENGINE_FAMILY" == snort3 ]] || { echo "[ARCHIVIRT] ABORT: invalid ENGINE '$ENGINE'" >&2; exit 4; }
[[ "$RUNS" =~ ^[1-9][0-9]{0,2}$ ]] || { echo "[ARCHIVIRT] ABORT: RUNS must be 1..999" >&2; exit 4; }
for _s in $SCENARIO_LIST; do [[ "$_s" =~ ^SCN-[0-9]{3}$ ]] || { echo "[ARCHIVIRT] ABORT: invalid scenario id '$_s'" >&2; exit 4; }; done
[[ -n "${SCENARIO_LIST// /}" ]] || { echo "[ARCHIVIRT] ABORT: empty scenario list" >&2; exit 4; }
# Capture scope (2026-10-21): IDS_IFACES is passed to the engine and to compute_perf.py; only the mirror outputs are accepted.
[[ "$IDS_IFACES" =~ ^(ens6|ens7|ens6,ens7|ens7,ens6)$ ]] || { echo "[ARCHIVIRT] ABORT: invalid IDS_IFACES '$IDS_IFACES'" >&2; exit 4; }
# Snort 3: engines/snort3.sh can start and stop the engine, but collection (EVE), validate_run.py, perf_snapshot (CPU/RSS)
# and the Article-2 ruleset are Suricata-only. Refuse before any side effect rather than produce INVALID runs.
[[ "$ENGINE_FAMILY" != snort3 ]] || { echo "[ARCHIVIRT] ABORT: SNORT3_CAMPAIGN_COLLECTION_NOT_INTEGRATED (see PLAN_CLOTURE_P2_VAL2.md)" >&2; exit 4; }
# IPS mode leaves NFQUEUE rules and cleared mirrors behind (no post-IPS restoration yet): refused before any side effect.
[[ "$MODE" != ips ]] || { echo "[ARCHIVIRT] ABORT: IPS_MODE_REFUSED (no post-IPS restoration of NFQUEUE rules / mirrors)" >&2; exit 4; }
# Per-scenario acceptance (owner decision 2026-10-21): RUNS = maximum runs per scenario; a scenario conforms iff it has
# >= MIN_VALID_RUNS valid runs and <= MAX_INVALID_RUNS non-valid runs (campaign_acceptance.py). Defaults: every run must be valid.
# Adaptive stop only when MIN_VALID_RUNS is given explicitly: a scenario stops as soon as it conforms or can no longer conform.
ADAPTIVE=0; [[ -n "${MIN_VALID_RUNS:-}" ]] && ADAPTIVE=1
MIN_VALID_RUNS="${MIN_VALID_RUNS:-$RUNS}"; MAX_INVALID_RUNS="${MAX_INVALID_RUNS:-0}"
# Stopping on validity must not depend on the detection outcome: with the article2 scoring a missed detection is INVALID.
[[ "$ADAPTIVE" == 0 || "${ARCHIVIRT_SCORING:-article2}" == p2 ]] \
    || { echo "[ARCHIVIRT] ABORT: adaptive stop (MIN_VALID_RUNS set) requires ARCHIVIRT_SCORING=p2" >&2; exit 4; }
[[ "$MIN_VALID_RUNS" =~ ^[1-9][0-9]{0,2}$ && "$MAX_INVALID_RUNS" =~ ^[0-9]{1,3}$ ]] && (( MIN_VALID_RUNS + MAX_INVALID_RUNS <= RUNS )) \
    || { echo "[ARCHIVIRT] ABORT: invalid MIN_VALID_RUNS/MAX_INVALID_RUNS ($MIN_VALID_RUNS/$MAX_INVALID_RUNS) for RUNS=$RUNS" >&2; exit 4; }

CAMPAIGN_ID="${CAMPAIGN_PREFIX}-${MODE}-$(date -u +%Y%m%dT%H%M%SZ)"
[[ ! -e "$RESULTS/$CAMPAIGN_ID" ]] || { echo "[ARCHIVIRT] ABORT: $RESULTS/$CAMPAIGN_ID already exists (results are never overwritten)" >&2; exit 4; }
CAMPAIGN_DIR="$(python3 -B "$PROCESSORS/results_guard.py" --repo "$ROOT" --dest "$RESULTS/$CAMPAIGN_ID" \
                --protect "$HOME/archivirt-backup" --create)" || { echo "[ARCHIVIRT] ABORT: campaign directory refused" >&2; exit 4; }
RM=(python3 -B "$PROCESSORS/p2_run_monitor.py")
printf 'IDS_IFACES=%s\nENGINE=%s\nMODE=%s\nRUNS=%s\nMIN_VALID_RUNS=%s\nMAX_INVALID_RUNS=%s\nSCENARIOS=%s\nSCORING=%s\n' "$IDS_IFACES" "$ENGINE" "$MODE" \
    "$RUNS" "$MIN_VALID_RUNS" "$MAX_INVALID_RUNS" "$SCENARIO_LIST" "${ARCHIVIRT_SCORING:-article2}" > "$CAMPAIGN_DIR/capture_scope.txt"
echo "ADAPTIVE_STOP=$ADAPTIVE" >> "$CAMPAIGN_DIR/capture_scope.txt"
CAMPAIGN_ABORT=""

ans() {
    ansible "$@" -i "$INVENTORY" \
        --ssh-extra-args='-o StrictHostKeyChecking=no -o ConnectTimeout=10'
}

log() { echo "[ARCHIVIRT] $*"; }

# Agent option (T1-c). STEP0 (BL-2): agent_start returns non-zero unless the agent script is
# installed AND its first record exists; agent_stop_fetch stops ONLY this run's agent
# (pattern = this run's output path), then fetches its data.
AGENT_BIN="/usr/local/lib/archivirt/monitor_metrics_agent.sh"
agent_start() {
    ans "$MONITOR" -m shell -a "[ -x '$AGENT_BIN' ] || exit 3; nohup bash '$AGENT_BIN' '$1/agent_metrics.jsonl' '$2' '$MODE' >/dev/null 2>&1 & sleep 2; test -s '$1/agent_metrics.jsonl'" --become >/dev/null 2>&1
}
agent_stop_fetch() {
    ans "$MONITOR" -m shell -a "pkill -TERM -f -- '$AGENT_BIN $1/agent_metrics.jsonl' 2>/dev/null; sleep 1; true" --become >/dev/null 2>&1 || true
    ans "$MONITOR" -m fetch -a "src=$1/agent_metrics.jsonl dest=$2/agent_metrics.jsonl flat=yes" --become >/dev/null 2>&1 || true
}

# STEP0 (BL-1): guaranteed cleanup on EVERY exit path (normal end, set -e error, exit N,
# SIGINT/SIGTERM/SIGHUP). If a run is in progress: stop its recorder (identity-checked by
# p2_run_monitor), stop/fetch its agent, finalize it as INVALID with the interruption reason.
# If the campaign did not complete normally: record campaign_abort.json (never overwritten).
# The original exit status is preserved.
CUR_RUN_DIR=""; CUR_REMOTE_DIR=""; CAMPAIGN_DONE=0; ABORT_SIGNAL=""
ENGINE_STARTED=0; REACHED_TAIL=0      # recovery (2026-10-21): an engine was started / the normal tail was reached
PHASE=precondition                    # P2-DIAG1 D0 (2026-10-22): precondition (lab not modified yet) | runs
on_signal() { ABORT_SIGNAL="$1"; exit "$2"; }
cleanup() {
    local rc=$?
    trap - EXIT
    trap '' INT TERM HUP      # recovery (2026-10-21): cleanup can last up to 600 s; a second signal must not cut it short
    set +e
    if [[ -n "$CUR_RUN_DIR" ]]; then
        "${RM[@]}" stop --run-dir "$CUR_RUN_DIR" >/dev/null 2>&1
        [[ "$METRICS_SOURCE" == "agent" && -n "$CUR_REMOTE_DIR" ]] && agent_stop_fetch "$CUR_REMOTE_DIR" "$CUR_RUN_DIR"
        "${RM[@]}" finalize --run-dir "$CUR_RUN_DIR" --mode "$MODE" --params "$STOP_CRITERIA" --repo "$ROOT" \
            --protect "$HOME/archivirt-backup" --note "interrupted: ${ABORT_SIGNAL:-exit status $rc}" >/dev/null 2>&1
    fi
    if [[ "$CAMPAIGN_DONE" != 1 && ! -f "$CAMPAIGN_DIR/campaign_abort.json" ]]; then
        python3 -B -c 'import json,sys,datetime
json.dump({"campaign_aborted": True, "reason": sys.argv[2], "exit_status": int(sys.argv[3]), "signal": sys.argv[4] or None,
           "run_in_progress": sys.argv[5] or None, "phase": sys.argv[6], "ts": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}, open(sys.argv[1], "w"))' \
            "$CAMPAIGN_DIR/campaign_abort.json" "${CAMPAIGN_ABORT:-unexpected exit}" "$rc" "$ABORT_SIGNAL" "$CUR_RUN_DIR" "$PHASE"
    fi
    # Recovery (2026-10-21): on any non-completed end, save the run's engine logs, stop ONLY this campaign's engine
    # instances, restore the Suricata service and check the lab against the campaign start (recovery.json).
    # setsid -w + </dev/null (P2-DIAG1 D0, 2026-10-22): no controlling terminal. `timeout` puts the recovery in a
    # background process group; launched from a terminal, sudo/virsh/pkttyagent then got SIGTTOU and stopped, the
    # recovery was killed at 600 s and recovery.json was never written. timeout still signals the whole group.
    # Its exit status is kept (PIPESTATUS[0]; 124 = timeout) and recorded in campaign_outcome.json.
    local rec_rc=none
    if [[ "$CAMPAIGN_DONE" != 1 ]]; then
        setsid -w timeout 600 bash "$PROCESSORS/campaign_recover.sh" --campaign-dir "$CAMPAIGN_DIR" --campaign-id "$CAMPAIGN_ID" \
            --mode "$MODE" --ifaces "$IDS_IFACES" --engine-started "$ENGINE_STARTED" --run-dir "$CUR_RUN_DIR" \
            --remote-dir "$CUR_REMOTE_DIR" </dev/null 2>&1 | grep -E '^(ARCHIVIRT_RECOVERY=|REFUSED|usage)' >&2
        rec_rc=${PIPESTATUS[0]}
        [[ -f "$CAMPAIGN_DIR/recovery.json" ]] || log "RECOVERY: recovery.json absent (campaign_recover.sh exit $rec_rc; 124 = timeout 600 s)" \
            "- lab state NOT verified: run campaign_recover.sh by hand with --tag manual (see campaign_abort.json)" >&2
    fi
    python3 -B "$PROCESSORS/campaign_outcome.py" --campaign-dir "$CAMPAIGN_DIR" --done "$CAMPAIGN_DONE" --rc "$rc" \
        --abort-reason "$CAMPAIGN_ABORT" --signal "$ABORT_SIGNAL" --reached-tail "$REACHED_TAIL" \
        --phase "$PHASE" --recovery-rc "$rec_rc" >&2
    exit "$rc"
}
trap cleanup EXIT
trap 'on_signal SIGINT 130' INT
trap 'on_signal SIGTERM 143' TERM
trap 'on_signal SIGHUP 129' HUP

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
    ENGINE_STARTED=1
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
    ans "$MONITOR" -m script -a "$ENGINES/stop.sh '$remote_dir'"      # stop.sh matches Suricata and Snort 3 instances
}

# RCA D0 2026-10-22: diagnostic evidence of the engine, collected AFTER the attack window (never during it):
# capture_geometry.json (effective AF_PACKET ring: v2/v3, frames per socket; engines/capture_geometry.sh, read-only,
# run after experiment_end and before stop_engine), suricata.log (ring parameters, per-RX-thread exit statistics),
# fast.log and the instance's pcap-log file (written in the -l directory once pcap-log has no "dir").
# Stored in <run>/engine_extra/ with ENGINE_EXTRA_SHA256SUMS; a file above ARCHIVIRT_EXTRA_MAX_BYTES is not
# transferred and is recorded as OMITTED with its remote size and sha256.
# r1 (2026-10-22 final review): diagnostic collection never aborts the campaign (set -e) and never fails silently:
# engine_extra/ENGINE_EXTRA_STATUS says COMPLETE or INCOMPLETE with the reasons (ansible rc, remote directory
# absent, expected file ABSENT/OMITTED/UNVERIFIED/MISMATCH, decoder error); the raw ansible output is kept.
capture_geometry() {
    local remote_dir="$1" local_dir="$2"
    mkdir -p "$local_dir/engine_extra"
    ans "$MONITOR" -m script -a "$ENGINES/capture_geometry.sh '$remote_dir'" > "$local_dir/engine_extra/capture_geometry.ansible.txt" 2>&1 \
        || echo "__ARCHIVIRT_ANSIBLE_RC__ $?" >> "$local_dir/engine_extra/capture_geometry.ansible.txt"
    return 0
}

collect_engine_extra() {
    local remote_dir="$1" local_dir="$2" max="${ARCHIVIRT_EXTRA_MAX_BYTES:-67108864}" rc=0
    mkdir -p "$local_dir/engine_extra"
    ans "$MONITOR" -m shell -a "
        cd '$remote_dir' 2>/dev/null || { echo '__ARCHIVIRT_NO_REMOTE_DIR__'; exit 0; }
        for f in capture_geometry.json suricata.log fast.log; do [ -f \"\$f\" ] || echo \"__ARCHIVIRT_FILE_ABSENT__ \$f\"; done
        ls archivirt-capture-*.pcap* >/dev/null 2>&1 || echo '__ARCHIVIRT_FILE_ABSENT__ archivirt-capture-*.pcap*'
        for f in capture_geometry.json suricata.log fast.log archivirt-capture-*.pcap*; do
            [ -f \"\$f\" ] || continue
            sz=\$(sudo stat -c %s \"\$f\" 2>/dev/null) || sz=ERR
            sha=\$(sudo sha256sum \"\$f\" 2>/dev/null | cut -d' ' -f1); [ -n \"\$sha\" ] || sha=ERR
            mt=\$(sudo stat -c %y \"\$f\" 2>/dev/null | tr ' ' '_'); [ -n \"\$mt\" ] || mt=ERR
            echo \"__ARCHIVIRT_FILE_BEGIN__ \$f \$sz \$sha \$mt\"
            [ \"\$sz\" != ERR ] && [ \"\$sz\" -le $max ] && sudo base64 -w0 \"\$f\"
            echo
            echo '__ARCHIVIRT_FILE_END__'
        done
        echo '__ARCHIVIRT_LISTING_DONE__'
    " > "$local_dir/engine_extra/monitor_extra_raw.txt" 2> "$local_dir/engine_extra/monitor_extra.stderr" || rc=$?
    python3 - "$local_dir/engine_extra/monitor_extra_raw.txt" "$local_dir/engine_extra" "$rc" <<'XPY' || echo "INCOMPLETE collector_error rc=$?" >> "$local_dir/engine_extra/ENGINE_EXTRA_STATUS"
import base64, hashlib, os, re, sys
from pathlib import Path
raw = Path(sys.argv[1]).read_text(errors="replace"); out = Path(sys.argv[2]); out.mkdir(exist_ok=True); arc = sys.argv[3]
sums, problems, mtimes = [], [], []
if arc != "0": problems.append("ansible_rc=%s" % arc)
if "__ARCHIVIRT_NO_REMOTE_DIR__" in raw: problems.append("remote_dir_absent")
elif "__ARCHIVIRT_LISTING_DONE__" not in raw: problems.append("remote_listing_incomplete")
for name in re.findall(r"__ARCHIVIRT_FILE_ABSENT__ (\S+)", raw):
    sums.append("ABSENT  %s" % name); problems.append("absent:%s" % name)
for name, size, sha, mt, body in re.findall(r"__ARCHIVIRT_FILE_BEGIN__ (\S+) (\S+) (\S+) (\S+)\s*(.*?)\s*__ARCHIVIRT_FILE_END__", raw, re.S):
    name = os.path.basename(name); mtimes.append("%s  %s" % (mt.replace("_", " "), name))   # remote mtime (ns): end-of-burst processing lag
    if not re.fullmatch(r"[0-9a-f]{64}", sha) or not size.isdigit():
        sums.append("UNVERIFIED  %s  size=%s remote_sha256=%s" % (name, size, sha)); problems.append("unverified:%s" % name); continue
    if not body.strip():
        sums.append("OMITTED  %s  size=%s remote_sha256=%s" % (name, size, sha)); problems.append("omitted:%s" % name); continue
    try:
        data = base64.b64decode(body.strip(), validate=True)
    except Exception:
        sums.append("UNDECODABLE  %s  remote_sha256=%s" % (name, sha)); problems.append("undecodable:%s" % name); continue
    got = hashlib.sha256(data).hexdigest()
    (out / name).write_bytes(data)
    sums.append("%s  %s%s" % (got, name, "" if got == sha else "  MISMATCH remote_sha256=" + sha))
    if got != sha: problems.append("mismatch:%s" % name)
(out / "ENGINE_EXTRA_SHA256SUMS").write_text("\n".join(sums) + ("\n" if sums else ""))
(out / "ENGINE_EXTRA_MTIMES").write_text("\n".join(mtimes) + ("\n" if mtimes else ""))
(out / "ENGINE_EXTRA_STATUS").write_text(("INCOMPLETE " + " ".join(problems) if problems else "COMPLETE") + "\n")
XPY
    return 0
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
    offline_gate || { CAMPAIGN_ABORT="precondition:offline_gate_refused"; exit 2; }
else
    log "ENFORCE_OFFLINE=0 — skipping offline readiness gate (facts still recorded)"
    bash "$PROCESSORS/offline_audit.sh" "$ENGINE_FAMILY" "$(echo "$SCENARIO_LIST" | tr ' ' ',')" "$CAMPAIGN_DIR" >/dev/null 2>&1 || true
fi
write_provenance >/dev/null
bash "$PROCESSORS/collect_lab_state.sh" "$CAMPAIGN_DIR" "$ROOT" >/dev/null \
    || { log "ABORT: lab state / monitor IDS provenance incomplete (no silent empty provenance)"; CAMPAIGN_ABORT="precondition:lab_state_incomplete"; exit 5; }
# Clock criterion (NTP offsets of the running VMs, lab_state.json clock_check): OK required; EXCEEDED or NOT_EVALUABLE aborts.
python3 -B -c 'import json,sys; c=json.load(open(sys.argv[1])).get("clock_check") or {}; print("[ARCHIVIRT] clock_check: %s worst=%s ms not_evaluable=%s" % (c.get("status"), c.get("worst_abs_offset_ms"), c.get("not_evaluable"))); sys.exit(0 if c.get("status") == "OK" else 1)' \
    "$CAMPAIGN_DIR/lab_state.json" || { log "ABORT: clock check not OK (lab_state.json clock_check)"; CAMPAIGN_ABORT="precondition:clock_check_failed"; exit 5; }
python3 -B "$PROCESSORS/provenance_v2.py" --repo "$ROOT" --cdir "$CAMPAIGN_DIR" --series "$SERIES" \
        --stop-criteria "$STOP_CRITERIA" --manifest "$ARCHIVIRT_OFFLINE_MANIFEST" --metrics-source "$METRICS_SOURCE" \
        --protect "$HOME/archivirt-backup" >/dev/null \
    || { log "ABORT: provenance v2 refused (see stderr)"; CAMPAIGN_ABORT="precondition:provenance_v2_refused"; exit 5; }
log "Provenance: provenance.json + provenance_v2.json (series $SERIES, manifest v$OFFLINE_MANIFEST_SCHEMA, stop criteria $STOP_CRITERIA_STATUS, metrics $METRICS_SOURCE)"
PHASE=runs      # from here the monitor is modified (ruleset, engine): an abort is no longer a precondition refusal


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
        # STEP2: run directory resolved and created through the guard, and required to stay inside CAMPAIGN_DIR.
        if ! RUN_DIR="$(python3 -B "$PROCESSORS/results_guard.py" --repo "$ROOT" --dest "$RUN_DIR" \
                        --protect "$HOME/archivirt-backup" --create)" || [[ "$RUN_DIR" != "$CAMPAIGN_DIR/"* ]]; then
            CAMPAIGN_ABORT="run_dir_refused:$RUN_ID"; break 2
        fi

        log "$MODE $RUN_ID"
        # (F-02) stop-criteria recorder: started and PROVEN (first sample) before anything else.
        # STEP0: the run is declared "in progress" BEFORE the recorder is spawned, so that a signal
        # handled right after the spawn can never leave an orphaned recorder (cleanup stops it via
        # its pid file, identity-checked).
        CUR_RUN_DIR="$RUN_DIR"; CUR_REMOTE_DIR="$REMOTE_DIR"
        if ! "${RM[@]}" start --run-dir "$RUN_DIR" --run-id "$RUN_ID" --mode "$MODE" \
                --params "$STOP_CRITERIA" --metrics-source "$METRICS_SOURCE"; then
            "${RM[@]}" finalize --run-dir "$RUN_DIR" --mode "$MODE" --params "$STOP_CRITERIA" --repo "$ROOT" \
                --protect "$HOME/archivirt-backup" >/dev/null 2>&1 || true
            CUR_RUN_DIR=""; CUR_REMOTE_DIR=""
            CAMPAIGN_ABORT="recorder_start_failed:$RUN_ID"; break 2
        fi
        if [[ "$METRICS_SOURCE" == "agent" ]]; then
            if ! agent_start "$REMOTE_DIR" "$RUN_ID"; then
                log "ABORT: metrics agent not started for $RUN_ID (mandatory remote metrics unavailable)"
                "${RM[@]}" stop --run-dir "$RUN_DIR" >/dev/null 2>&1 || true
                agent_stop_fetch "$REMOTE_DIR" "$RUN_DIR"
                "${RM[@]}" finalize --run-dir "$RUN_DIR" --mode "$MODE" --params "$STOP_CRITERIA" --repo "$ROOT" \
                    --protect "$HOME/archivirt-backup" --note "agent_start_failed" >/dev/null 2>&1 || true
                CUR_RUN_DIR=""; CUR_REMOTE_DIR=""
                CAMPAIGN_ABORT="agent_start_failed:$RUN_ID"; break 2
            fi
        fi
        rc_check=0

        if [[ "$MODE" != "baseline" ]]; then
            start_engine "$REMOTE_DIR"
        fi
        "${RM[@]}" check --run-dir "$RUN_DIR" || rc_check=$?      # 7 = immediate abort, 6 = recorder failure
        date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$RUN_DIR/experiment_start.txt"
        perf_snapshot start "$RUN_DIR"

        if [[ $rc_check -eq 0 ]]; then
            run_attack "$scenario" "$RUN_DIR"
        else
            log "SKIP attack $RUN_ID: stop-criteria check rc=$rc_check before the attack"
        fi

        sleep 5                                  # let final packets reach the engine
        perf_snapshot end "$RUN_DIR"
        date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$RUN_DIR/experiment_end.txt"
        [[ $rc_check -eq 0 ]] && { "${RM[@]}" check --run-dir "$RUN_DIR" || rc_check=$?; }

        if [[ "$MODE" != "baseline" ]]; then
            [[ "$MODE" == "ids" ]] && capture_geometry "$REMOTE_DIR" "$RUN_DIR"   # read-only, after experiment_end
            # r1: keep STOPPED_CLEAN / STOPPED_FORCED (a forced stop loses Suricata's final stats dump)
            stop_engine "$REMOTE_DIR" | tee "$RUN_DIR/engine_stop.txt"   # graceful flush BEFORE collection
            collect_eve "$REMOTE_DIR" "$RUN_DIR"
            collect_engine_extra "$REMOTE_DIR" "$RUN_DIR"
        else
            : > "$RUN_DIR/eve.json"              # baseline: no engine, no EVE by design
        fi

        ARCHIVIRT_CAPTURE_IFACES="$IDS_IFACES" python3 "$PROCESSORS/compute_perf.py" \
            "$RUN_DIR/perf_start.txt" "$RUN_DIR/perf_end.txt" > "$RUN_DIR/perf.json" 2>/dev/null || true

        python3 "$PROCESSORS/validate_run.py" \
            "$CAMPAIGN_ID" "$RUN_ID" "$ENGINE" "$MODE" "$scenario" \
            "$RUN_DIR/attack_times.txt" "$RUN_DIR/attack.log" \
            "$RUN_DIR/eve.json" "$RUN_DIR/stats.log" \
            > "$RUN_DIR/result.json"

        # (F-02/F-04/F-05) stop recorder (clean end record required), fetch agent data, evaluate,
        # and write result.json["stop_criteria"]; INVALID if a criterion is confirmed or not evaluable.
        "${RM[@]}" stop --run-dir "$RUN_DIR" || { [[ $rc_check -eq 0 ]] && rc_check=6; }
        fin_args=(--run-dir "$RUN_DIR" --mode "$MODE" --params "$STOP_CRITERIA" --repo "$ROOT" --protect "$HOME/archivirt-backup")
        [[ "$MODE" == "ids" ]] && fin_args+=(--stats-log "$RUN_DIR/stats.log")
        if [[ "$METRICS_SOURCE" == "agent" ]]; then agent_stop_fetch "$REMOTE_DIR" "$RUN_DIR"; fin_args+=(--remote-jsonl "$RUN_DIR/agent_metrics.jsonl"); fi
        fin=0; "${RM[@]}" finalize "${fin_args[@]}" || fin=$?
        if [[ $fin -eq 2 || $fin -eq 4 ]]; then
            # evaluator failed: the run can never be presented as VALID
            "${RM[@]}" mark-invalid --run-dir "$RUN_DIR" --repo "$ROOT" --protect "$HOME/archivirt-backup" \
                --reason "stop-criteria evaluation failed (rc $fin)" >/dev/null 2>&1 || true
            CUR_RUN_DIR=""; CUR_REMOTE_DIR=""
            CAMPAIGN_ABORT="evaluator_error_rc$fin:$RUN_ID"; break 2
        fi
        CUR_RUN_DIR=""; CUR_REMOTE_DIR=""
        [[ $rc_check -eq 7 ]] && { CAMPAIGN_ABORT="stop_immediate:$RUN_ID"; break 2; }
        [[ $rc_check -eq 6 ]] && { CAMPAIGN_ABORT="recorder_failure:$RUN_ID"; break 2; }

        log "Completed $RUN_ID ($(python3 -c "import json;print(json.load(open('$RUN_DIR/result.json'))['run_status'])"))"
        if [[ "$ADAPTIVE" == 1 ]]; then           # ARCHIVIRT_ADAPTIVE_BEGIN (same validity definition as campaign_acceptance.py)
            n_valid=""; n_nonvalid=""
            read -r n_valid n_nonvalid < <(python3 -B "$PROCESSORS/campaign_acceptance.py" --count "$CAMPAIGN_DIR/$MODE/$scenario") || true
            [[ "${n_valid:-}" =~ ^[0-9]+$ && "${n_nonvalid:-}" =~ ^[0-9]+$ ]] || { log "$scenario: run count unavailable - scenario stopped (NON_CONFORM)"; break; }
            if (( n_valid >= MIN_VALID_RUNS )); then log "$scenario: $n_valid valid runs after $n run(s) - scenario complete"; break; fi
            if (( n_nonvalid > MAX_INVALID_RUNS )); then log "$scenario: $n_nonvalid non-valid runs > $MAX_INVALID_RUNS - NON_CONFORM, stopped"; break; fi
            if (( n_valid + RUNS - n < MIN_VALID_RUNS )); then log "$scenario: $MIN_VALID_RUNS valid runs no longer reachable - NON_CONFORM, stopped"; break; fi
        fi                                           # ARCHIVIRT_ADAPTIVE_END
    done
done

python3 "$PROCESSORS/summarize.py" "$CAMPAIGN_DIR"
# Per-scenario conformity (>= MIN_VALID_RUNS valid, <= MAX_INVALID_RUNS non-valid, <= RUNS runs) + C1 rate rules, all runs kept.
python3 -B "$PROCESSORS/campaign_acceptance.py" "$CAMPAIGN_DIR" --max-runs "$RUNS" --min-valid "$MIN_VALID_RUNS" \
    --max-invalid "$MAX_INVALID_RUNS" --out "$CAMPAIGN_DIR/campaign_acceptance.json" || log "Scenario conformity NOT met (see campaign_acceptance.json)"
if [[ -n "$CAMPAIGN_ABORT" ]]; then
    python3 -B -c 'import json,sys; json.dump({"campaign_aborted": True, "reason": sys.argv[2], "exit_status": 6, "signal": None, "phase": sys.argv[4], "ts": sys.argv[3]}, open(sys.argv[1], "w"))' \
        "$CAMPAIGN_DIR/campaign_abort.json" "$CAMPAIGN_ABORT" "$(date -u +%FT%TZ)" "$PHASE"
fi

# Restore the baseline: hand capture back to the systemd-managed engine.
REACHED_TAIL=1
ans "$MONITOR" -m shell -a 'sudo systemctl start suricata 2>/dev/null || true' >/dev/null 2>&1 || true

if [[ -n "$CAMPAIGN_ABORT" ]]; then log "CAMPAIGN ABORTED ($CAMPAIGN_ABORT) - data kept in $CAMPAIGN_DIR"; exit 6; fi
CAMPAIGN_DONE=1
log "CAMPAIGN COMPLETE"
log "RESULTS: $CAMPAIGN_DIR"
