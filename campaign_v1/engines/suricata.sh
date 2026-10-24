#!/bin/bash
# ARCHIVIRT campaign_v1 — Suricata engine (single source of truth)
# Runs ON the monitor host. Transferred + executed by the orchestrator
# via `ansible -m script`. Prints machine-readable ARCHIVIRT_ENGINE= markers.
#
# Usage: suricata.sh <ids|ips> <logdir> [iface_csv]
#   ids : passive capture via af-packet on the given interfaces (default ens6,ens7)
#   ips : inline capture via NFQUEUE 0 (iptables rules set up by the orchestrator)
#
# Rationale (Article 2 fix): in IDS mode the previous inline start passed NO
# --af-packet interface, so Suricata listened on nothing and eve.json stayed
# empty. EVE output itself is already enabled in suricata.yaml.
set -uo pipefail

MODE="${1:?usage: suricata.sh <ids|ips> <logdir> [iface_csv] [rules_file]}"
LOGDIR="${2:?missing logdir}"
IFACES="${3:-ens6,ens7}"
RULES="${4:-}"                                    # optional: load this ruleset EXCLUSIVELY (-S)

CONF="/etc/suricata/suricata.yaml"
RULE_ARG=(); [ -n "$RULES" ] && [ -f "$RULES" ] && RULE_ARG=(-S "$RULES")
SURI_LOG="/var/log/suricata/suricata.log"

# Root-cause notes (Article 2 qualification):
#  * Suricata renames its main process comm to "Suricata-Main", so the former
#    `pgrep -x suricata` never matched a running engine -> false NOT_READY.
#  * A systemd-managed suricata.service (Restart=on-failure) runs in parallel
#    with `--af-packet` bound to NO explicit interface. Two engines on the same
#    AF_PACKET sockets = invalid capture, and it respawns on kill. The campaign
#    therefore stops that service and runs its OWN instance bound explicitly to
#    the mirror interfaces, identified uniquely by its per-run -l directory so
#    we never touch the service's instance.
RUNPAT="[s]uricata .* -l ${LOGDIR}"               # this campaign run's instance only
CAMPAT="[s]uricata .* -l /var/log/archivirt"      # any campaign instance (never systemd)
running() { pgrep -f "$RUNPAT" >/dev/null 2>&1; }

# Hand over control from the systemd-managed engine for the duration of the run.
sudo systemctl stop suricata 2>/dev/null || true

sudo mkdir -p "$LOGDIR"
sudo rm -f "$LOGDIR/eve.json" "$LOGDIR/stats.log" "$LOGDIR/fast.log"
sudo pkill -TERM -f "$CAMPAT" 2>/dev/null || true
sleep 1
sudo pkill -KILL -f "$CAMPAT" 2>/dev/null || true
# Truncate the engine log so the "engine started" readiness check reflects THIS
# launch, not a previous one (the log file is persistent across runs).
sudo truncate -s 0 "$SURI_LOG" 2>/dev/null || true

# Fail fast on a broken config instead of silently producing no EVE.
if ! sudo suricata -T -c "$CONF" "${RULE_ARG[@]}" >/tmp/archivirt-suri-test.log 2>&1; then
    echo "ARCHIVIRT_ENGINE=CONFIG_TEST_FAILED"
    sudo cat /tmp/archivirt-suri-test.log 2>/dev/null || true
    exit 1
fi

case "$MODE" in
    ids)
        af_args=()
        IFS=',' read -ra _ifs <<< "$IFACES"
        for _if in "${_ifs[@]}"; do
            sudo ip link set "$_if" up 2>/dev/null || true
            af_args+=(--af-packet="$_if")
        done
        # -D : Suricata double-forks and detaches, so it survives the Ansible
        # SSH session closing (nohup+& did not reliably survive).
        sudo suricata -c "$CONF" "${RULE_ARG[@]}" "${af_args[@]}" -l "$LOGDIR" -D
        ;;
    ips)
        sudo suricata -c "$CONF" "${RULE_ARG[@]}" -q 0 -l "$LOGDIR" -D
        ;;
    *)
        echo "ARCHIVIRT_ENGINE=BAD_MODE:$MODE"
        exit 2
        ;;
esac

# Readiness (fix 2026-10-21, P2VAL2-ids-20261021T150511Z): the former check waited for "engine started" in
# suricata.log, but the deployed suricata.yaml has no logging section (console only) -> false NOT_READY while
# the engine was running. Readiness is now decided from the engine's own state, never from the PID alone:
#   READY                   : this run's instance alive AND eve.json present AND stats.log written by this
#                             instance (it is removed before the start) with a "Date:" record, AND (ids) the
#                             counter capture.kernel_packets present AND at least one capture thread per
#                             requested interface (RX#nn-<if> autofp / W#nn-<if> workers)
#   (fix 2026-10-21, P2VAL2-ids-20261021T200439Z) the instance is the process matching the run's -l directory whose
#   argv holds "-l <logdir>" exactly and whose main thread is "Suricata-Main" (a sudo/shell wrapper is never taken
#   for the engine); with ONE requested interface, Suricata 6.0.4 names the autofp capture threads RX#nn without the
#   interface suffix (observed 15:06:55 and 20:05: "RX#01 RX#02"), so RX#nn is accepted then; never an unsuffixed
#   W#nn (autofp workers are not capture threads); with several interfaces the suffix stays mandatory.
#   START_FAILED            : instance absent (never started or died)            -> exit 1
#   NOT_READY_PROCESS_ALIVE : alive at the deadline, evidence missing (listed)   -> instance stopped, exit 1
#   TIMEOUT_INDETERMINATE   : alive at the deadline, evidence not readable       -> instance stopped, exit 1
# ips (NFQ, refused by campaign_v1.sh): no per-interface capture threads; alive + eve.json + stats record only.
READY_TIMEOUT="${ARCHIVIRT_ENGINE_READY_TIMEOUT:-60}"
stop_instance() { sudo pkill -TERM -f "$RUNPAT" 2>/dev/null || true; sleep 2; sudo pkill -KILL -f "$RUNPAT" 2>/dev/null || true; }
# This run's engine daemon: argv contains "-l" "<LOGDIR>" exactly and the main thread is named Suricata-Main.
find_daemon() {
    local p
    for p in $(pgrep -f "$RUNPAT" 2>/dev/null); do
        [ "$(cat "/proc/$p/comm" 2>/dev/null)" = Suricata-Main ] || continue
        tr '\0' '\n' < "/proc/$p/cmdline" 2>/dev/null | awk -v d="$LOGDIR" 'prev == "-l" && $0 == d {f = 1} {prev = $0} END {exit !f}' \
            && { echo "$p"; return 0; }
    done
    return 1
}
IFS=',' read -ra _req <<< "$IFACES"
missing=""; state="START_FAILED"
for _i in $(seq 1 "$READY_TIMEOUT"); do
    if ! pgrep -f "$RUNPAT" >/dev/null 2>&1; then
        state="START_FAILED"; [ "$_i" -ge 5 ] && break; sleep 1; continue   # 5 s grace for the -D fork
    fi
    missing=""; state="NOT_READY_PROCESS_ALIVE"
    if ! pid=$(find_daemon); then
        missing=" daemon(Suricata-Main with -l $LOGDIR)"; sleep 1; continue  # only a wrapper (e.g. sudo) so far
    fi
    sudo test -f "$LOGDIR/eve.json" || missing="$missing eve.json"
    if sudo test -f "$LOGDIR/stats.log"; then
        sudo grep -q "^Date:" "$LOGDIR/stats.log" 2>/dev/null || missing="$missing stats.record"
        if [ "$MODE" = ids ]; then
            sudo grep -qE "^capture\.kernel_packets +\|" "$LOGDIR/stats.log" 2>/dev/null || missing="$missing stats.capture.kernel_packets"
        fi
    else
        missing="$missing stats.log"
    fi
    if [ "$MODE" = ids ]; then
        if threads=$(ps -T -p "$pid" -o comm= 2>/dev/null); then
            for _if in "${_req[@]}"; do
                pat="^(RX|W)#[0-9]+-${_if}\$"; [ "${#_req[@]}" -eq 1 ] && pat="^(RX#[0-9]+|(RX|W)#[0-9]+-${_if})\$"
                grep -qE "$pat" <<< "$threads" || missing="$missing thread:${_if}"
            done
        else
            state="TIMEOUT_INDETERMINATE"; missing="$missing threads-unreadable"
        fi
    fi
    if [ -z "$missing" ]; then
        echo "ARCHIVIRT_ENGINE=READY mode=$MODE log=$LOGDIR ifaces=$IFACES pid=$pid after=${_i}s"
        exit 0
    fi
    sleep 1
done

if [ "$state" = START_FAILED ]; then
    echo "ARCHIVIRT_ENGINE=START_FAILED mode=$MODE log=$LOGDIR (no instance matching the run)"
else
    echo "ARCHIVIRT_ENGINE=$state mode=$MODE log=$LOGDIR missing:${missing} (timeout ${READY_TIMEOUT}s) - stopping this run's instance"
    stop_instance
fi
echo "--- $SURI_LOG (tail; empty when the yaml has no logging section) ---"
sudo tail -40 "$SURI_LOG" 2>/dev/null || true
exit 1
