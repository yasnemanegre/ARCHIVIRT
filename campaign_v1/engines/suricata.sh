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

# Readiness: engine process alive, eve.json created, and the engine reports
# "engine started" in its own log (console logging is disabled in the config,
# so stderr is empty — the authoritative signal is suricata.log).
for _i in $(seq 1 30); do
    if running \
        && sudo test -f "$LOGDIR/eve.json" \
        && sudo grep -q "engine started" "$SURI_LOG" 2>/dev/null; then
        echo "ARCHIVIRT_ENGINE=READY mode=$MODE log=$LOGDIR ifaces=$IFACES"
        exit 0
    fi
    sleep 1
done

echo "ARCHIVIRT_ENGINE=NOT_READY mode=$MODE log=$LOGDIR"
echo "--- $SURI_LOG (tail) ---"
sudo tail -40 "$SURI_LOG" 2>/dev/null || true
exit 1
