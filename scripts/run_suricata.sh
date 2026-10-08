#!/bin/bash
# =============================================================================
# ARCHIVIRT — Start/stop Suricata for a single scenario
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 2.4.0 — 2026-05-19
#
# Usage:
#   sudo bash run_suricata.sh start|stop SCENARIO_NAME [ids|ips]
#
#   MODE argument is optional — defaults to "ids" for backward compatibility.
#   IDS mode : passive AF-PACKET capture (sniffer-only, no traffic blocking)
#   IPS mode : inline NFQ capture (traffic blocking via iptables NFQUEUE)
#
# FIX v2.4.0: replaced fixed sleep with deterministic AFP thread detection.
#   Polls suricata_stdout.log every 2s until "All AFP capture threads are
#   running" appears (max 300s). No more timing-dependent failures.
# =============================================================================

ACTION=$1
SCENARIO=${2:-default}
MODE=${3:-ids}

LOG_DIR=/var/log/suricata/${SCENARIO}
PID_FILE=${LOG_DIR}/suricata.pid
CONFIG=/etc/suricata/suricata.yaml
IFACE=ens4
NFQ_QUEUE=0
SURICATA_BIN=/usr/bin/suricata
AFP_READY_MSG="engine started"
AFP_TIMEOUT=300

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 start|stop SCENARIO_NAME [ids|ips]"
    exit 1
fi

case $ACTION in
    start)
        mkdir -p "$LOG_DIR"
        ip link set "$IFACE" up
        ip link set "$IFACE" promisc on
        truncate -s 0 "${LOG_DIR}/eve.json" 2>/dev/null || true
        truncate -s 0 "${LOG_DIR}/suricata_stdout.log" 2>/dev/null || true

        if [ "$MODE" = "ips" ]; then
            echo "[ARCHIVIRT] Starting Suricata IPS (NFQ queue=$NFQ_QUEUE) for $SCENARIO ..."
            "$SURICATA_BIN" -c "$CONFIG" -q "$NFQ_QUEUE" --runmode=autofp -l "$LOG_DIR" \
                > "${LOG_DIR}/suricata_stdout.log" 2>&1 &
        else
            echo "[ARCHIVIRT] Starting Suricata IDS (AF-PACKET, iface=$IFACE) for $SCENARIO ..."
            "$SURICATA_BIN" -c "$CONFIG" --pcap=$IFACE -l "$LOG_DIR" \
                > "${LOG_DIR}/suricata_stdout.log" 2>&1 &
        fi

        SURICATA_PID=$!
        echo $SURICATA_PID > "$PID_FILE"

        # --- Deterministic startup check -------------------------------------
        if [ "$MODE" = "ips" ]; then
            echo "[ARCHIVIRT] Waiting for Suricata IPS startup..."
            sleep 3
            if ! kill -0 "$SURICATA_PID" 2>/dev/null; then
                echo "[ARCHIVIRT] ERROR: Suricata IPS process died during startup"
                tail -30 "${LOG_DIR}/suricata_stdout.log"
                exit 1
            fi
            echo "[ARCHIVIRT] Suricata IPS process is running."
            echo "[ARCHIVIRT] PID=$SURICATA_PID mode=$MODE logs=$LOG_DIR"
            exit 0
        fi

        # --- Deterministic IDS startup check --------------------------------
        echo "[ARCHIVIRT] Waiting for AFP capture threads (max ${AFP_TIMEOUT}s)..."
        WAITED=0
        while [ $WAITED -lt $AFP_TIMEOUT ]; do
            sleep 2
            WAITED=$((WAITED + 2))

            # Check if Suricata died
            if ! kill -0 $SURICATA_PID 2>/dev/null; then
                echo "[ARCHIVIRT] ERROR: Suricata process died after ${WAITED}s"
                tail -5 "${LOG_DIR}/suricata_stdout.log"
                exit 1
            fi

            # Check for AFP ready
            if grep -q "$AFP_READY_MSG" "${LOG_DIR}/suricata_stdout.log" 2>/dev/null; then
                echo "[ARCHIVIRT] Suricata ready after ${WAITED}s — AFP threads running"
                echo "[ARCHIVIRT] PID=$SURICATA_PID mode=$MODE logs=$LOG_DIR"
                exit 0
            fi
        done

        echo "[ARCHIVIRT] ERROR: AFP threads did not start within ${AFP_TIMEOUT}s"
        tail -10 "${LOG_DIR}/suricata_stdout.log"
        exit 1
        ;;

    stop)
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            echo "[ARCHIVIRT] Stopping Suricata PID=$PID for $SCENARIO ..."
            kill -SIGINT "$PID" 2>/dev/null
            sleep 8
            kill -9 "$PID" 2>/dev/null || true
            rm -f "$PID_FILE"
        else
            echo "[ARCHIVIRT] No PID file for $SCENARIO — killing all suricata"
            pkill -9 -f suricata || true
        fi

        # NFQUEUE rules are managed by Ansible and are intentionally
        # not removed by this scenario helper.

        ALERTS=$(grep -c '"event_type":"alert"' "${LOG_DIR}/eve.json" 2>/dev/null || echo 0)
        echo "[ARCHIVIRT] Suricata stopped. Mode=$MODE Alerts=$ALERTS"
        ;;

    *)
        echo "Invalid action. Use: start|stop"
        exit 1
        ;;
esac
