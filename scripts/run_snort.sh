#!/bin/bash
# run_snort.sh - Start/stop Snort 3 for a single scenario (ARCHIVIRT IaC pipeline)
# Author: Yasnemanegre SAWADOGO (SPbGUPTD)
# Usage: sudo bash run_snort.sh start|stop SCENARIO_NAME

ACTION=$1
SCENARIO=${2:-default}
LOG_DIR=/var/log/snort3/${SCENARIO}
PID_FILE=${LOG_DIR}/snort.pid
CONFIG=/etc/snort3/snort.lua
IFACE=ens4
DAQ_DIR=/usr/local/lib/daq
SNORT_BIN=/usr/local/bin/snort

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 start|stop SCENARIO_NAME"
    exit 1
fi

case $ACTION in
    start)
        mkdir -p "$LOG_DIR"
        ip link set "$IFACE" up
        ip link set "$IFACE" promisc on
        truncate -s 0 "${LOG_DIR}/alert_fast.txt" 2>/dev/null || true
        truncate -s 0 "${LOG_DIR}/alert_json.txt" 2>/dev/null || true
        echo "[ARCHIVIRT] Starting Snort 3 on $IFACE for $SCENARIO ..."
        nohup "$SNORT_BIN" -i "$IFACE" -c "$CONFIG" \
            -l "$LOG_DIR" --daq-dir "$DAQ_DIR" \
            > "${LOG_DIR}/snort_stdout.log" 2>&1 &
        SNORT_PID=$!
        echo $SNORT_PID > "$PID_FILE"
        sleep 10
        if kill -0 $SNORT_PID 2>/dev/null; then
            echo "[ARCHIVIRT] Snort3 running PID=$SNORT_PID logs=$LOG_DIR"
        else
            echo "[ARCHIVIRT] ERROR: Snort3 failed to start"
            tail -5 "${LOG_DIR}/snort_stdout.log"
            exit 1
        fi
        ;;
    stop)
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            echo "[ARCHIVIRT] Stopping Snort3 PID=$PID for $SCENARIO ..."
            kill -SIGINT "$PID" 2>/dev/null
            sleep 5
            kill -9 "$PID" 2>/dev/null || true
            rm -f "$PID_FILE"
            ALERTS=$(wc -l < "${LOG_DIR}/alert_fast.txt" 2>/dev/null || echo 0)
            echo "[ARCHIVIRT] Snort3 stopped. Alerts: $ALERTS"
        else
            echo "[ARCHIVIRT] No PID file for $SCENARIO — killing all snort"
            pkill -f snort || true
            ALERTS=$(wc -l < "${LOG_DIR}/alert_fast.txt" 2>/dev/null || echo 0)
            echo "[ARCHIVIRT] Alerts: $ALERTS"
        fi
        ;;
    *)
        echo "Invalid action. Use: start|stop"
        exit 1
        ;;
esac
