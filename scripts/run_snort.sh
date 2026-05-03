#!/bin/bash
# run_snort.sh - Start/stop Snort 3 for a single scenario (ARCHIVIRT IaC pipeline)
# Author: Yasnemanegre SAWADOGO (SPbGUPTD)
# Usage: sudo bash run_snort.sh start|stop SCENARIO_NAME

ACTION=$1
SCENARIO=$2
LOG_DIR="/var/log/snort3/${SCENARIO}"
PID_FILE="${LOG_DIR}/snort.pid"
CONFIG="/etc/snort3/snort.lua"
IFACE="ens4"
DAQ_DIR="/usr/local/lib/daq"
SNORT_BIN="/usr/local/bin/snort"

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
        sleep 8
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
            echo "[ARCHIVIRT] Snort3 stopped. Logs: $LOG_DIR"
            python3 -c "
rules={'1:9000001:1':'ICMP','1:9000002:1':'TCP SYN Scan',
       '1:9000003:1':'SSH','1:9000004:1':'HTTP','1:9000005:1':'Slowloris'}
counts={}
try:
    with open('${LOG_DIR}/alert_json.txt') as f:
        for line in f:
            try:
                d=json.loads(line)
                r=rules.get(d.get('rule','?'),'OTHER')
                counts[r]=counts.get(r,0)+1
            except: pass
    for k,v in sorted(counts.items()): print(f'  {k}: {v}')
    print(f'  TOTAL: {sum(counts.values())}')
except: print('  No alerts file found')
" 2>/dev/null
        else
            echo "[ARCHIVIRT] No PID file for $SCENARIO — killing all snort"
            pkill -f snort || true
        fi
        ;;
    *)
        echo "Invalid action. Use: start|stop"
        exit 1
        ;;
esac
