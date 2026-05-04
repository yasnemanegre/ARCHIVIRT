#!/bin/bash
# run_snort.sh - ARCHIVIRT IaC-compliant Snort3 lifecycle manager
# Usage: sudo bash run_snort.sh start|stop SCENARIO_NAME
# Author: Yasnemanegre SAWADOGO (SPbGUPTD)

ACTION=$1
SCENARIO=${2:-"default"}
LOG_DIR="/var/log/snort3"
PID_FILE="${LOG_DIR}/snort3.pid"
CONFIG="/etc/snort3/snort.lua"
IFACE="ens4"
DAQ_DIR="/usr/local/lib/daq"
SNORT="/usr/local/bin/snort"

case $ACTION in
  start)
    echo "[ARCHIVIRT] Starting Snort3 for $SCENARIO..."
    # Stop any existing instance
    if [ -f "$PID_FILE" ]; then
      kill $(cat $PID_FILE) 2>/dev/null; sleep 3
    fi
    pkill -f snort 2>/dev/null; sleep 3

    # Clear logs
    truncate -s 0 ${LOG_DIR}/alert_fast.txt 2>/dev/null || true
    truncate -s 0 ${LOG_DIR}/alert_json.txt 2>/dev/null || true
    chmod 666 ${LOG_DIR}/alert_fast.txt ${LOG_DIR}/alert_json.txt 2>/dev/null || true

    # Bring up interface
    ip link set $IFACE up
    ip link set $IFACE promisc on

    # Start Snort3
    nohup $SNORT -c $CONFIG -i $IFACE -l $LOG_DIR \
      --daq-dir $DAQ_DIR \
      > ${LOG_DIR}/snort_stdout.log 2>&1 &
    echo $! > $PID_FILE
    sleep 15

    # Verify
    if kill -0 $(cat $PID_FILE) 2>/dev/null; then
      echo "[ARCHIVIRT] Snort3 running PID=$(cat $PID_FILE)"
    else
      echo "[ARCHIVIRT] ERROR: Snort3 failed to start"
      tail -5 ${LOG_DIR}/snort_stdout.log
      exit 1
    fi
    ;;

  stop)
    echo "[ARCHIVIRT] Stopping Snort3 for $SCENARIO..."
    if [ -f "$PID_FILE" ]; then
      kill -SIGINT $(cat $PID_FILE) 2>/dev/null; sleep 5
      kill -9 $(cat $PID_FILE) 2>/dev/null; true
      rm -f $PID_FILE
    fi
    pkill -f snort 2>/dev/null; true

    # Count alerts
    ALERTS=$(wc -l < ${LOG_DIR}/alert_fast.txt 2>/dev/null || echo 0)
    echo "[ARCHIVIRT] $SCENARIO: $ALERTS alerts → ${LOG_DIR}/alert_fast.txt"
    ;;

  status)
    if [ -f "$PID_FILE" ] && kill -0 $(cat $PID_FILE) 2>/dev/null; then
      echo "[ARCHIVIRT] Snort3 running PID=$(cat $PID_FILE)"
      echo "[ARCHIVIRT] Alerts so far: $(wc -l < ${LOG_DIR}/alert_fast.txt)"
    else
      echo "[ARCHIVIRT] Snort3 NOT running"
    fi
    ;;

  *)
    echo "Usage: $0 start|stop|status [SCENARIO]"
    exit 1
    ;;
esac
