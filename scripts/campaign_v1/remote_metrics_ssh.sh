#!/bin/bash
# ARCHIVIRT — remote metrics over SSH (PROPOSAL C1.3, option T1-a). READ-ONLY (cat of /proc,/sys).
# One persistent SSH master per host (ControlPersist) limits the load on the measured monitor.
# Output: KEY=<int> | KEY=NA (not applicable in this mode) | KEY=ERR (could not be read).
# Usage: remote_metrics_ssh.sh <mode>   Test hooks: ARCHIVIRT_SSH, ARCHIVIRT_INVENTORY
set -u
MODE="${1:-ids}"
INV="${ARCHIVIRT_INVENTORY:-$(realpath -e -- "$(dirname -- "$(realpath -e -- "$0")")/../..")/ansible/inventory/hosts.ini}"   # STEP2: no hard-coded root
CP="${XDG_RUNTIME_DIR:-/tmp}/archivirt-cm-%r@%h:%p"
SSH="${ARCHIVIRT_SSH:-ssh -o BatchMode=yes -o ConnectTimeout=3 -o ControlMaster=auto -o ControlPath=$CP -o ControlPersist=120}"
ip_of() { awk -v h="$1" '$1==h {for(i=2;i<=NF;i++) if($i ~ /^ansible_host=/){sub("ansible_host=","",$i); print $i; exit}}' "$INV"; }
MON=$(ip_of archivirt-monitor-ids); T03=$(ip_of archivirt-target-03)
emit_err() { for k in "$@"; do echo "$k=ERR"; done; }
if [ -n "$MON" ] && out=$($SSH "ubuntu@$MON" 'awk "/^MemAvailable:/{print int(\$2/1024)}" /proc/meminfo; cat /sys/class/net/ens6/statistics/rx_dropped /sys/class/net/ens7/statistics/rx_dropped; awk "{q+=\$6; u+=\$7} END{print (NR?q:\"NA\"), (NR?u:\"NA\")}" /proc/net/netfilter/nfnetlink_queue 2>/dev/null || echo "NA NA"' 2>/dev/null); then
  set -- $out
  echo "monitor_mem_available_mib=${1:-ERR}"
  if [ "$MODE" = ips ]; then echo "ens6_rx_dropped=NA"; echo "ens7_rx_dropped=NA"; else echo "ens6_rx_dropped=${2:-ERR}"; echo "ens7_rx_dropped=${3:-ERR}"; fi
  if [ "$MODE" = ips ]; then echo "nfq_queue_dropped=${4:-ERR}"; echo "nfq_user_dropped=${5:-ERR}"; else echo "nfq_queue_dropped=NA"; echo "nfq_user_dropped=NA"; fi
else
  emit_err monitor_mem_available_mib ens6_rx_dropped ens7_rx_dropped nfq_queue_dropped nfq_user_dropped
fi
if [ -n "$T03" ] && v=$($SSH "ubuntu@$T03" 'awk "/^MemAvailable:/{print int(\$2/1024)}" /proc/meminfo' 2>/dev/null) && [ -n "$v" ]; then
  echo "target03_mem_available_mib=$v"
else echo "target03_mem_available_mib=ERR"; fi
exit 0
