#!/bin/bash
# ARCHIVIRT — local metrics agent on the monitor (PROPOSAL C1.3, option T1-c). READ-ONLY sampling.
# Writes records in the recorder format (values/status) to <out>, one per interval, until SIGTERM;
# final {"end": true}. The file is collected with the run data and evaluated post-run
# (--remote-jsonl). No live immediate-abort from remote metrics in this option.
# target-03 memory is NOT visible from the monitor -> reported MISSING (needs another source).
# Usage: monitor_metrics_agent.sh <out> <run_id> <mode> [interval]   Test hooks: AGENT_SYS, AGENT_PROC
set -u
OUT="$1"; RID="$2"; MODE="$3"; IV="${4:-5}"; SYS="${AGENT_SYS:-/sys/class/net}"; PROC="${AGENT_PROC:-/proc}"
run=1; trap 'run=0' TERM INT; seq=0; b6=""; bq=""
while [ $run = 1 ]; do
  t=$(date +%s.%N); mem=$(awk '/^MemAvailable:/{print int($2/1024)}' "$PROC/meminfo" 2>/dev/null)
  d6=$(cat "$SYS/ens6/statistics/rx_dropped" 2>/dev/null); d7=$(cat "$SYS/ens7/statistics/rx_dropped" 2>/dev/null)
  q=$(awk '{q+=$6+$7} END{if(NR) print q}' "$PROC/net/netfilter/nfnetlink_queue" 2>/dev/null)
  python3 -B - "$t" "$RID" "$MODE" "$seq" "${mem:-}" "${d6:-}" "${d7:-}" "${q:-}" "$b6" "$bq" >> "$OUT" <<'PY'
import json, sys
t, rid, mode, seq, mem, d6, d7, q, b6, bq = sys.argv[1:11]
v, s = {}, {}
def num(x): return int(x) if x.strip().isdigit() else None
m = num(mem)
if m is None: s["monitor_mem_available_mib"] = "ERROR"
else: v["monitor_mem_available_mib"], s["monitor_mem_available_mib"] = m, "MEASURED"
s["target03_mem_available_mib"] = "MISSING"
if mode == "ips": s["capture_iface_drops_delta"] = "NOT_APPLICABLE"
elif num(d6) is None or num(d7) is None: s["capture_iface_drops_delta"] = "ERROR"
else: v["capture_iface_drops_delta"], s["capture_iface_drops_delta"] = num(d6) + num(d7) - (num(b6) if num(b6) is not None else num(d6) + num(d7)), "MEASURED"
if mode != "ips": s["nfq_queue_dropped_delta"] = "NOT_APPLICABLE"
elif num(q) is None: s["nfq_queue_dropped_delta"] = "ERROR"
else: v["nfq_queue_dropped_delta"], s["nfq_queue_dropped_delta"] = num(q) - (num(bq) if num(bq) is not None else num(q)), "MEASURED"
print(json.dumps({"seq": int(seq), "ts_epoch": round(float(t), 3), "run_id": rid, "mode": mode, "values": v, "status": s, "source": "agent"}, sort_keys=True))
PY
  [ -z "$b6" ] && [ -n "${d6:-}" ] && [ -n "${d7:-}" ] && b6=$((d6 + d7)); [ -z "$bq" ] && [ -n "${q:-}" ] && bq="$q"
  seq=$((seq + 1)); end=$(( $(date +%s) + ${IV%.*} )); while [ $run = 1 ] && [ "$(date +%s)" -lt "$end" ]; do sleep 0.2; done
done
echo "{\"end\": true, \"run_id\": \"$RID\", \"samples\": $seq, \"source\": \"agent\"}" >> "$OUT"
