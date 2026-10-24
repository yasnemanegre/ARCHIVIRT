#!/bin/bash
# ARCHIVIRT mission — controlled IDS/IPS validation of ONE engine at a time (run from the host).
# Usage: validate_engine.sh <suricata|snort3> <ids|ips> <out_dir>
# Ground truth: the attacker sends (1) legitimate HTTP GETs + pings to the 3 targets, then (2) the
# validation markers (HTTP User-Agent canary to target-01, ICMP payload canary via hping3), with
# UTC timestamps recorded on the attacker. Only lab addresses are used (10.0.2.0/24, 10.0.4.0/24).
# The validation engine instance is dedicated (own log dir, own pid) and always stopped at the end
# (trap); the packaged service is restored to its previous state. Never two IPS engines at once.
set -uo pipefail
ENGINE="${1:?engine}"; MODE="${2:?mode}"; OUT="${3:?out dir}"
KH="${ARCHIVIRT_MON_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"   # monitor host key (re-learnt after every rebuild)
SERIES="${ARCHIVIRT_SERIES:?set ARCHIVIRT_SERIES (e.g. ARCHIVIRT-P2-VAL2)}"
case "$SERIES" in ARTICLE*|article*) echo "REFUSED: series $SERIES (Article-2 identifiers are frozen)"; exit 2;; esac
MON="ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KH ubuntu@10.0.3.10"
ATT="ssh -o BatchMode=yes ubuntu@10.0.4.10"
REPO=$HOME/ARCHIVIRT; TS=$(date -u +%Y%m%dT%H%M%SZ)
RUNID="VAL-${ENGINE}-${MODE}-${TS}"; LOGDIR="/var/log/archivirt/validation/$RUNID"
[ -e "$OUT" ] && { echo "REFUSED: $OUT already exists (results are never overwritten)"; exit 2; }
mkdir -p "$(dirname "$OUT")" && mkdir "$OUT" || exit 2; exec > >(tee -a "$OUT/driver.log") 2>&1
echo "== $RUNID (series $SERIES, NOT publishable)"
case "$ENGINE/$MODE" in suricata/ids|suricata/ips|snort3/ids|snort3/ips) ;; *) echo "bad engine/mode"; exit 2;; esac
RULES_LOCAL="$REPO/campaign_v1/validation/archivirt-validation-${MODE}.rules"
[ "$ENGINE" = snort3 ] && RULES_LOCAL="$REPO/campaign_v1/validation/archivirt-validation-snort3-${MODE}.rules"
[ -f "$RULES_LOCAL" ] || { echo "missing $RULES_LOCAL"; exit 2; }
RULES_REMOTE="/var/lib/archivirt/validation/$(basename "$RULES_LOCAL")"
sha256sum "$RULES_LOCAL" | tee "$OUT/rules.sha256"
$MON "sudo -n mkdir -p /var/lib/archivirt/validation '$LOGDIR' && sudo -n tee '$RULES_REMOTE' >/dev/null" < "$RULES_LOCAL"

svc_was=$($MON "systemctl is-active suricata" 2>/dev/null)
cleanup() {
  echo "-- cleanup"
  touch "$OUT/sampler.stop"
  $MON "if [ -f '$LOGDIR/engine.pid' ]; then p=\$(cat '$LOGDIR/engine.pid'); sudo -n kill -TERM \$p 2>/dev/null; for i in \$(seq 1 30); do sudo -n kill -0 \$p 2>/dev/null || break; sleep 1; done; sudo -n kill -0 \$p 2>/dev/null && sudo -n kill -KILL \$p; fi; true"
  if [ "$svc_was" = active ]; then $MON "sudo -n systemctl start suricata; systemctl is-active suricata" | sed 's/^/service suricata: /'; fi
}
trap cleanup EXIT

# 1. configuration check with ONLY the validation rules (rule file on disk != loaded: prove the load)
if [ "$ENGINE" = suricata ]; then
  $MON "sudo -n suricata -T -c /etc/suricata/suricata.yaml -S '$RULES_REMOTE' -l '$LOGDIR' > /tmp/val-T.log 2>&1; rc=\$?; grep -E 'rules successfully loaded|signatures processed|Error' /tmp/val-T.log; exit \$rc" | tee "$OUT/config_test.txt"
  grep -q '2 rules successfully loaded, 0 rules failed' "$OUT/config_test.txt" || { echo "STOP: validation rules not loaded as expected"; exit 3; }
else
  $MON "sudo -n /usr/local/bin/snort -c /etc/snort3/snort.lua -R '$RULES_REMOTE' --daq-dir /usr/local/lib/daq -T > /tmp/val-T.log 2>&1; rc=\$?; grep -iE 'rules loaded|text rules|Snort successfully validated|ERROR' /tmp/val-T.log | head -8; exit \$rc" | tee "$OUT/config_test.txt"
  grep -q 'successfully validated' "$OUT/config_test.txt" || { echo "STOP: snort -T failed"; exit 3; }
fi

# 2. dedicated engine instance (the packaged Suricata service is stopped during the run: one engine at a time)
$MON "sudo -n systemctl stop suricata; pgrep -a -f '[s]nort -c|[S]uricata' | grep -v systemd || true" | sed 's/^/engines before start: /'
# Capture-path parity (FINAL-reprise 2026-10-20, demonstrated): Suricata 6 disables NIC offloads (sg/tso/gso/gro) on its
# capture interfaces while it runs and re-enables them when it stops. With GRO back on, TSO super-frames (up to ~7.3 kB)
# reach ens6/ens7 and Snort's default snaplen truncates them (116:6, ~15 %). Re-apply the capture helper so that every
# engine sees per-wire frames, record the offload state with the run, and refuse to run if GRO is still on.
if [ "$MODE" = ids ]; then
  $MON "sudo -n /usr/local/sbin/archivirt-capture-ifaces.sh enable ens6 ens7 >/dev/null && for i in ens6 ens7; do echo \"\$i \$(ethtool -k \$i | grep -E '^(generic-receive-offload|rx-gro-hw|tcp-segmentation-offload|generic-segmentation-offload|scatter-gather):' | tr '\n' ' ')\"; done" | tee "$OUT/capture_offloads.txt"
  grep -q "generic-receive-offload: on" "$OUT/capture_offloads.txt" && { echo "STOP: GRO still on for the capture interfaces"; exit 3; }
fi
# Capture scope (FINAL 2026-10-20): Snort IDS listens on the same mirror outputs as Suricata (ens6+ens7,
# afpacket passive colon list). ARCHIVIRT_SNORT_IFACES=ens6 reproduces the earlier single-interface runs.
SNORT_IFACES="${ARCHIVIRT_SNORT_IFACES:-ens6:ens7}"
# Suricata capture scope (proposal 2026-10-21): ARCHIVIRT_SURICATA_IFACES=ens7 for the single-mirror comparison
SURICATA_IFACES="${ARCHIVIRT_SURICATA_IFACES:-ens6,ens7}"
case "$SURICATA_IFACES" in ens6|ens7|ens6,ens7|ens7,ens6) ;; *) echo "REFUSED: ARCHIVIRT_SURICATA_IFACES=$SURICATA_IFACES"; exit 2;; esac
SURICATA_AFP=$(echo "$SURICATA_IFACES" | tr "," "\n" | sed "s/^/--af-packet=/" | tr "\n" " ")
case "$SNORT_IFACES" in ens6|ens7|ens6:ens7|ens7:ens6) ;; *) echo "REFUSED: ARCHIVIRT_SNORT_IFACES=$SNORT_IFACES"; exit 2;; esac
echo "capture scope: suricata=$SURICATA_IFACES snort=$SNORT_IFACES" 
case "$ENGINE/$MODE" in
  suricata/ids) START="suricata -c /etc/suricata/suricata.yaml -S '$RULES_REMOTE' $SURICATA_AFP-l '$LOGDIR'";;
  suricata/ips) START="suricata -c /etc/suricata/suricata.yaml -S '$RULES_REMOTE' -q 0 -l '$LOGDIR'";;
  snort3/ids)   START="stdbuf -oL -eL /usr/local/bin/snort -c /etc/snort3/snort.lua -R '$RULES_REMOTE' --daq-dir /usr/local/lib/daq --daq afpacket --daq-mode passive -i $SNORT_IFACES -A alert_fast -l '$LOGDIR' -k none";;
  snort3/ips)   START="stdbuf -oL -eL /usr/local/bin/snort -c /etc/snort3/snort.lua -R '$RULES_REMOTE' --daq-dir /usr/local/lib/daq -Q --daq nfq --daq-var queue=0 -A alert_fast -l '$LOGDIR' -k none";;
esac
# launcher written on the monitor: all fds redirected, engine detached (setsid), pid recorded; ssh returns at once
printf '#!/bin/bash\ncd %q || exit 1\nexec > engine.out 2>&1 < /dev/null || exit 1\nsetsid %s &\necho $! > %q\n' "$LOGDIR" "$START" "$LOGDIR/engine.pid" \
  | $MON "sudo -n tee '$LOGDIR/launch.sh' > /dev/null"
timeout 30 $MON "sudo -n bash '$LOGDIR/launch.sh'; sleep 1; echo launched pid=\$(sudo -n cat '$LOGDIR/engine.pid')"
ready=0
for i in $(seq 1 90); do
  if $MON "sudo -n grep -qE 'engine started|Commencing packet processing' '$LOGDIR/engine.out'" 2>/dev/null; then ready=1; break; fi
  sleep 1
done
$MON "sudo -n grep -E 'engine started|Commencing|rules loaded|signatures processed|NFQ|DAQ|Error|ERROR' '$LOGDIR/engine.out' | head -12" | tee "$OUT/engine_start.txt"
[ $ready = 1 ] || { echo "STOP: engine not ready"; exit 4; }
[ "$MODE" = ips ] && $MON "sudo -n cat /proc/net/netfilter/nfnetlink_queue" | tee "$OUT/nfq_before.txt"

# 2b. EXPERIMENT mode: 1 Hz SSH sampler + reproducible load (200 HTTP GETs, latency per request)
if [ "${EXP:-0}" = 1 ]; then
  rm -f "$OUT/sampler.stop"; python3 -B "$(dirname "$0")/sampler.py" "$OUT/samples.jsonl" "$OUT/sampler.stop" "$KH" & SAMPLER=$!
  sleep 3
  date -u +%s.%N > "$OUT/load_start.txt"
  $ATT 'for i in $(seq 1 200); do t=10.0.2.1$((i % 3 + 1)); r=$(curl -s -o /dev/null -m 5 -w "%{http_code} %{time_total} %{size_download}" http://$t/); echo "$(date -u +%s.%N) $t $r"; done' > "$OUT/load.txt"
  date -u +%s.%N > "$OUT/load_end.txt"
fi

# 3. ground truth traffic from the attacker (lab only)
$ATT 'set -u; gt(){ echo "$(date -u +%FT%T.%3NZ) $*"; }
for t in 10.0.2.11 10.0.2.12 10.0.2.13; do for n in 1 2 3; do c=$(curl -s -o /dev/null -m 5 -w "%{http_code}" http://$t/); gt "LEGIT http GET $t -> $c"; done; p=$(ping -c 2 -W 2 $t | grep -oE "[0-9]+% packet loss"); gt "LEGIT ping $t -> $p"; done
sleep 2
for n in 1 2 3; do c=$(curl -s -o /dev/null -m 5 -A "ARCHIVIRT-VALIDATION-CANARY-7f3a" -w "%{http_code}" http://10.0.2.11/); gt "CANARY http UA -> 10.0.2.11 -> ${c}"; done
o=$(sudo -n hping3 -1 -c 3 -i u300000 -e ARCHIVIRT-ICMP-CANARY 10.0.2.11 2>&1 | grep -oE "[0-9]+ packets received|[0-9]+% packet loss" | tr "\n" " "); gt "CANARY icmp payload x3 -> 10.0.2.11 -> $o"
sleep 2
for t in 10.0.2.11 10.0.2.12; do c=$(curl -s -o /dev/null -m 5 -w "%{http_code}" http://$t/); gt "LEGIT-AFTER http GET $t -> $c"; done' | tee "$OUT/ground_truth.txt"
sleep 6
[ "$MODE" = ips ] && $MON "sudo -n cat /proc/net/netfilter/nfnetlink_queue" | tee "$OUT/nfq_after.txt"
if [ "${EXP:-0}" = 1 ]; then touch "$OUT/sampler.stop"; wait $SAMPLER 2>/dev/null; fi

# 4. stop the instance (flush), then collect
trap - EXIT; cleanup
$MON "sudo -n tar -C '$LOGDIR' -czf - ." > "$OUT/engine_logs.tgz"; (cd "$OUT" && mkdir -p logs && tar -xzf engine_logs.tgz -C logs)
python3 - "$OUT" "$ENGINE" "$MODE" <<'PY' | tee "$OUT/summary.txt"
import json, os, re, sys, collections, glob
out, eng, mode = sys.argv[1:4]; L = os.path.join(out, "logs")
gt = open(os.path.join(out, "ground_truth.txt")).read().splitlines()
alerts = collections.Counter(); actions = collections.Counter(); legit_alerts = 0
engine_events = collections.Counter()  # Snort builtin/decoder events (gid != 1): reported, never silently dropped
if eng == "suricata":
    f = os.path.join(L, "eve.json")
    for line in open(f) if os.path.exists(f) else []:
        try: e = json.loads(line)
        except ValueError: continue
        if e.get("event_type") == "alert":
            sid = e["alert"]["signature_id"]; alerts[sid] += 1; actions[(sid, e["alert"].get("action"))] += 1
    st = os.path.join(L, "stats.log"); last = {}
    for line in open(st) if os.path.exists(st) else []:
        m = re.match(r"^(\S+)\s+\|\s+Total\s+\|\s+(\d+)", line)
        if m: last[m.group(1)] = int(m.group(2))
    counters = {k: last.get(k, "MISSING") for k in ("capture.kernel_packets", "capture.kernel_drops", "decoder.pkts", "decoder.invalid", "decoder.event.ipv4.trunc_pkt", "ips.accepted", "ips.blocked", "ips.rejected", "ips.replaced")}
else:
    for f in glob.glob(os.path.join(L, "alert_fast*")):
        for line in open(f):
            g = re.search(r"\[(\d+):(\d+):\d+\]", line)
            if g and g.group(1) != "1":
                engine_events["%s:%s" % (g.group(1), g.group(2))] += 1
            m = re.search(r"\[1:(\d+):\d+\]", line)
            if m:
                sid = int(m.group(1)); alerts[sid] += 1
                act = re.search(r"\[(drop|alert|block|would_drop|would_block|reject)\]", line); actions[(sid, act.group(1) if act else "alert")] += 1
    # end-of-run DAQ / codec statistics of Snort (first occurrence of each counter in engine.out); absent = MISSING
    eo = os.path.join(L, "engine.out"); txt = open(eo).read() if os.path.exists(eo) else ""
    def first(name):
        m = re.search(r"^\s+%s:\s+(\d+)" % re.escape(name), txt, re.M)
        return int(m.group(1)) if m else "MISSING"
    counters = {"daq.received": first("received"), "daq.analyzed": first("analyzed"), "daq.dropped": first("dropped"),
                "codec.discards": first("discards"), "detection.total_alerts": first("total_alerts")}
legit_alerts = sum(v for k, v in alerts.items() if k not in (9100001, 9100002, 9100011, 9100012, 9200001, 9200002, 9200011, 9200012))
legit_http = [l for l in gt if l.split(" ", 1)[1].startswith("LEGIT http") or "LEGIT-AFTER" in l]
canary_http = [l for l in gt if "CANARY http" in l]
print(json.dumps({"engine": eng, "mode": mode, "alerts_by_sid": dict(alerts), "actions": {"%s/%s" % k: v for k, v in actions.items()},
                  "unexpected_alerts": legit_alerts, "engine_events_by_gid": dict(engine_events), "legit_http_codes": [l.rsplit(" ", 1)[1] for l in legit_http],
                  "canary_http_codes": [l.rsplit(" ", 1)[1] for l in canary_http], "counters": counters}, indent=1))
PY
[ "${EXP:-0}" = 1 ] && python3 -B "$(dirname "$0")/analyze_experiment.py" "$OUT" "$ENGINE" "$MODE" "$RUNID" "${ARCHIVIRT_EXP_PARAMS:?set ARCHIVIRT_EXP_PARAMS (series parameters file) for EXP=1}" | tee "$OUT/experiment_result.txt"
echo "== done $RUNID -> $OUT"
