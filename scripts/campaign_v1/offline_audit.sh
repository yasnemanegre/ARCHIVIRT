#!/usr/bin/env bash
# ARCHIVIRT campaign_v1 — collect host facts and run the offline readiness audit.
# READ-ONLY: probes presence/versions of local artifacts. Downloads NOTHING.
#
# Usage: offline_audit.sh [ENGINE] [SCENARIOS_CSV] [OUT_DIR]
#   ENGINE        : suricata (default) | snort3
#   SCENARIOS_CSV : e.g. "SCN-001" or "SCN-001,SCN-002" (default SCN-001)
#   OUT_DIR       : where readiness.json is written (default: a temp dir)
# Exit 0 if all required artifacts are READY, else 3.
set -uo pipefail

ROOT="/home/archivirt/ARCHIVIRT"
INVENTORY="$ROOT/ansible/inventory/hosts.ini"
MANIFEST="$ROOT/campaign_v1/manifest/offline_manifest.json"
AUDIT_PY="$ROOT/scripts/campaign_v1/offline_audit.py"

ENGINE="${1:-suricata}"
SCENARIOS="${2:-SCN-001}"
OUT_DIR="${3:-$(mktemp -d)}"
mkdir -p "$OUT_DIR"

ans() {
    ansible "$@" -i "$INVENTORY" \
        --ssh-extra-args='-o StrictHostKeyChecking=no -o ConnectTimeout=10'
}

MON_FACTS="$OUT_DIR/monitor_facts.txt"
ATT_FACTS="$OUT_DIR/attacker_facts.txt"

# --- Monitor (engine) facts ---
ans archivirt-monitor-ids -m shell -a '
  v=$(suricata -V 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1); echo "suricata_version=${v:-ABSENT}"
  if command -v snort >/dev/null 2>&1; then
    echo "snort3_version=$(snort --version 2>/dev/null | grep -oiE "Version [0-9.]+" | head -1 | grep -oE "[0-9.]+")"
  else echo "snort3_version=ABSENT"; fi
  d=$(dpkg-query -W -f="${Version}" libdaq3 2>/dev/null); echo "libdaq3_version=${d:-ABSENT}"
  [ -f /etc/suricata/rules/archivirt.rules ] && echo "suricata_rules_archivirt_file=PRESENT" || echo "suricata_rules_archivirt_file=ABSENT"
' 2>/dev/null | grep -E '^[a-z0-9_]+=' > "$MON_FACTS"

# --- Attacker (scenario) facts ---
ans archivirt-attacker -m shell -a '
  nv=$(nmap --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+" | head -1); echo "nmap_version=${nv:-ABSENT}"
  command -v hydra  >/dev/null 2>&1 && echo "hydra_version=$(hydra 2>&1 | grep -oE "v[0-9.]+" | head -1)" || echo "hydra_version=ABSENT"
  command -v sqlmap >/dev/null 2>&1 && echo "sqlmap_version=$(sqlmap --version 2>/dev/null | head -1)" || echo "sqlmap_version=ABSENT"
  pv=$(python3 --version 2>&1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+"); echo "python3_version=${pv:-ABSENT}"
  command -v curl >/dev/null 2>&1 && echo "curl_version=$(curl --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)" || echo "curl_version=ABSENT"
  [ -f /usr/share/wordlists/rockyou.txt ] && echo "rockyou_file=PRESENT" || echo "rockyou_file=ABSENT"
  [ -f /opt/archivirt/attack-scripts/slowloris.py ] && echo "slowloris_file=PRESENT" || echo "slowloris_file=ABSENT"
' 2>/dev/null | grep -E '^[a-z0-9_]+=' > "$ATT_FACTS"

python3 "$AUDIT_PY" "$MANIFEST" "$ENGINE" "$SCENARIOS" "$MON_FACTS" "$ATT_FACTS" \
    > "$OUT_DIR/readiness.json"
rc=$?
cat "$OUT_DIR/readiness.json"
echo "readiness.json: $OUT_DIR/readiness.json" >&2
exit $rc
