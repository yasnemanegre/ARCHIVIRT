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

# STEP2: the root is the ARCHIVIRT tree containing this script (no hard-coded path); if ARCHIVIRT_ROOT
# is set it must designate that same tree (canonical), otherwise the audit refuses to run.
ROOT="$(realpath -e -- "$(dirname -- "$(realpath -e -- "${BASH_SOURCE[0]}")")/../..")"
if [ -n "${ARCHIVIRT_ROOT:-}" ] && [ "$(realpath -e -- "$ARCHIVIRT_ROOT" 2>/dev/null)" != "$ROOT" ]; then
    echo "ROOT_MISMATCH: ARCHIVIRT_ROOT=$ARCHIVIRT_ROOT is not $ROOT" >&2; exit 2
fi
INVENTORY="$ROOT/ansible/inventory/hosts.ini"
# B4 (proposal C1.1): the manifest is selected explicitly; v1 (Article-2) stays the default
# so that historical behaviour is unchanged. v2 adds generic, read-only file probes.
MANIFEST="${ARCHIVIRT_OFFLINE_MANIFEST:-$ROOT/campaign_v1/manifest/offline_manifest.json}"
[ -r "$MANIFEST" ] || { echo "MANIFEST_UNREADABLE: $MANIFEST" >&2; exit 2; }
V2_MON_PROBES=""; V2_ATT_PROBES=""
if python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("schema")=="archivirt-offline-manifest/2" else 1)' "$MANIFEST"; then
    V2_MON_PROBES="$(python3 "$ROOT/scripts/campaign_v1/offline_audit.py" --emit-file-probes "$MANIFEST" archivirt-monitor-ids)" || exit 2
    V2_ATT_PROBES="$(python3 "$ROOT/scripts/campaign_v1/offline_audit.py" --emit-file-probes "$MANIFEST" archivirt-attacker)" || exit 2
fi
AUDIT_PY="$ROOT/scripts/campaign_v1/offline_audit.py"

ENGINE="${1:-suricata}"
SCENARIOS="${2:-SCN-001}"
OUT_DIR="${3:-$(mktemp -d)}"
# STEP2: OUT_DIR is resolved BEFORE creation and refused inside any ARCHIVIRT tree (repository, clone,
# worktree: frozen results included). cycle/runs stays allowed (step 04 writes its audit there).
OUT_DIR="$(realpath -m -- "$OUT_DIR")"
_d="$OUT_DIR"; while :; do
    if [ -e "$_d/.git" ] && [ -f "$_d/scripts/campaign_v1/campaign_v1.sh" ]; then echo "OUT_DIR_REFUSED: $OUT_DIR is inside the ARCHIVIRT tree $_d" >&2; exit 2; fi
    [ "$_d" = / ] && break; _d="$(dirname -- "$_d")"
done
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
  # STEP3.2 (C-2): LibDAQ 3 is identified by the LIBRARY actually installed (pkg-config + libdaq.so.3),
  # distinguished from a dpkg package and never inferred from a source archive (host-side only).
  lv=$(PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/lib/pkgconfig pkg-config --modversion libdaq 2>/dev/null)
  so=$(ldconfig -p 2>/dev/null | grep -c "libdaq\.so\.3")
  pv=$(dpkg-query -W -f=\${Version} libdaq3 2>/dev/null)   # STEP3.2: escaped - the former -f="${Version}" was expanded (empty) by the remote shell -> always ABSENT
  echo "libdaq3_library_version=${lv:-ABSENT}"; echo "libdaq3_library_so=$([ "${so:-0}" -gt 0 ] && echo PRESENT || echo ABSENT)"
  echo "libdaq3_package_version=${pv:-ABSENT}"
  if [ -n "$lv" ] && [ "${so:-0}" -gt 0 ]; then echo "libdaq3_version=$lv"; echo "libdaq3_source=LIBRARY"
  elif [ -n "$pv" ]; then echo "libdaq3_version=$pv"; echo "libdaq3_source=PACKAGE_WITHOUT_LIBRARY"
  else echo "libdaq3_version=ABSENT"; echo "libdaq3_source=ABSENT"; fi
  [ -f /etc/suricata/rules/archivirt.rules ] && echo "suricata_rules_archivirt_file=PRESENT" || echo "suricata_rules_archivirt_file=ABSENT"
'"$V2_MON_PROBES" 2>/dev/null | grep -E '^[a-z0-9_]+=' > "$MON_FACTS"

# --- Attacker (scenario) facts ---
ans archivirt-attacker -m shell -a '
  nv=$(nmap --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+" | head -1); echo "nmap_version=${nv:-ABSENT}"
  command -v hydra  >/dev/null 2>&1 && echo "hydra_version=$(hydra 2>&1 | grep -oE "v[0-9.]+" | head -1)" || echo "hydra_version=ABSENT"
  command -v sqlmap >/dev/null 2>&1 && echo "sqlmap_version=$(sqlmap --version 2>/dev/null | head -1)" || echo "sqlmap_version=ABSENT"
  pv=$(python3 --version 2>&1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+"); echo "python3_version=${pv:-ABSENT}"
  command -v curl >/dev/null 2>&1 && echo "curl_version=$(curl --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)" || echo "curl_version=ABSENT"
  [ -f /usr/share/wordlists/rockyou.txt ] && echo "rockyou_file=PRESENT" || echo "rockyou_file=ABSENT"
  [ -f /opt/archivirt/attack-scripts/slowloris.py ] && echo "slowloris_file=PRESENT" || echo "slowloris_file=ABSENT"
'"$V2_ATT_PROBES" 2>/dev/null | grep -E '^[a-z0-9_]+=' > "$ATT_FACTS"

python3 "$AUDIT_PY" "$MANIFEST" "$ENGINE" "$SCENARIOS" "$MON_FACTS" "$ATT_FACTS" \
    > "$OUT_DIR/readiness.json"
rc=$?
cat "$OUT_DIR/readiness.json"
echo "readiness.json: $OUT_DIR/readiness.json" >&2
exit $rc
