#!/bin/bash
# ARCHIVIRT campaign_v1 — PREFLIGHT (report only, installs NOTHING).
# Reports, per scenario, whether its attacker prerequisites are present.
# Output per scenario: "<SCN>=READY" or "<SCN>=PREREQUISITE_MISSING(<what>)".
set +e

ROOT="/home/archivirt/ARCHIVIRT"
INVENTORY="$ROOT/ansible/inventory/hosts.ini"

ans() {
    ansible "$@" -i "$INVENTORY" \
        --ssh-extra-args='-o StrictHostKeyChecking=no -o ConnectTimeout=10'
}

echo "========== CAMPAIGN V1 PREFLIGHT =========="

echo
echo "===== MONITOR (Suricata engine) ====="
ans archivirt-monitor-ids -m shell -a '
    echo "HOST=$(hostname)"
    echo "SURICATA=$(suricata -V 2>&1 | head -1)"
    echo "FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
    echo "--- capture interfaces (expect ens6/ens7 for IDS, ens4/ens5 for IPS) ---"
    ip -br addr 2>/dev/null | grep -E "ens4|ens5|ens6|ens7" || echo "NONE"
    echo "--- build features ---"
    suricata --build-info 2>&1 | grep -Ei "NFQueue|AF_PACKET" || true
    echo "--- eve-log enabled in config ---"
    grep -A2 "eve-log" /etc/suricata/suricata.yaml 2>/dev/null | grep -E "enabled" | head -1 || echo "UNKNOWN"
'

echo
echo "===== ATTACKER — per-scenario prerequisites ====="
ans archivirt-attacker -m shell -a '
    report() { printf "%s=%s\n" "$1" "$2"; }

    # SCN-001 nmap
    if command -v nmap >/dev/null 2>&1; then report SCN-001 READY; \
    else report SCN-001 "PREREQUISITE_MISSING(nmap)"; fi

    # SCN-002 hydra + rockyou
    miss=""
    command -v hydra >/dev/null 2>&1 || miss="hydra"
    [ -f /usr/share/wordlists/rockyou.txt ] || miss="${miss:+$miss,}wordlist:/usr/share/wordlists/rockyou.txt"
    if [ -z "$miss" ]; then report SCN-002 READY; else report SCN-002 "PREREQUISITE_MISSING($miss)"; fi

    # SCN-003 sqlmap
    if command -v sqlmap >/dev/null 2>&1; then report SCN-003 READY; \
    else report SCN-003 "PREREQUISITE_MISSING(sqlmap)"; fi

    # SCN-004 slowloris
    miss=""
    command -v python3 >/dev/null 2>&1 || miss="python3"
    [ -f /opt/archivirt/attack-scripts/slowloris.py ] || miss="${miss:+$miss,}slowloris:/opt/archivirt/attack-scripts/slowloris.py"
    if [ -z "$miss" ]; then report SCN-004 READY; else report SCN-004 "PREREQUISITE_MISSING($miss)"; fi

    # SCN-005 benign
    if command -v curl >/dev/null 2>&1; then report SCN-005 READY; \
    else report SCN-005 "PREREQUISITE_MISSING(curl)"; fi
'

echo
echo "===== TARGETS (reachability) ====="
for host in archivirt-target-01 archivirt-target-02 archivirt-target-03; do
    if ans "$host" -m ping >/dev/null 2>&1; then
        echo "$host=SSH_OK"
    else
        echo "$host=UNREACHABLE"
    fi
done

echo
echo "========== PREFLIGHT END =========="
