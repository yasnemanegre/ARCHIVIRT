#!/bin/bash
# ARCHIVIRT campaign_v1 — SCN-001 Port Scan (nmap). SINGLE SOURCE OF TRUTH.
# Runs ON the attacker (ansible -m script). Emits machine-readable markers on
# stdout so the orchestrator never has to re-encode the attack command.
#   ARCHIVIRT_SCENARIO / ARCHIVIRT_PREREQUISITE_MISSING /
#   ARCHIVIRT_ATTACK_START / ARCHIVIRT_ATTACK_END / ARCHIVIRT_ATTACK_RC
set -uo pipefail

TARGETS="${ARCHIVIRT_TARGETS:-10.0.2.11 10.0.2.12 10.0.2.13}"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

echo "ARCHIVIRT_SCENARIO=SCN-001"

if ! command -v nmap >/dev/null 2>&1; then
    echo "ARCHIVIRT_PREREQUISITE_MISSING=nmap"
    exit 0
fi

echo "ARCHIVIRT_ATTACK_START=$(ts)"
sudo timeout 60 nmap -sS -Pn -p 1-1024 --min-rate 1000 -T4 $TARGETS
rc=$?
echo "ARCHIVIRT_ATTACK_END=$(ts)"
echo "ARCHIVIRT_ATTACK_RC=$rc"
