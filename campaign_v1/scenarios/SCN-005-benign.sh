#!/bin/bash
# ARCHIVIRT campaign_v1 — SCN-005 Benign/Normal traffic. SINGLE SOURCE OF TRUTH.
# Runs ON the attacker (ansible -m script).
# Baseline for false-positive rate: NO alert is the expected outcome, so a run
# with zero alerts is still a VALID run (see validate_run.py expected_detection).
set -uo pipefail

TARGET="${ARCHIVIRT_BENIGN_URL:-http://10.0.2.11/}"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

echo "ARCHIVIRT_SCENARIO=SCN-005"

if ! command -v curl >/dev/null 2>&1; then
    echo "ARCHIVIRT_PREREQUISITE_MISSING=curl"
    exit 0
fi

echo "ARCHIVIRT_ATTACK_START=$(ts)"
for _i in $(seq 1 20); do
    curl -fsS --max-time 5 "$TARGET" >/dev/null || true
    sleep 1
done
rc=0
echo "ARCHIVIRT_ATTACK_END=$(ts)"
echo "ARCHIVIRT_ATTACK_RC=$rc"
