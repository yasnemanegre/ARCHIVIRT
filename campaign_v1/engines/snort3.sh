#!/bin/bash
# ARCHIVIRT campaign_v1 — Snort 3 engine (common engine interface).
# Runs ON the monitor host (ansible -m script).
#
# Usage: snort3.sh <ids|ips> <logdir> [iface_csv]   (same contract as suricata.sh)
#
# ARCHIVIRT-LAB is OFFLINE: this engine NEVER downloads or installs anything.
# Until Snort 3 is provisioned from the local offline artifact set and a real
# qualification is validated, it refuses honestly with SNORT3_NOT_READY_OFFLINE
# and the exact list of missing artifacts — it does not pretend to be running.
set -uo pipefail

MODE="${1:?usage: snort3.sh <ids|ips> <logdir> [iface_csv]}"
LOGDIR="${2:?missing logdir}"
IFACES="${3:-ens6,ens7}"

missing=()
command -v snort >/dev/null 2>&1 || missing+=("snort3-binary")
dpkg-query -W -f='${Version}' libdaq3 >/dev/null 2>&1 || missing+=("libdaq3")

if [ "${#missing[@]}" -gt 0 ]; then
    echo "ARCHIVIRT_ENGINE=SNORT3_NOT_READY_OFFLINE mode=$MODE"
    echo "OFFLINE_ARTIFACT_MISSING=${missing[*]}"
    echo "NOTE=Snort 3 is not installable offline from the current local mirror"
    echo "NOTE=(mirror provides Snort 2.9 rules + libdaq2 only). No download attempted."
    exit 1
fi

# --- Provisioned path (only reached once Snort 3 is genuinely installed) ---
SNORT_VER="$(snort --version 2>/dev/null | grep -oiE 'Version [0-9.]+' | head -1)"
echo "ARCHIVIRT_ENGINE=SNORT3_DETECTED $SNORT_VER mode=$MODE"
# Deliberately NOT starting a campaign engine here: starting Snort 3 for real
# requires a validated config + qualification first (see master prompt §6/§12).
echo "ARCHIVIRT_ENGINE=SNORT3_START_NOT_YET_QUALIFIED"
exit 1
