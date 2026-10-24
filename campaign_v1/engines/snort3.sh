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

# STEP3.2 (C-1/C-2): exact reference versions; LibDAQ is checked as the LIBRARY actually installed
# (pkg-config + libdaq.so.3), not as a package name; the Ubuntu "snort" package (Snort 2.9) is refused.
SNORT3_VERSION="3.1.74.0"; LIBDAQ_VERSION="3.0.13"
missing=()
if dpkg-query -W -f='${Status}' snort 2>/dev/null | grep 'install ok installed' >/dev/null; then
    echo "ARCHIVIRT_ENGINE=SNORT2_PACKAGE_PRESENT mode=$MODE (Ubuntu 'snort' = Snort 2.9: refused)"; exit 1
fi
got_snort=$( { /usr/local/bin/snort -V 2>&1 || true; } | awk '!v { for (i = 1; i < NF; i++) if ($i == "Version") { v = $(i + 1); break } } END { print v }')
[ -x /usr/local/bin/snort ] || missing+=("snort3-binary")
[ -x /usr/local/bin/snort ] && [ "$got_snort" != "$SNORT3_VERSION" ] && missing+=("snort3-version:${got_snort:-unknown}!=$SNORT3_VERSION")
got_daq=$(PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --modversion libdaq 2>/dev/null)
ldconfig -p 2>/dev/null | grep -q 'libdaq\.so\.3' || missing+=("libdaq3-library")
[ -n "$got_daq" ] && [ "$got_daq" != "$LIBDAQ_VERSION" ] && missing+=("libdaq-version:$got_daq!=$LIBDAQ_VERSION")

if [ "${#missing[@]}" -gt 0 ]; then
    echo "ARCHIVIRT_ENGINE=SNORT3_NOT_READY_OFFLINE mode=$MODE"
    echo "OFFLINE_ARTIFACT_MISSING=${missing[*]}"
    echo "NOTE=Snort 3 is not installable offline from the current local mirror"
    echo "NOTE=Sources (snort3 3.1.74.0, libdaq 3.0.13) exist on the host only; build per role ids_snort. No download attempted."
    exit 1
fi

# --- Provisioned path (only reached once Snort 3 is genuinely installed) ---
SNORT_VER="Version $got_snort (LibDAQ $got_daq)"
echo "ARCHIVIRT_ENGINE=SNORT3_DETECTED $SNORT_VER mode=$MODE"
# Deliberately NOT starting a campaign engine here: starting Snort 3 for real
# requires a validated config + qualification first (see master prompt §6/§12).
echo "ARCHIVIRT_ENGINE=SNORT3_START_NOT_YET_QUALIFIED"
exit 1
