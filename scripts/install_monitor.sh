#!/bin/bash
# =============================================================================
# ARCHIVIRT - Install and configure IDS packages on monitor VM
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 3.0.0 — 2026-05-19
#
# IaC Option B: all packages and rules served from local apt mirror only.
# The monitor VM has NO direct internet access.
#
# Package sources  : http://10.0.3.1:8080/
# Suricata rules   : http://10.0.3.1:8080/rules/suricata.rules (ET Open 49778)
# Snort 3 rules    : http://10.0.3.1:8080/rules/snort.rules (ET Open Snort3)
# Both rulesets pre-downloaded on host by scripts/update_mirror.sh
#
# Do NOT add external apt sources — IaC option B enforced.
# =============================================================================

set -euo pipefail

MIRROR="http://10.0.3.1:8080"
LOG=/var/log/archivirt-bootstrap.log
exec > >(tee -a "$LOG") 2>&1
SCRIPTS_DIR="/opt/archivirt/scripts"

# --- Configure local apt mirror as sole source -------------------------------
echo "deb [trusted=yes] $MIRROR ./" > /etc/apt/sources.list.d/archivirt-local.list
echo "" > /etc/apt/sources.list

apt-get update \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  -o Dir::Etc::sourceparts="-" \
  -o APT::Get::List-Cleanup=0 -q

APT_OPTS=(-y --no-install-recommends -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list)

# --- Required IDS packages (Suricata stack): fail loudly if missing ----------
# Installed one by one so that an absent optional package can never abort them.
# STEP3.2 (C-3): libdaq2 (DAQ of Snort 2.9) removed: required by neither Suricata nor Snort 3.
for pkg in libdumbnet1 libhwloc15 libhyperscan5 suricata suricata-update; do
  if ! apt-cache policy "$pkg" | grep 'Candidate: [^(]' >/dev/null; then
    echo "[ARCHIVIRT] OFFLINE_ARTIFACT_MISSING=$pkg (required)"
    exit 1
  fi
  apt-get install "${APT_OPTS[@]}" "$pkg"
done
echo "[ARCHIVIRT] $(suricata --build-info | grep 'This is Suricata')"

# --- Optional: Snort 3 (not provided by the Ubuntu 22.04 mirror) ------------
# STEP3.2: only the LOCAL package "snort3" at the reference version is accepted (never the Ubuntu
# package "snort" = Snort 2.9, never an unpinned candidate). A candidate with another version is a
# contradictory mirror state -> explicit failure. After installation, Snort AND the LibDAQ library
# actually loaded are verified (library version via pkg-config, not a package name).
SNORT3_VERSION="3.1.74.0"; LIBDAQ_VERSION="3.0.13"
SNORT3_AVAILABLE=0
# (no early-exit reader under pipefail: SIGPIPE false negatives, cf. R1 2026-10-19)
if dpkg-query -W -f='${Status}' snort 2>/dev/null | grep 'install ok installed' >/dev/null; then
  echo "[ARCHIVIRT] ERROR: Ubuntu package 'snort' (Snort 2.9) is installed; refusing."
  exit 1
fi
SNORT3_CAND="$(apt-cache policy snort3 | awk '/Candidate:/ {print $2}')"
if [ -z "$SNORT3_CAND" ] || [ "$SNORT3_CAND" = "(none)" ]; then
  echo "[ARCHIVIRT] OFFLINE_ARTIFACT_MISSING=snort3 (optional — Snort 3 setup skipped)"
elif [ "$SNORT3_CAND" != "$SNORT3_VERSION" ]; then
  echo "[ARCHIVIRT] ERROR: snort3 candidate $SNORT3_CAND != reference $SNORT3_VERSION (contradictory mirror); refusing."
  exit 1
else
  apt-get install "${APT_OPTS[@]}" "snort3=$SNORT3_VERSION"
  got_snort="$(/usr/local/bin/snort -V 2>&1 | awk '!v { for (i = 1; i < NF; i++) if ($i == "Version") { v = $(i + 1); break } } END { print v }')"
  got_daq="$(PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --modversion libdaq 2>/dev/null || echo ABSENT)"
  if [ "$got_snort" != "$SNORT3_VERSION" ] || [ "$got_daq" != "$LIBDAQ_VERSION" ]; then
    echo "[ARCHIVIRT] ERROR: installed Snort '$got_snort' / LibDAQ library '$got_daq' != $SNORT3_VERSION / $LIBDAQ_VERSION"
    exit 1
  fi
  SNORT3_AVAILABLE=1
  echo "[ARCHIVIRT] Snort $got_snort with LibDAQ library $got_daq"
fi

# --- Create ARCHIVIRT scripts directory --------------------------------------
mkdir -p "$SCRIPTS_DIR"

# =============================================================================
# SURICATA CONFIGURATION
# =============================================================================

# --- Download ET Open rules for Suricata from local mirror -------------------
echo "[ARCHIVIRT] Fetching Suricata ET Open rules from local mirror..."
mkdir -p /etc/suricata/rules

wget -q --timeout=60 --tries=3 \
  "${MIRROR}/rules/suricata.rules" \
  -O /etc/suricata/rules/suricata.rules

SURICATA_RULES=$(grep -c '^alert' /etc/suricata/rules/suricata.rules 2>/dev/null || echo 0)
echo "[ARCHIVIRT] Suricata rules: ${SURICATA_RULES} rules"

if [ "$SURICATA_RULES" -lt 1000 ]; then
  echo "[ARCHIVIRT] ERROR: Suricata rule count too low, aborting."
  exit 1
fi

# Create empty placeholder for custom rules
touch /etc/suricata/rules/archivirt-local.rules

# =============================================================================
# SNORT 3 CONFIGURATION
# =============================================================================

# --- Create Snort 3 configuration directory ----------------------------------
echo "[ARCHIVIRT] Configuring Snort 3..."
mkdir -p /etc/snort3/rules
mkdir -p /usr/local/etc/snort

# --- snort_defaults.lua — network variables ----------------------------------
cat > /usr/local/etc/snort/snort_defaults.lua << 'DEFAULTSEOF'
-- ARCHIVIRT Snort 3 defaults
HOME_NET = '10.0.0.0/8'
EXTERNAL_NET = '!$HOME_NET'
HTTP_SERVERS = '$HOME_NET'
SMTP_SERVERS = '$HOME_NET'
SQL_SERVERS = '$HOME_NET'
DNS_SERVERS = '$HOME_NET'
SSH_SERVERS = '$HOME_NET'
FTP_SERVERS = '$HOME_NET'
SIP_SERVERS = '$HOME_NET'
HTTP_PORTS = '80'
SHELLCODE_PORTS = '!80'
ORACLE_PORTS = 1521
SSH_PORTS = 22
FTP_PORTS = '21'
DEFAULTSEOF

# --- snort.lua — main configuration ------------------------------------------
cat > /etc/snort3/snort.lua << 'SNORTEOF'
-- ARCHIVIRT Snort 3.1.74.0 configuration
-- IDS passive mode on ens4 (OVS transit mirror interface)
include '/usr/local/etc/snort/snort_defaults.lua'
ips = {
  enable_builtin_rules = true,
  rules = [[
    include /etc/snort3/rules/snort.rules
    include /etc/snort3/rules/archivirt.rules
  ]]
}
alert_fast = { file = true, packet = false }
alert_json = { file = true, limit = 100 }
SNORTEOF

# --- Download ET Open rules for Snort 3 from local mirror (only if Snort 3) --
if [ "$SNORT3_AVAILABLE" -eq 1 ]; then
  echo "[ARCHIVIRT] Fetching Snort 3 ET Open rules from local mirror..."
  wget -q --timeout=60 --tries=3 \
    "${MIRROR}/rules/snort.rules" \
    -O /etc/snort3/rules/snort.rules
  SNORT_RULES=$(wc -l < /etc/snort3/rules/snort.rules)
  echo "[ARCHIVIRT] Snort 3 rules: ${SNORT_RULES} lines"
  if [ "$SNORT_RULES" -lt 1000 ]; then
    echo "[ARCHIVIRT] ERROR: Snort 3 rule count too low, aborting."
    exit 1
  fi
else
  echo "[ARCHIVIRT] Snort 3 rules download skipped (snort3 not installed)"
fi

# Create empty placeholder for custom rules
touch /etc/snort3/rules/archivirt.rules

# --- Validate Snort 3 configuration ------------------------------------------
if [ "$SNORT3_AVAILABLE" -eq 1 ]; then
  echo "[ARCHIVIRT] Validating Snort 3 configuration..."
  /usr/local/bin/snort \
    -c /etc/snort3/snort.lua \
    --plugin-path /usr/local/lib/snort3 \
    -T > /var/log/archivirt-snort3-validate.log 2>&1
  # display only (the validation itself already failed the script under set -e if snort -T failed)
  grep -E "loaded|rules|ERROR|WARNING" /var/log/archivirt-snort3-validate.log | tail -5 || echo "[ARCHIVIRT] (no summary line in the validation log)"
else
  echo "[ARCHIVIRT] Snort 3 validation skipped (snort3 not installed)"
fi

echo "[ARCHIVIRT] Monitor installation complete."
echo "[ARCHIVIRT] NOTE: Suricata takes ~80s to load rules on 2 vCPU."
echo "[ARCHIVIRT] run_suricata.sh and run_snort.sh deployed by Ansible."
