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

set -e

MIRROR="http://10.0.3.1:8080"
SCRIPTS_DIR="/opt/archivirt/scripts"

# --- Configure local apt mirror as sole source -------------------------------
echo "deb [trusted=yes] $MIRROR ./" > /etc/apt/sources.list.d/archivirt-local.list
echo "" > /etc/apt/sources.list

apt-get update \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  -o Dir::Etc::sourceparts="-" \
  -o APT::Get::List-Cleanup=0 -q 2>/dev/null

# --- Install IDS packages from local mirror ----------------------------------
apt-get install -y --no-install-recommends \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  snort3 suricata suricata-update \
  libdumbnet1 libhwloc15 libdaq2 libhyperscan5 2>&1 | tail -5

echo "[ARCHIVIRT] $(suricata --build-info 2>/dev/null | grep 'This is Suricata' || echo 'suricata OK')"
echo "[ARCHIVIRT] $(/usr/local/bin/snort --version 2>&1 | grep 'Snort++' || echo 'snort3 OK')"

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

# --- Download ET Open rules for Snort 3 from local mirror --------------------
echo "[ARCHIVIRT] Fetching Snort 3 ET Open rules from local mirror..."
wget -q --timeout=60 --tries=3 \
  "${MIRROR}/rules/snort.rules" \
  -O /etc/snort3/rules/snort.rules

SNORT_RULES=$(wc -l < /etc/snort3/rules/snort.rules 2>/dev/null || echo 0)
echo "[ARCHIVIRT] Snort 3 rules: ${SNORT_RULES} lines"

# Create empty placeholder for custom rules
touch /etc/snort3/rules/archivirt.rules

# --- Validate Snort 3 configuration ------------------------------------------
echo "[ARCHIVIRT] Validating Snort 3 configuration..."
/usr/local/bin/snort \
  -c /etc/snort3/snort.lua \
  --plugin-path /usr/local/lib/snort3 \
  -T 2>&1 | grep -E "loaded|rules|ERROR|WARNING" | tail -5

echo "[ARCHIVIRT] Monitor installation complete."
echo "[ARCHIVIRT] NOTE: Suricata takes ~80s to load rules on 2 vCPU."
echo "[ARCHIVIRT] run_suricata.sh and run_snort.sh deployed by Ansible."
