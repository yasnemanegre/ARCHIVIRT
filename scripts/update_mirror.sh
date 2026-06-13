#!/bin/bash
# =============================================================================
# ARCHIVIRT - Update local apt mirror with all required packages and rules
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 4.0.0 — 2026-05-19
#
# Downloads ALL packages, dependencies, ET Open rules (Suricata + Snort 3)
# to the local apt mirror. Uses apt-cache depends --recurse for automatic
# full dependency resolution — no manual package listing needed.
#
# Must be run on the HOST (internet access required).
# VMs use this mirror exclusively (IaC option B — no direct internet).
#
# Mirror : /var/spool/apt-mirror/packages/
# Rules  : /var/spool/apt-mirror/packages/rules/
# nginx  : http://10.0.X.1:8080/
#
# Usage: sudo bash scripts/update_mirror.sh
# =============================================================================

set -e

MIRROR_DIR="/var/spool/apt-mirror/packages"
RULES_DIR="$MIRROR_DIR/rules"

# Ensure correct permissions from the start
mkdir -p "$MIRROR_DIR" "$RULES_DIR"
chown -R root:archivirt "$MIRROR_DIR" "$RULES_DIR" 2>/dev/null || true
chmod 775 "$MIRROR_DIR" "$RULES_DIR"

cd "$MIRROR_DIR"

echo "[ARCHIVIRT] Updating local apt mirror in $MIRROR_DIR ..."

# --- All top-level packages required by ARCHIVIRT VMs -----------------------
TOP_PACKAGES="nmap nmap-common hydra sqlmap hping3 tcpreplay python3-scapy \
  suricata suricata-update snort3 \
  libdumbnet1 libhwloc15 libdaq2 libhyperscan5 \
  apache2 libapache2-mod-php8.1 php8.1 php8.1-mysql \
  mariadb-server samba vsftpd openssh-server \
  influxdb2 telegraf \
  curl wget git python3"

echo "[ARCHIVIRT] Resolving full dependency tree..."
ALL_DEPS=$(apt-cache depends --recurse --no-recommends --no-suggests \
  --no-conflicts --no-breaks --no-replaces --no-enhances \
  $TOP_PACKAGES 2>/dev/null | grep "^\w" | sort -u | tr '\n' ' ')

COUNT=$(echo "$ALL_DEPS" | wc -w)
echo "[ARCHIVIRT] Total packages to download (including dependencies): $COUNT"

echo "[ARCHIVIRT] Downloading all packages..."
apt-get install --reinstall --download-only -y $ALL_DEPS 2>&1 | tail -3
cp /var/cache/apt/archives/*.deb "$MIRROR_DIR/" 2>/dev/null || true

# grafana
if ls "$MIRROR_DIR"/grafana*.deb 2>/dev/null | head -1 | grep -q grafana; then
  echo "[ARCHIVIRT] grafana already in mirror ✓"
else
  echo "[ARCHIVIRT] WARNING: grafana not found in mirror — add manually"
fi

# --- ET Open rules for Suricata 6.0.4 ----------------------------------------
echo "[ARCHIVIRT] Updating ET Open rules for Suricata..."
if which suricata-update > /dev/null 2>&1; then
  suricata-update add-source et/open \
    https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz \
    2>/dev/null || true
  suricata-update \
    --suricata-version 6.0.4 \
    --output "$RULES_DIR" \
    --no-reload 2>&1 | tail -5
  chmod 640 "$RULES_DIR/suricata.rules" 2>/dev/null || true
  RULE_COUNT=$(grep -c '^alert' "$RULES_DIR/suricata.rules" 2>/dev/null || echo 0)
  echo "[ARCHIVIRT] Suricata ET Open rules: $RULE_COUNT rules"
fi

# --- ET Open rules for Snort 3 -----------------------------------------------
echo "[ARCHIVIRT] Downloading ET Open rules for Snort 3..."
ET_SNORT3_URL="https://rules.emergingthreats.net/open/snort-3.0/emerging.rules.tar.gz"

curl -sL --max-time 120 "$ET_SNORT3_URL" -o /tmp/et-snort3.tar.gz

if file /tmp/et-snort3.tar.gz | grep -q "gzip"; then
  tar -xzf /tmp/et-snort3.tar.gz -C /tmp/
  cat /tmp/rules/*.rules > "$RULES_DIR/snort.rules"
  chmod 640 "$RULES_DIR/snort.rules"
  rm -rf /tmp/rules /tmp/et-snort3.tar.gz
  SNORT_COUNT=$(wc -l < "$RULES_DIR/snort.rules")
  echo "[ARCHIVIRT] Snort 3 ET Open rules: $SNORT_COUNT lines"
else
  echo "[ARCHIVIRT] WARNING: Snort 3 rules download failed"
fi

# --- Fix permissions ---------------------------------------------------------
chown -R root:archivirt "$RULES_DIR"
chmod 640 "$RULES_DIR"/*.rules 2>/dev/null || true

# --- Rebuild Packages index --------------------------------------------------
echo "[ARCHIVIRT] Rebuilding Packages index..."
dpkg-scanpackages . /dev/null 2>/dev/null | tee Packages > /dev/null
gzip -k -f Packages

PKG_COUNT=$(grep -c '^Package:' Packages)
TOTAL_SIZE=$(du -sh . | cut -f1)
echo "[ARCHIVIRT] Mirror updated: $PKG_COUNT packages, $TOTAL_SIZE"
echo "[ARCHIVIRT] Rules: Suricata=$(wc -l < $RULES_DIR/suricata.rules 2>/dev/null || echo 0) lines, Snort=$(wc -l < $RULES_DIR/snort.rules 2>/dev/null || echo 0) lines"
echo "[ARCHIVIRT] Served via: http://10.0.X.1:8080/"
echo "[ARCHIVIRT] Done. Run 'terraform destroy/apply' for clean deployment."
