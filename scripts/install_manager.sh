#!/bin/bash
# =============================================================================
# ARCHIVIRT - Manager VM bootstrap (cloud-init runcmd)
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 3.0.0 — 2026-10-17
#
# Responsibility split (single provisioning path):
#   cloud-init (this script) : point APT to the local mirror and verify that
#                              the monitoring packages are available offline.
#   Ansible role "manager"   : install pinned InfluxDB2/Telegraf (+ Grafana if
#                              archivirt_grafana_enabled=true),
#                              configure them with secrets from ansible-vault,
#                              validate the chain end-to-end.
# No secret is handled here (cloud-init user-data ends up in Terraform state).
#
# Offline-first: mirror only (http://10.0.5.1:8080/). Missing artefacts are
# reported with OFFLINE_ARTIFACT_MISSING and make the script fail.
# =============================================================================

set -euo pipefail

MIRROR="${ARCHIVIRT_MIRROR:-http://10.0.5.1:8080}"
LOG=/var/log/archivirt-bootstrap.log
REQUIRED_PACKAGES="influxdb2 influxdb2-cli telegraf"   # metric collection/storage
OPTIONAL_PACKAGES="grafana"                            # UI, archivirt_grafana_enabled

exec > >(tee -a "$LOG") 2>&1
echo "[ARCHIVIRT] manager bootstrap start $(date -u +%FT%TZ) mirror=$MIRROR"

echo "deb [trusted=yes] $MIRROR ./" > /etc/apt/sources.list.d/archivirt-local.list

apt-get update \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  -o Dir::Etc::sourceparts="-" \
  -o APT::Get::List-Cleanup=0 -q

missing=0
for pkg in $REQUIRED_PACKAGES; do
  candidate=$(apt-cache policy "$pkg" | awk '/Candidate:/ {print $2}')
  if [ -z "$candidate" ] || [ "$candidate" = "(none)" ]; then
    echo "[ARCHIVIRT] OFFLINE_ARTIFACT_MISSING=$pkg (not in local mirror $MIRROR)"
    missing=1
  else
    echo "[ARCHIVIRT] mirror provides $pkg=$candidate"
  fi
done

for pkg in $OPTIONAL_PACKAGES; do
  candidate=$(apt-cache policy "$pkg" | awk '/Candidate:/ {print $2}')
  if [ -z "$candidate" ] || [ "$candidate" = "(none)" ]; then
    echo "[ARCHIVIRT] OFFLINE_ARTIFACT_MISSING=$pkg (optional — only required if archivirt_grafana_enabled=true)"
  else
    echo "[ARCHIVIRT] mirror provides $pkg=$candidate (optional)"
  fi
done

if [ "$missing" -ne 0 ]; then
  echo "[ARCHIVIRT] manager bootstrap FAILED: local mirror incomplete"
  exit 1
fi

echo "[ARCHIVIRT] manager bootstrap OK — run Ansible role 'manager' to install and configure monitoring"
