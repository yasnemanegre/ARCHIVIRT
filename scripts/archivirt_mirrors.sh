#!/bin/bash
# =============================================================================
# ARCHIVIRT - Configure OVS port mirroring for IDS traffic capture
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 3.0.0 — 2026-05-19
#
# Configures OVS port mirroring natively via ovs-vsctl.
# Mirrors all traffic from ovs-targets and ovs-attack bridges
# to the monitor VM capture port (ens4 / vnet connected to ovs-targets).
#
# This replaces the previous tc mirred approach which had limitations
# with libvirt bridge filtering. OVS native mirroring bypasses this.
#
# Usage: sudo bash archivirt_mirrors.sh
# Called by: suricata_scenario.yml (Play 1 and Play 2)
# =============================================================================

set -euo pipefail

MONITOR_BRIDGE="ovs-targets"
MIRROR_NAME="archivirt-ids-mirror"

# --- Detect monitor capture port on OVS bridge -------------------------------
MONITOR_PORT=$(sudo virsh domiflist archivirt-monitor-ids 2>/dev/null | \
  grep "archivirt-net-targets\|ovs-targets" | \
  awk '{print $1}' | grep -v "^-$" | head -1)

if [ -z "$MONITOR_PORT" ]; then
  echo "❌ ERROR: monitor capture port not found on ovs-targets bridge"
  echo "   Ensure archivirt-monitor-ids is running and connected to ovs-targets"
  exit 1
fi

echo "[ARCHIVIRT] Monitor capture port: $MONITOR_PORT"

# --- Remove existing mirror (idempotent) -------------------------------------
sudo ovs-vsctl --if-exists destroy Mirror $MIRROR_NAME 2>/dev/null || true

# Clear existing mirror references from bridges
for bridge in ovs-targets ovs-attack; do
  sudo ovs-vsctl clear Bridge $bridge mirrors 2>/dev/null || true
done

# --- Configure OVS port mirror -----------------------------------------------
# Mirror ALL traffic from ovs-targets and ovs-attack to monitor capture port

# Get all ports on ovs-targets (except monitor port itself)
TARGETS_PORTS=$(sudo ovs-vsctl list-ports ovs-targets 2>/dev/null | \
  grep -v "^${MONITOR_PORT}$" | \
  while read p; do echo "--id=@${p} get Port ${p}"; done)

# Get all ports on ovs-attack
ATTACK_PORTS=$(sudo ovs-vsctl list-ports ovs-attack 2>/dev/null | \
  while read p; do echo "--id=@${p} get Port ${p}"; done)

# Get monitor output port ID
MONITOR_PORT_ID=$(sudo ovs-vsctl get Port $MONITOR_PORT _uuid 2>/dev/null || echo "")

if [ -z "$MONITOR_PORT_ID" ]; then
  # Add monitor port to ovs-targets if not present
  sudo ovs-vsctl --may-exist add-port ovs-targets $MONITOR_PORT
fi

# Create mirror: all traffic on ovs-targets and ovs-attack → monitor port
sudo ovs-vsctl \
  -- --id=@mirror_out get Port $MONITOR_PORT \
  -- --id=@m create Mirror \
       name=$MIRROR_NAME \
       select-all=true \
       output-port=@mirror_out \
  -- add Bridge $MONITOR_BRIDGE mirrors @m

# Create SEPARATE mirror on ovs-attack (one Mirror object per OVS bridge required)
sudo ovs-vsctl --if-exists destroy Mirror "${MIRROR_NAME}-attack" 2>/dev/null || true
sudo ovs-vsctl \
  -- --id=@mirror_out2 get Port $MONITOR_PORT \
  -- --id=@m2 create Mirror \
       name="${MIRROR_NAME}-attack" \
       select-all=true \
       output-port=@mirror_out2 \
  -- add Bridge ovs-attack mirrors @m2

echo "✅ OVS mirrors configured: ovs-targets AND ovs-attack → $MONITOR_PORT"

# --- Verify mirror -----------------------------------------------------------
echo "[ARCHIVIRT] Mirror status:"
sudo ovs-vsctl list Mirror $MIRROR_NAME 2>/dev/null | \
  grep -E "name|output|select" || echo "Mirror not found — check logs"

# --- Show OVS topology -------------------------------------------------------
echo "[ARCHIVIRT] OVS bridges:"
sudo ovs-vsctl show | grep -E "Bridge|Port|Mirror" | head -30
