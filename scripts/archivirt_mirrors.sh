#!/bin/bash
# =============================================================================
# ARCHIVIRT - Configure OVS port mirroring for IDS traffic capture
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 3.0.0 — 2026-05-19
#
# Configures OVS port mirroring natively via ovs-vsctl.
# Mirrors ovs-attack traffic to the monitor VM IDS capture interface ens6
# and ovs-targets traffic to the monitor VM IDS capture interface ens7.
#
# This replaces the previous tc mirred approach which had limitations
# with libvirt bridge filtering. OVS native mirroring bypasses this.
#
# Usage: sudo bash archivirt_mirrors.sh
# Called by: suricata_scenario.yml (Play 1 and Play 2)
# =============================================================================

set -euo pipefail

IDS_ATTACK_INTERFACE="ens6"
IDS_TARGET_INTERFACE="ens7"
MIRROR_ATTACK="archivirt-ids-mirror-attack"
MIRROR_TARGET="archivirt-ids-mirror-targets"

get_monitor_port() {
  local bridge="$1"
  local mac="$2"

  sudo virsh domiflist archivirt-monitor-ids 2>/dev/null |
    awk -v b="$bridge" -v m="$mac" '$3 == b && $5 == m {print $1; exit}'
}

get_port_id() {
  sudo ovs-vsctl get Port "$1" _uuid 2>/dev/null
}

# Resolve the dedicated IDS capture ports by their fixed libvirt MAC addresses.
# ens6 is the passive capture interface connected to ovs-attack.
# ens7 is the passive capture interface connected to ovs-targets.
IDS_ATTACK_MAC="52:54:00:8c:8b:e0"
IDS_TARGET_MAC="52:54:00:8c:8b:e1"

ATTACK_MAC="$IDS_ATTACK_MAC"
TARGET_MAC="$IDS_TARGET_MAC"

if [ -z "$ATTACK_MAC" ] || [ -z "$TARGET_MAC" ]; then
  echo "ERROR: IDS capture interfaces could not be resolved from libvirt"
  exit 1
fi

ATTACK_PORT=$(get_monitor_port "ovs-attack" "$ATTACK_MAC")
TARGET_PORT=$(get_monitor_port "ovs-targets" "$TARGET_MAC")

if [ -z "$ATTACK_PORT" ] || [ -z "$TARGET_PORT" ]; then
  echo "ERROR: IDS capture ports could not be resolved"
  exit 1
fi

echo "[ARCHIVIRT] IDS attack capture: $ATTACK_PORT -> $IDS_ATTACK_INTERFACE"
echo "[ARCHIVIRT] IDS target capture: $TARGET_PORT -> $IDS_TARGET_INTERFACE"

sudo ovs-vsctl --if-exists destroy Mirror "$MIRROR_ATTACK" 2>/dev/null || true
sudo ovs-vsctl --if-exists destroy Mirror "$MIRROR_TARGET" 2>/dev/null || true

sudo ovs-vsctl clear Bridge ovs-attack mirrors
sudo ovs-vsctl clear Bridge ovs-targets mirrors

sudo ovs-vsctl \
  -- --id=@attack_out get Port "$ATTACK_PORT" \
  -- --id=@attack_mirror create Mirror \
       name="$MIRROR_ATTACK" \
       select-all=true \
       output-port=@attack_out \
  -- add Bridge ovs-attack mirrors @attack_mirror

sudo ovs-vsctl \
  -- --id=@target_out get Port "$TARGET_PORT" \
  -- --id=@target_mirror create Mirror \
       name="$MIRROR_TARGET" \
       select-all=true \
       output-port=@target_out \
  -- add Bridge ovs-targets mirrors @target_mirror

echo "OVS IDS mirrors configured:"
echo "  ovs-attack  -> $ATTACK_PORT ($IDS_ATTACK_INTERFACE)"
echo "  ovs-targets -> $TARGET_PORT ($IDS_TARGET_INTERFACE)"

echo "[ARCHIVIRT] Mirror status:"
sudo ovs-vsctl --columns=name,output_port,select_all,statistics list Mirror \
  | grep -E "name|output_port|select_all|statistics" || true

# --- Show OVS topology -------------------------------------------------------
echo "[ARCHIVIRT] OVS bridges:"
sudo ovs-vsctl show | grep -E "Bridge|Port|Mirror" | head -30
