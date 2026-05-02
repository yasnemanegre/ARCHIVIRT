#!/bin/bash
# ARCHIVIRT - Auto-detect and apply tc mirrors
MONITOR_VNET=$(sudo virsh domiflist archivirt-monitor-ids | grep targets | awk '{print $1}')
echo "Monitor vnet: $MONITOR_VNET"
for VNET in $(bridge link show | grep virbr3 | awk '{print $2}' | tr -d ':'); do
  sudo tc qdisc del dev $VNET ingress 2>/dev/null || true
  sudo tc qdisc add dev $VNET ingress
  sudo tc filter add dev $VNET parent ffff: \
    protocol all u32 match u8 0 0 \
    action mirred egress mirror dev $MONITOR_VNET
  echo "✅ Mirror: $VNET -> $MONITOR_VNET"
done
# Attacker vnet on virbr2
for VNET in $(bridge link show | grep virbr2 | awk '{print $2}' | tr -d ':'); do
  sudo tc qdisc del dev $VNET ingress 2>/dev/null || true
  sudo tc qdisc add dev $VNET ingress
  sudo tc filter add dev $VNET parent ffff: \
    protocol all u32 match u8 0 0 \
    action mirred egress mirror dev $MONITOR_VNET
  echo "✅ Mirror: $VNET -> $MONITOR_VNET"
done
