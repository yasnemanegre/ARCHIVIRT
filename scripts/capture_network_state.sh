#!/bin/bash
# =============================================================================
# ARCHIVIRT - Capture the network state of the lab (READ-ONLY)
# =============================================================================
# Records, for the host and every VM of the inventory: IPv4 addresses, routes,
# ip_forward, NFQUEUE / FORWARD rules and the inline-routing unit status.
# Intended to be run before and after any IPS test or campaign and stored with
# the campaign provenance. Changes nothing.
#
# Usage: scripts/capture_network_state.sh <output-dir>
# =============================================================================
set -euo pipefail

OUT="${1:?usage: $0 <output-dir>}"
mkdir -p "$OUT"
cd "$(dirname "$0")/.."

ts=$(date -u +%FT%TZ)
echo "captured_at=$ts" > "$OUT/meta.txt"

{
  echo "## host $(hostname)"
  echo "# ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"
  ip -4 -o addr show | awk '{print "addr", $2, $4}'
  ip -4 route show | sed 's/^/route /'
  sudo -n iptables -S FORWARD 2>/dev/null | sed 's/^/fw /' || echo "fw (iptables needs sudo)"
} > "$OUT/host.txt"

python3 scripts/gen_lab_names.py --hosts | awk '$1 ~ /^10\./ {print $2}' | while read -r vm; do
  ssh -o BatchMode=yes -o ConnectTimeout=5 "$vm" 'bash -s' > "$OUT/$vm.txt" 2>&1 <<'EOF' || echo "UNREACHABLE" >> "$OUT/$vm.txt"
echo "## $(hostname)"
echo "# ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"
ip -4 -o addr show scope global | awk '{print "addr", $2, $4}'
ip -4 route show | sed 's/^/route /'
for d in 10.0.2.11 10.0.4.10; do echo "route_get $d $(ip route get $d 2>/dev/null | head -1)"; done
echo "nfqueue_rules=$(sudo -n iptables -S 2>/dev/null | grep -c NFQUEUE || true)"
echo "inline_unit=$(systemctl is-enabled archivirt-inline-routing.service 2>/dev/null || echo absent)/$(systemctl is-active archivirt-inline-routing.service 2>/dev/null || true)"
EOF
done

(cd "$OUT" && sha256sum ./*.txt > SHA256SUMS)
echo "network state captured in $OUT ($ts)"
