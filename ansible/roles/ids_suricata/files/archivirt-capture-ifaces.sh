#!/bin/sh
# ARCHIVIRT — IDS capture interfaces (PROPOSAL C1.3, F-07; supersedes C1.1 B2 helper).
#   archivirt-capture-ifaces.sh enable IFACE...   (IDS only) link up + promisc, verified
#   archivirt-capture-ifaces.sh disable IFACE...  promisc off (link left as is), verified
# Precondition for "enable": /etc/archivirt/ids-mode exists and contains exactly "ids".
#   - mode "ips"     -> exit 0 with "SKIPPED" (a leftover enabled unit can never re-enable promisc)
#   - missing/other  -> exit 6 (refuse: unknown mode = unsafe)
# Refuses lo/ens3/ens4/ens5 and any interface holding IPv4. Idempotent.
# "enable" also turns receive GRO off (rx-gro-hw, gro): with it on, mirrored GSO super-frames reached the
# engines truncated (Suricata ipv4.trunc_pkt, Snort 116:6 "datagram length > captured length", ~14 %;
# FINAL 2026-10-20). Verified after setting; "[fixed]" features are accepted as they are.
# Test hooks: ARCHIVIRT_SYSFS, ARCHIVIRT_IP, ARCHIVIRT_MODE_FILE, ARCHIVIRT_ETHTOOL.
set -eu
SYSFS="${ARCHIVIRT_SYSFS:-/sys/class/net}"; IPCMD="${ARCHIVIRT_IP:-ip}"; ETHTOOL="${ARCHIVIRT_ETHTOOL:-ethtool}"; MODEF="${ARCHIVIRT_MODE_FILE:-/etc/archivirt/ids-mode}"
ACTION="${1:-}"; [ "$#" -ge 2 ] || { echo "usage: $0 enable|disable IFACE..." >&2; exit 2; }
shift
case "$ACTION" in enable|disable) ;; *) echo "usage: $0 enable|disable IFACE..." >&2; exit 2;; esac
if [ "$ACTION" = enable ]; then
  [ -f "$MODEF" ] || { echo "REFUSED: $MODEF missing (mode unknown)" >&2; exit 6; }
  mode=$(cat "$MODEF")
  case "$mode" in
    ids) ;;
    ips) echo "SKIPPED: mode ips (capture interfaces must not be promiscuous)"; exit 0 ;;
    *) echo "REFUSED: unknown mode '$mode' in $MODEF" >&2; exit 6 ;;
  esac
fi
for i in "$@"; do
  case "$i" in lo|ens3|ens4|ens5|"") echo "REFUSED: $i is not a capture interface" >&2; exit 3 ;; esac
  [ -e "$SYSFS/$i" ] || { echo "MISSING: interface $i" >&2; exit 4; }
  if $IPCMD -4 -o addr show dev "$i" | grep inet >/dev/null; then echo "REFUSED: $i holds IPv4" >&2; exit 3; fi
  if [ "$ACTION" = enable ]; then
    $IPCMD link set dev "$i" up; $IPCMD link set dev "$i" promisc on
    for feat in rx-gro-hw gro; do
      $ETHTOOL -K "$i" "$feat" off 2>/dev/null || true
      state=$($ETHTOOL -k "$i" | sed -n "s/^generic-receive-offload:/gro:/; s/^$feat: //p" | head -1)
      case "$state" in off*|*fixed*|"") ;; *) echo "VERIFY_FAILED: $i $feat still '$state'" >&2; exit 5 ;; esac
    done
    flags=$(cat "$SYSFS/$i/flags"); [ $(( flags & 0x101 )) -eq $(( 0x101 )) ] || { echo "VERIFY_FAILED: $i flags=$flags" >&2; exit 5; }
  else
    $IPCMD link set dev "$i" promisc off
    flags=$(cat "$SYSFS/$i/flags"); [ $(( flags & 0x100 )) -eq 0 ] || { echo "VERIFY_FAILED: $i still promiscuous flags=$flags" >&2; exit 5; }
  fi
  echo "OK: $ACTION $i (flags=$flags)"
done
