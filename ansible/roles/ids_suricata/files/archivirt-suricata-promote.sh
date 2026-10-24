#!/bin/bash
# ARCHIVIRT — validate-then-promote Suricata configuration (PROPOSAL C1.3, F-06).
# 1) candidates are prepared SEPARATELY in $CAND (yaml + rules/*.rules) by the role;
# 2) candidate validated with: suricata -T -c $CAND/suricata.yaml --set default-rule-path=$CAND/rules
#    -> on failure NOTHING active is touched (exit 10);
# 3) unchanged candidates -> "unchanged" (exit 0, no backup, no restart);
# 4) backup of the active files to $BKP/<UTC>/ + SHA256SUMS, then atomic replacement (same dir
#    temp + mv) of each changed file;
# 5) post-validation of the ACTIVE configuration; on failure -> restore the backup byte-for-byte
#    and exit 11 (active state = previous state);
# 6) prints "promoted <backup_dir>" and writes $BKP/LAST (path of the last good backup).
# Never restarts any service. Rollback: archivirt-suricata-promote.sh --rollback <backup_dir>.
# Test hooks: SURI_ACTIVE (default /etc/suricata), SURI_CAND, SURI_BKP, SURICATA_BIN.
set -uo pipefail
ACT="${SURI_ACTIVE:-/etc/suricata}"; CAND="${SURI_CAND:-/etc/suricata/archivirt-candidate}"
BKP="${SURI_BKP:-/var/backups/archivirt/suricata}"; SURI="${SURICATA_BIN:-/usr/bin/suricata}"
FILES="suricata.yaml rules/archivirt-local.rules rules/archivirt-ips.rules"
die() { echo "PROMOTE_ERROR: $*" >&2; exit "${2:-12}"; }
restore() {  # $1 backup dir
  local b="$1"; ( cd "$b" && sha256sum -c --quiet SHA256SUMS ) || die "backup $b corrupted - manual action required" 13
  for f in $FILES; do
    if [ -f "$b/$f" ]; then cp -p "$b/$f" "$ACT/$f.archivirt-tmp" && mv -f "$ACT/$f.archivirt-tmp" "$ACT/$f"
    elif [ -f "$b/$f.absent" ]; then rm -f "$ACT/$f"; fi
  done
}
if [ "${1:-}" = "--rollback" ]; then [ -d "${2:-}" ] || die "usage: --rollback <backup_dir>" 2; restore "$2"; echo "rolled-back $2"; exit 0; fi
[ -f "$CAND/suricata.yaml" ] || die "candidate suricata.yaml missing" 2
"$SURI" -T -c "$CAND/suricata.yaml" --set "default-rule-path=$CAND/rules" -l /tmp >"$CAND/validate.log" 2>&1 \
  || die "candidate configuration rejected by suricata -T (nothing active changed, see $CAND/validate.log)" 10
changed=""
for f in $FILES; do
  [ -f "$CAND/$f" ] || continue
  if ! cmp -s "$CAND/$f" "$ACT/$f" 2>/dev/null; then changed="$changed $f"; fi
done
[ -n "$changed" ] || { echo "unchanged"; exit 0; }
ts=$(date -u +%Y%m%dT%H%M%S.%NZ); b="$BKP/$ts"; mkdir -p "$b/rules" || die "cannot create backup dir" 12
for f in $FILES; do if [ -f "$ACT/$f" ]; then cp -p "$ACT/$f" "$b/$f"; else : > "$b/$f.absent"; fi; done
( cd "$b" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -r sha256sum > SHA256SUMS ) || die "backup manifest failed" 12
for f in $changed; do
  mkdir -p "$(dirname "$ACT/$f")"
  cp -p "$CAND/$f" "$ACT/$f.archivirt-tmp" && mv -f "$ACT/$f.archivirt-tmp" "$ACT/$f" || { restore "$b"; die "replacement of $f failed (restored)" 11; }
done
if ! "$SURI" -T -c "$ACT/suricata.yaml" -l /tmp >"$b/post-validate.log" 2>&1; then
  restore "$b"; die "post-promotion validation failed - previous configuration restored from $b" 11
fi
echo "$b" > "$BKP/LAST"
echo "promoted $b (changed:$changed)"
