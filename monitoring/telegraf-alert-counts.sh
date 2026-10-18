#!/bin/sh
# ARCHIVIRT — IDS alert counters for Telegraf (inputs.exec, data_format = "influx").
# Emits one line-protocol point per engine ONLY when its alert file exists and is
# readable by the calling user: a missing/unreadable source yields no metric
# (never a misleading 0). Value = number of alert lines in the current file
# (the files are rotated daily by logrotate).
# Telemetry only: experimental results come from the campaign logs, not from here.

emit() {
  measurement=$1; shift
  files=""
  for f in "$@"; do
    [ -f "$f" ] && [ -r "$f" ] && files="$files $f"
  done
  [ -n "$files" ] || return 0
  # shellcheck disable=SC2086
  n=$(cat $files | wc -l)
  echo "$measurement value=${n}i"
}

emit archivirt_suricata_alerts /var/log/suricata/fast.log
emit archivirt_snort_alerts /var/log/snort3/*/alert_fast.txt
exit 0
