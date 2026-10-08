#!/bin/bash
# ARCHIVIRT campaign_v1 — stop the campaign's Suricata instance (graceful flush).
# Runs ON the monitor host (ansible -m script).
#
# Usage: stop.sh [logdir]
#   logdir : stop only the instance launched with `-l <logdir>` (one run).
#            Without it, stop every campaign instance (-l /var/log/archivirt/*).
#
# Rationale (Article 2 fixes):
#  * Target the instance by command line (pkill -f on its unique -l path), so a
#    systemd-managed suricata.service is NEVER touched (comm-based kills would
#    have hit it too).
#  * SIGTERM first so Suricata flushes buffered EVE to disk; SIGKILL last resort.
#    The orchestrator stops the engine BEFORE collecting eve.json.
set -uo pipefail

LOGDIR="${1:-}"
if [ -n "$LOGDIR" ]; then
    PAT="[s]uricata .* -l ${LOGDIR}"
else
    PAT="[s]uricata .* -l /var/log/archivirt"
fi
running() { pgrep -f "$PAT" >/dev/null 2>&1; }

sudo pkill -TERM -f "$PAT" 2>/dev/null || true

for _i in $(seq 1 15); do
    if ! running; then
        echo "ARCHIVIRT_ENGINE=STOPPED_CLEAN"
        exit 0
    fi
    sleep 1
done

sudo pkill -KILL -f "$PAT" 2>/dev/null || true
echo "ARCHIVIRT_ENGINE=STOPPED_FORCED"
