#!/bin/bash
# run a list of experiments sequentially (one engine at a time); usage: run_series.sh <mode> <spec...>  spec = engine:rep
TOOLS=$(dirname "$(readlink -f "$0")"); OUTROOT="${ARCHIVIRT_VAL_OUT:?set ARCHIVIRT_VAL_OUT (results root OUTSIDE the repository)}"; MODE=$1; shift
case "$(readlink -f "$OUTROOT")/" in "$(readlink -f "$TOOLS/../../..")/"*) echo "REFUSED: results root inside the repository"; exit 2;; esac
for s in "$@"; do e=${s%%:*}; r=${s##*:}; echo "$(date -u +%FT%TZ) start $e $MODE r$r"; EXP=1 timeout 580 bash "$TOOLS/validate_engine.sh" "$e" "$MODE" "$OUTROOT/$e-$MODE-r$r" > /dev/null 2>&1 < /dev/null; echo "$(date -u +%FT%TZ) end $e $MODE r$r rc=$? status=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["run_status"])' "$OUTROOT/$e-$MODE-r$r/experiment_result.json" 2>/dev/null || echo NO_RESULT)"; sleep 5; done
