#!/usr/bin/env python3
"""ARCHIVIRT campaign_v1 — campaign summary.

Aggregates every result.json under a campaign directory. INVALID and
PREREQUISITE_MISSING runs are kept as explicit, separate counters — failed
runs are never silently dropped.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict


def main():
    root = Path(sys.argv[1])
    rows = []
    for path in root.rglob("result.json"):
        try:
            rows.append(json.loads(path.read_text()))
        except (ValueError, OSError):
            pass

    summary = defaultdict(lambda: {
        "runs_total": 0,
        "runs_valid": 0,
        "runs_invalid": 0,
        "runs_prerequisite_missing": 0,
        "detections": 0,
        "blocked": 0,
        "alerts": 0,
    })

    for r in rows:
        key = (r.get("mode", "?"), r.get("scenario", "?"))
        x = summary[key]
        x["runs_total"] += 1
        x["alerts"] += r.get("alert_count", 0) or 0

        status = r.get("run_status")
        if status == "VALID":
            x["runs_valid"] += 1
        elif status == "PREREQUISITE_MISSING":
            x["runs_prerequisite_missing"] += 1
        else:
            x["runs_invalid"] += 1

        if r.get("detection_status"):
            x["detections"] += 1
        if r.get("blocking_status") is True:
            x["blocked"] += 1

    output = {f"{mode}:{scenario}": data for (mode, scenario), data in summary.items()}

    (root / "summary.json").write_text(json.dumps(output, indent=2))
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
