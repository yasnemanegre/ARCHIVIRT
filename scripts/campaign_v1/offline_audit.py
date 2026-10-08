#!/usr/bin/env python3
"""ARCHIVIRT campaign_v1 — OFFLINE ARTIFACT AUDIT.

Compares the offline manifest against observed host facts and emits a readiness
report. It NEVER downloads anything: a missing artifact is reported with an
explicit status, never fetched.

Statuses (per artifact): READY | MISSING | VERSION_MISMATCH |
OFFLINE_ARTIFACT_MISSING | NOT_REQUIRED
  * MISSING                  -> a required binary/package is absent
  * OFFLINE_ARTIFACT_MISSING -> a required local file artifact is absent
  * VERSION_MISMATCH         -> present but version != manifest expect_version
  * NOT_REQUIRED             -> not needed for the selected engine/scenarios

Facts files are simple KEY=VALUE lines produced by offline_audit.sh:
  <id>_version=<string|ABSENT>   for binaries/pkgs
  <id>_file=<PRESENT|ABSENT>     for files

Usage:
  offline_audit.py MANIFEST ENGINE SCENARIOS_CSV FACTS_FILE... > readiness.json
Exit code 0 if all required artifacts READY, else 3.
"""

import json
import sys
from pathlib import Path


def load_facts(paths):
    facts = {}
    for p in paths:
        if not p or not Path(p).exists():
            continue
        for line in Path(p).read_text(errors="replace").splitlines():
            line = line.strip().replace("\r", "")
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                facts[k.strip()] = v.strip()
    return facts


def main():
    if len(sys.argv) < 5:
        sys.stderr.write(__doc__)
        sys.exit(2)

    manifest = json.loads(Path(sys.argv[1]).read_text())
    engine = sys.argv[2]
    scenarios = [s for s in sys.argv[3].split(",") if s]
    facts = load_facts(sys.argv[4:])

    wanted = {f"engine:{engine}", *scenarios}

    report = {"engine": engine, "scenarios": scenarios, "artifacts": []}
    all_ready = True

    for art in manifest["artifacts"]:
        aid = art["id"]
        required = bool(set(art.get("required_for", [])) & wanted)

        if not required:
            status, found = "NOT_REQUIRED", None
        elif art["type"] == "file":
            found = facts.get(f"{aid}_file", "ABSENT")
            status = "READY" if found == "PRESENT" else "OFFLINE_ARTIFACT_MISSING"
        else:  # binary | pkg
            found = facts.get(f"{aid}_version", "ABSENT")
            if found == "ABSENT" or not found:
                status = "MISSING"
            else:
                expect = art.get("expect_version")
                if expect and expect not in found:
                    status = "VERSION_MISMATCH"
                else:
                    status = "READY"

        if required and status != "READY":
            all_ready = False

        report["artifacts"].append({
            "id": aid,
            "role": art.get("role"),
            "host": art.get("host"),
            "type": art["type"],
            "path": art.get("path"),
            "expect_version": art.get("expect_version"),
            "found": found,
            "required": required,
            "status": status,
        })

    report["all_required_ready"] = all_ready
    print(json.dumps(report, indent=2))
    sys.exit(0 if all_ready else 3)


if __name__ == "__main__":
    main()
