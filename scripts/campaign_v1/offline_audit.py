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
  offline_audit.py --emit-file-probes MANIFEST HOST   (v2 only: shell probes for HOST)
Exit code 0 if all required artifacts READY, else 3; 2 = invalid manifest.

Schemas (proposal C1.1, B4):
  * v1  : "manifest_version": "1.0" (Article-2, sha 2c10bea9...) - behaviour and report
          format UNCHANGED.
  * v2  : "schema": "archivirt-offline-manifest/2" - validated fields, optional
          per-file "sha256" (status HASH_MISMATCH), facts <id>_file / <id>_sha256
          produced by the generic probes; report adds manifest_schema/manifest_sha256.
  * STEP3.2 (v2 only): type "library" (fact <id>_version + <id>_source; READY only if the
          source is LIBRARY, i.e. a loadable library, never a package name or a source archive)
          and "version_match": "exact" (default "substring" = historical behaviour, under which
          "3." accepts any 3.x and "3.0.1" is "contained" in "3.0.13").
"""

import hashlib
import json
import shlex
import sys
from pathlib import Path

V2 = "archivirt-offline-manifest/2"


def schema_of(m):
    if m.get("schema") == V2:
        return 2
    if m.get("manifest_version") == "1.0" and "schema" not in m:
        return 1
    raise ValueError("unknown manifest schema")


def validate(m):
    """Return the schema (1|2) or raise ValueError (-> exit 2, MANIFEST_INVALID)."""
    v = schema_of(m)
    if not isinstance(m.get("artifacts"), list) or not m["artifacts"]:
        raise ValueError("artifacts list missing/empty")
    seen = set()
    for a in m["artifacts"]:
        for k in ("id", "type", "host", "required_for"):
            if k not in a:
                raise ValueError("artifact without %r: %r" % (k, a))
        if a["id"] in seen:
            raise ValueError("duplicate id %r" % a["id"])
        seen.add(a["id"])
        if a["type"] not in ("file", "binary", "pkg") + (("library",) if v == 2 else ()):
            raise ValueError("bad type for %r" % a["id"])
        if a.get("version_match", "substring") not in ("substring", "exact") or (v == 1 and "version_match" in a):
            raise ValueError("bad version_match for %r" % a["id"])
        if v == 2 and a["type"] == "file":
            if not str(a.get("path", "")).startswith("/"):
                raise ValueError("v2 file artifact %r needs an absolute path" % a["id"])
            h = a.get("sha256")
            if h is not None and (len(h) != 64 or any(c not in "0123456789abcdef" for c in h)):
                raise ValueError("bad sha256 for %r" % a["id"])
    return v


def emit_file_probes(m, host):
    for a in m["artifacts"]:
        if a["type"] == "file" and a["host"] == host:
            q, i = shlex.quote(a["path"]), a["id"]
            print('if [ -f %s ]; then echo "%s_file=PRESENT"; echo "%s_sha256=$(sha256sum %s | cut -d\\  -f1)"; '
                  'else echo "%s_file=ABSENT"; fi' % (q, i, i, q, i))


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
    if len(sys.argv) == 4 and sys.argv[1] == "--emit-file-probes":
        try:
            m = json.loads(Path(sys.argv[2]).read_text())
            if validate(m) != 2:
                raise ValueError("--emit-file-probes is for v2 manifests only")
        except (OSError, ValueError) as e:
            sys.stderr.write("MANIFEST_INVALID: %s\n" % e)
            sys.exit(2)
        emit_file_probes(m, sys.argv[3])
        sys.exit(0)
    if len(sys.argv) < 5:
        sys.stderr.write(__doc__)
        sys.exit(2)

    try:
        raw = Path(sys.argv[1]).read_bytes()
        manifest = json.loads(raw)
        if not isinstance(manifest, dict):
            raise ValueError("manifest is not a JSON object")
        schema = validate(manifest)
    except (OSError, ValueError) as e:  # json.JSONDecodeError is a ValueError
        sys.stderr.write("MANIFEST_INVALID: %s\n" % e)
        sys.exit(2)
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
            if schema == 2 and status == "READY" and art.get("sha256"):
                got = facts.get(f"{aid}_sha256", "")
                if got != art["sha256"]:
                    status = "HASH_MISMATCH"
            if schema == 2:  # C1.3: what the v2 audit actually checked for this file
                art = dict(art, _observed_sha256=facts.get(f"{aid}_sha256"), _sha256_pinned=bool(art.get("sha256")))
        else:  # binary | pkg | library (v2)
            found = facts.get(f"{aid}_version", "ABSENT")
            if found == "ABSENT" or not found:
                status = "MISSING"
            elif art["type"] == "library" and facts.get(f"{aid}_source") != "LIBRARY":
                status = "MISSING"   # a package name or an archive is not a usable library
            else:
                expect = art.get("expect_version")
                exact = art.get("version_match") == "exact"
                if expect and ((found != expect) if exact else (expect not in found)):
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
            **({"found_source": facts.get(f"{aid}_source", "ABSENT"), "version_match": art.get("version_match", "substring")} if art["type"] == "library" else {}),
            **({"sha256_pinned": art.get("_sha256_pinned"), "observed_sha256": art.get("_observed_sha256")} if schema == 2 and art["type"] == "file" else {}),
            "required": required,
            "status": status,
        })

    report["all_required_ready"] = all_ready
    if schema == 2:  # v1 report format kept byte-compatible
        report["manifest_schema"] = V2
        report["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(report, indent=2))
    sys.exit(0 if all_ready else 3)


if __name__ == "__main__":
    main()
