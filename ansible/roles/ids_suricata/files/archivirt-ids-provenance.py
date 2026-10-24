#!/usr/bin/env python3
"""ARCHIVIRT — record SHA-256 of the IDS artefacts actually deployed (PROPOSAL C1.1, B1/B3).
Writes OUT atomically, only when the content changes (idempotent). Prints 'updated' or
'unchanged'. Exit 5 if a mandatory file is missing or Suricata's version is unreadable.
Usage: archivirt-ids-provenance.py --series S --out FILE --suricata BIN FILE [FILE...]
"""
import argparse, hashlib, json, os, re, subprocess, sys
ap = argparse.ArgumentParser()
ap.add_argument("--series", required=True); ap.add_argument("--out", required=True)
ap.add_argument("--suricata", default="/usr/bin/suricata"); ap.add_argument("files", nargs="+")
a = ap.parse_args()
def die(m): print("IDS_PROVENANCE_ERROR: " + m, file=sys.stderr); sys.exit(5)
if not a.series.strip() or a.series.upper().startswith("ARTICLE") or a.series == "UNSET":
    die("invalid series %r" % a.series)
files = {}
for p in a.files:
    if not os.path.isfile(p): die("missing %s" % p)
    with open(p, "rb") as f: files[p] = hashlib.sha256(f.read()).hexdigest()
try:
    out = subprocess.run([a.suricata, "-V"], capture_output=True, text=True, timeout=30).stdout
    ver = re.search(r"(\d+\.\d+\.\d+)", out).group(1)
except Exception as e:
    die("suricata version unreadable: %s" % e)
doc = {"schema": "archivirt-ids-provenance/1", "series": a.series, "suricata_version": ver, "files": files}
new = json.dumps(doc, indent=2, sort_keys=True) + "\n"
old = open(a.out).read() if os.path.isfile(a.out) else None
if old == new:
    print("unchanged"); sys.exit(0)
os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
tmp = a.out + ".tmp"
with open(tmp, "w") as f: f.write(new)
os.replace(tmp, a.out)
print("updated")
