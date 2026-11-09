#!/usr/bin/env python3
"""ARCHIVIRT campaign_v1 — computed frozen guard for campaign_acceptance.py (owner decision D-FG, 2026-11-09). Read-only.
Definition: the frozen files of the series (evaluators, criteria, scripts) are the PIN lines of the launch manifest
("PIN <sha256> <repo-relative path>") and must be byte-identical in the repository at the end of the campaign.
Prints "PASS:..." (rc 0) or "FAIL:..." (rc 1; a differing or missing pinned file is a FAIL).
No usable evidence (unreadable manifest, no PIN line, malformed line, unsafe path): prints nothing on stdout, rc 2, so the rule stays NOT_EVALUATED.
Usage: frozen_guard_check.py <repo_root> <manifest>"""
import hashlib, os, re, sys

PIN = re.compile(r"PIN ([0-9a-f]{64}) (\S+)")

def nope(msg):
    print("FROZEN_GUARD_ERROR: " + msg, file=sys.stderr); return 2

def main():
    if len(sys.argv) != 3: return nope("usage: frozen_guard_check.py <repo_root> <manifest>")
    root, manifest = os.path.realpath(sys.argv[1]), sys.argv[2]
    try: raw = open(manifest, "rb").read(); lines = raw.decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as e: return nope("manifest unreadable: %s" % e)
    pins = []
    for line in lines:
        if not line.startswith("PIN"): continue
        m = PIN.fullmatch(line)
        if not m or m.group(2).startswith("/") or ".." in m.group(2).split("/"): return nope("malformed PIN line: %r" % line[:120])
        pins.append(m.groups())
    if not pins: return nope("no PIN line in manifest")
    bad = []
    for want, rel in pins:
        try:
            with open(os.path.join(root, rel), "rb") as f: got = hashlib.sha256(f.read()).hexdigest()
        except FileNotFoundError: got = "missing"
        except OSError as e: return nope("%s unreadable: %s" % (rel, e))
        if got != want: bad.append("%s(%s)" % (rel, got[:12]))
    tag = "manifest %s" % hashlib.sha256(raw).hexdigest()[:16]
    if bad: print("FAIL:%d/%d pinned files differ, %s: %s" % (len(bad), len(pins), tag, " ".join(bad))); return 1
    print("PASS:%d pinned files identical, %s" % (len(pins), tag)); return 0

if __name__ == "__main__":
    sys.exit(main())
