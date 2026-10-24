#!/usr/bin/env python3
"""ARCHIVIRT — pre-installation guard (PROPOSAL STEP3.1). READ-ONLY: reads files, runs only
`dpkg --compare-versions` (pure comparison). Never installs, downloads or writes anything.

Fails (exit 3) whenever the origin, version, architecture, checksum or dependencies of a package
selected for a profile cannot be PROVEN against an approved version lock, or when several
candidates exist, or when engine version / IDS-IPS configuration expectations disagree.
Exit 0 = every check PASS ; 2 = usage/input error ; 3 = at least one FAIL.

Usage:
  archivirt_install_guard.py --lock LOCK.json --profile NAME --mirror-dir DIR
        [--apt-policy FILE --expected-origin URL]      # `apt-cache policy <pkgs>` captured on the target VM
        [--installed FILE]                             # `dpkg-query -W -f='${Package} ${Version}\n'` of the VM
        [--repo DIR]                                   # repository tree: manifest + IDS/IPS template checks
"""
import argparse, collections, hashlib, json, os, re, subprocess, sys

RESULTS = []
def res(status, check, detail):
    RESULTS.append((status, check, detail)); print("%-4s %-28s %s" % (status, check, detail))

def parse_index(path):
    ents, cur = [], {}
    for line in open(path, encoding="utf-8", errors="replace"):
        if not line.strip():
            if cur: ents.append(cur); cur = {}
            continue
        if line[0] in " \t": continue
        k, _, v = line.partition(":"); cur[k.strip()] = v.strip()
    if cur: ents.append(cur)
    return ents

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()

def vcmp(a, op, b):
    return subprocess.run(["dpkg", "--compare-versions", a, op, b]).returncode == 0

OPS = {">=": "ge", "<=": "le", ">>": "gt", "<<": "lt", "=": "eq"}
def satisfied(alt, avail):
    """alt = 'name (op ver)' ; avail = {name: [versions]} ; True if one available version satisfies."""
    m = re.match(r"^([a-z0-9.+-]+)(?::[a-z0-9]+)?\s*(?:\((>=|<=|>>|<<|=)\s*([^)]+)\))?$", alt.strip())
    if not m: return False
    name, op, ver = m.groups()
    vs = avail.get(name, [])
    return any((op is None) or vcmp(v, OPS[op], ver.strip()) for v in vs)

def parse_policy(path):
    """apt-cache policy output -> {pkg: {'candidate': v, 'installed': v, 'origins': {version: [origin lines]}}}"""
    out, pkg, ver = {}, None, None
    for line in open(path, encoding="utf-8", errors="replace"):
        if re.match(r"^[a-z0-9.+-]+:$", line.strip()) and not line.startswith(" "):
            pkg = line.strip()[:-1]; out[pkg] = {"candidate": None, "installed": None, "origins": collections.defaultdict(list)}; ver = None
        elif pkg and line.strip().startswith("Candidate:"): out[pkg]["candidate"] = line.split(":", 1)[1].strip()
        elif pkg and line.strip().startswith("Installed:"): out[pkg]["installed"] = line.split(":", 1)[1].strip()
        elif pkg and re.match(r"^\s+(\*\*\* )?\S+ -?\d+$", line.rstrip()):
            ver = line.replace("***", "").split()[0]
        elif pkg and ver and re.match(r"^\s+-?\d+ \S", line):
            out[pkg]["origins"][ver].append(line.strip())
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", required=True); ap.add_argument("--profile", required=True)
    ap.add_argument("--mirror-dir", required=True); ap.add_argument("--apt-policy"); ap.add_argument("--expected-origin")
    ap.add_argument("--installed"); ap.add_argument("--repo")
    a = ap.parse_args()
    try:
        lock = json.load(open(a.lock))
        prof = lock["profiles"][a.profile]
        idx = parse_index(os.path.join(a.mirror_dir, "Packages"))
    except Exception as e:
        print("GUARD_INPUT_ERROR: %s" % e, file=sys.stderr); return 2
    print("== guard profile=%s lock=%s status=%s" % (a.profile, os.path.basename(a.lock), lock.get("status")))
    if lock.get("status") != "APPROVED":
        res("FAIL", "lock-approval", "version lock status is %r (installation requires an APPROVED lock)" % lock.get("status"))
    by = collections.defaultdict(list)
    for e in idx: by[(e.get("Package"), e.get("Architecture"))].append(e)
    avail = collections.defaultdict(list)
    for e in idx:
        avail[e["Package"]].append(e["Version"])
        for p in e.get("Provides", "").split(","):
            if p.strip(): avail[p.strip().split()[0]].append(e["Version"])
    base = lock.get("base_image_packages", {})
    for n, v in base.items(): avail[n].append(v)
    if a.installed:
        for line in open(a.installed):
            parts = line.split()
            if len(parts) == 2 and parts[1]: avail[parts[0]].append(parts[1])
    # 1. forbidden packages must not be selectable from the mirror
    for f in prof.get("forbidden", []):
        hits = [e for e in idx if e["Package"] == f]
        res("FAIL" if hits else "PASS", "forbidden:" + f, ("present in mirror: %s" % [h["Version"] for h in hits]) if hits else "absent from mirror")
    # 2. each locked package: one candidate, exact version/arch/sha, file present and intact, deps resolvable
    for name, L in sorted(prof.get("packages", {}).items()):
        arch = L.get("arch", "amd64")
        cands = by.get((name, arch), []) + ([] if arch == "all" else by.get((name, "all"), []))
        if not cands: res("FAIL", "missing:" + name, "not in mirror (required: %s %s)" % (L["version"], arch)); continue
        if len(cands) > 1: res("FAIL", "multi-candidate:" + name, "several candidates: %s" % [c["Version"] for c in cands]); continue
        c = cands[0]; ok = True
        if c["Version"] != L["version"]: res("FAIL", "version:" + name, "mirror %s != lock %s" % (c["Version"], L["version"])); ok = False
        if c.get("Architecture") != arch: res("FAIL", "arch:" + name, "mirror %s != lock %s" % (c.get("Architecture"), arch)); ok = False
        if c.get("SHA256") != L["sha256"]: res("FAIL", "index-sha:" + name, "index %s != lock %s" % (c.get("SHA256", "")[:16], L["sha256"][:16])); ok = False
        f = os.path.join(a.mirror_dir, os.path.basename(c.get("Filename", "")))
        if not os.path.isfile(f): res("FAIL", "file:" + name, "missing file %s" % f); ok = False
        elif sha256(f) != L["sha256"]: res("FAIL", "file-sha:" + name, "file content differs from lock"); ok = False
        unmet = []
        for field in ("Pre-Depends", "Depends"):
            for grp in c.get(field, "").split(","):
                if grp.strip() and not any(satisfied(x, avail) for x in grp.split("|")): unmet.append(grp.strip())
        if unmet: res("FAIL", "deps:" + name, "unresolvable from mirror+base image: %s" % unmet); ok = False
        if ok: res("PASS", "package:" + name, "%s %s sha %s, single candidate, deps resolvable" % (c["Version"], arch, L["sha256"][:12]))
    # 3. source artifacts (e.g. Snort 3 / LibDAQ tarballs)
    for name, S in sorted(prof.get("sources", {}).items()):
        p = os.path.expanduser(S["path"])
        if not os.path.isfile(p): res("FAIL", "source:" + name, "missing %s" % p)
        elif sha256(p) != S["sha256"]: res("FAIL", "source:" + name, "sha256 mismatch")
        else: res("PASS", "source:" + name, "%s sha %s" % (os.path.basename(p), S["sha256"][:12]))
    # 4. selection on the target VM: candidate == lock AND every candidate origin is the expected mirror
    if a.apt_policy:
        pol = parse_policy(a.apt_policy)
        for name, L in sorted(prof.get("packages", {}).items()):
            P = pol.get(name)
            if P is None: res("FAIL", "policy:" + name, "not present in the captured apt-cache policy"); continue
            if P["candidate"] != L["version"]:
                res("FAIL", "policy-candidate:" + name, "VM would select %s, lock requires %s" % (P["candidate"], L["version"])); continue
            origins = [o for o in P["origins"].get(P["candidate"], []) if "/var/lib/dpkg/status" not in o]
            other = sorted(v for v in P["origins"] if v != P["candidate"] and any("/var/lib/dpkg/status" not in o for o in P["origins"][v]))
            if not origins or not a.expected_origin or not all(a.expected_origin in o for o in origins):
                res("FAIL", "policy-origin:" + name, "origin not proven: %s" % origins)
            elif other: res("FAIL", "policy-alternatives:" + name, "other versions selectable: %s" % other)
            else: res("PASS", "policy:" + name, "candidate %s from %s only" % (P["candidate"], a.expected_origin))
    # 5. engine / configuration consistency (repository)
    if a.repo:
        for chk in prof.get("repo_checks", []):
            p = os.path.join(a.repo, chk["file"])
            if not os.path.isfile(p): res("FAIL", "repo:" + chk["id"], "missing %s" % chk["file"]); continue
            txt = open(p, encoding="utf-8", errors="replace").read()
            bad = [r for r in chk.get("must_match", []) if not re.search(r, txt, re.M)] + \
                  ["!" + r for r in chk.get("must_not_match", []) if re.search(r, txt, re.M)]
            res("FAIL" if bad else "PASS", "repo:" + chk["id"], ("violations %s" % bad) if bad else chk["file"])
    nf = sum(1 for r in RESULTS if r[0] == "FAIL")
    print("RESULT: %d PASS, %d FAIL -> %s" % (len(RESULTS) - nf, nf, "INSTALLATION ALLOWED" if nf == 0 else "INSTALLATION REFUSED"))
    return 0 if nf == 0 else 3

if __name__ == "__main__":
    sys.exit(main())
