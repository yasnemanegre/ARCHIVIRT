#!/usr/bin/env python3
"""Isolated tests of the acceptance evidence chain (P1, 2026-11-09; no lab, no network, nothing outside a temporary directory):
collect_ids_after.sh against a fake SSH, and the ARCHIVIRT_ACCEPT_EVIDENCE blocks of campaign_v1.sh extracted and run alone.
Usage: test_acceptance_evidence.py <scripts/campaign_v1 directory>   -> rc 0 iff all PASS"""
import hashlib, json, os, re, stat, subprocess, sys, tempfile
HERE = os.path.abspath(sys.argv[1]); SCRIPT = os.path.join(HERE, "collect_ids_after.sh")
results = []
def rec(tid, desc, ok, detail=""):
    results.append(ok); print("%-4s %s %s %s" % (tid, "PASS" if ok else "FAIL", desc, detail[:200]))

A, B = "/etc/suricata/suricata.yaml", "/etc/archivirt/ids-mode"
HA, HB, HX = "a" * 64, "b" * 64, "c" * 64

def collect(t, ssh_out, ssh_rc=0, before=True, inv=True, pre=False):
    cd = os.path.join(t, "camp"); os.makedirs(cd)
    if before is True: json.dump({"files": {A: HA, B: HB}}, open(os.path.join(cd, "monitor_ids_provenance.json"), "w"))
    elif before: open(os.path.join(cd, "monitor_ids_provenance.json"), "w").write(before)
    if pre: open(os.path.join(cd, "ids_deployed_after.json"), "w").write("old")
    fake = os.path.join(t, "fake_ssh"); open(fake, "w").write("#!/bin/bash\ncat <<'EOF'\n%s\nEOF\nexit %d\n" % (ssh_out, ssh_rc)); os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
    hosts = os.path.join(t, "hosts.ini"); open(hosts, "w").write("archivirt-monitor-ids ansible_host=10.0.3.10\n" if inv else "other ansible_host=1.1.1.1\n")
    cp = subprocess.run(["bash", SCRIPT, cd], capture_output=True, text=True, env=dict(os.environ, ARCHIVIRT_SSH=fake, ARCHIVIRT_INVENTORY=hosts, PYTHONDONTWRITEBYTECODE="1"))
    p = os.path.join(cd, "ids_deployed_after.json")
    return cp.returncode, (open(p).read() if os.path.exists(p) else None)

OK = "%s  %s\n%s  %s" % (HB, B, HA, A)
CASES = [("E1", "all files hashed", dict(ssh_out=OK), 0, {A: HA, B: HB}),
         ("E2", "a changed file is recorded as observed (evaluator: FAIL)", dict(ssh_out="%s  %s\n%s  %s" % (HX, A, HB, B)), 0, {A: HX, B: HB}),
         ("E3", "one file missing from the output: no evidence", dict(ssh_out="%s  %s" % (HA, A)), 5, None),
         ("E4", "sha256sum error on the monitor: no evidence", dict(ssh_out=OK, ssh_rc=1), 5, None),
         ("E5", "monitor unreachable: no evidence", dict(ssh_out="", ssh_rc=255), 5, None),
         ("E6", "garbage line: no evidence", dict(ssh_out=OK + "\nsha256sum: permission denied"), 5, None),
         ("E7", "recorded list absent: no evidence", dict(ssh_out=OK, before=False), 5, None),
         ("E8", "recorded list unreadable: no evidence", dict(ssh_out=OK, before="{bad"), 5, None),
         ("E9", "monitor not in inventory: no evidence", dict(ssh_out=OK, inv=False), 5, None)]
for tid, desc, kw, rc, files in CASES:
    with tempfile.TemporaryDirectory() as t:
        got, txt = collect(t, **kw)
        ok = got == rc and (json.loads(txt)["files"] == files if files else txt is None)
        rec(tid, desc, ok, "rc %d" % got)
with tempfile.TemporaryDirectory() as t:
    got, txt = collect(t, OK, pre=True); rec("E10", "existing output never overwritten", got == 2 and txt == "old", "rc %d" % got)

SRC = open(os.path.join(HERE, "campaign_v1.sh")).read()
def block(name):
    m = re.search(r"^[^\n]*%s_BEGIN[^\n]*\n(.*?)^[^\n]*%s_END" % (name, name), SRC, re.S | re.M)
    return m.group(1) if m else None
VALIDATE, BUILD = block("ARCHIVIRT_ACCEPT_EVIDENCE_VALIDATE"), block("ARCHIVIRT_ACCEPT_EVIDENCE_ARGS")
rec("S0", "evidence blocks present in campaign_v1.sh", bool(VALIDATE and BUILD))
call = "campaign_acceptance.py\" \"$CAMPAIGN_DIR\" --max-runs"
rec("S0b", "acceptance call passes the evidence array", SRC.count(call) == 1 and '"${ACCEPT_EVIDENCE[@]}"' in SRC[SRC.index(call):SRC.index(call) + 260])

def validate(**env):
    e = {k: v for k, v in os.environ.items() if not k.startswith("ARCHIVIRT_")}; e.update(env)
    return subprocess.run(["bash", "-c", "set -euo pipefail\n" + VALIDATE + "\necho SURVIVED"], capture_output=True, text=True, env=e)
SHA = "d" * 64; MEM = "archivirt-monitor-ids=2048,archivirt-attacker=1024"
for tid, desc, env, good in [("V1", "nothing set is allowed (rules stay NOT_EVALUATED)", {}, True),
                             ("V2", "valid values", {"ARCHIVIRT_DECLARED_MEM": MEM, "ARCHIVIRT_EGRESS_SHA256": SHA}, True),
                             ("V3", "malformed memory refused", {"ARCHIVIRT_DECLARED_MEM": "monitor=abc"}, False),
                             ("V4", "short egress hash refused", {"ARCHIVIRT_EGRESS_SHA256": "abc"}, False),
                             ("V5", "uppercase egress hash refused", {"ARCHIVIRT_EGRESS_SHA256": "D" * 64}, False)]:
    cp = validate(**env); ok = (cp.returncode == 0 and "SURVIVED" in cp.stdout) if good else (cp.returncode == 4 and "SURVIVED" not in cp.stdout)
    rec(tid, desc, ok, "rc %d" % cp.returncode)

def fg(t, manifest, files=()):
    root = os.path.join(t, "repo"); os.makedirs(root)
    for rel, body in files:
        p = os.path.join(root, rel); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(body)
    m = os.path.join(t, "manifest")
    if manifest is not None: open(m, "w").write(manifest)
    return subprocess.run([sys.executable, "-B", "-I", os.path.join(HERE, "frozen_guard_check.py"), root, m], capture_output=True, text=True)
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
for tid, desc, man, files, rc, prefix in [
    ("F1", "all pins identical", "# x\nFILE z\nPIN %s a/b.py\nPIN %s c.json\n" % (sha("1"), sha("2")), [("a/b.py", "1"), ("c.json", "2")], 0, "PASS:2 pinned"),
    ("F2", "one pinned file differs", "PIN %s a/b.py\nPIN %s c.json\n" % (sha("1"), sha("2")), [("a/b.py", "x"), ("c.json", "2")], 1, "FAIL:1/2"),
    ("F3", "a pinned file is missing: FAIL", "PIN %s a/b.py\n" % sha("1"), [], 1, "FAIL:1/1"),
    ("F4", "manifest absent: no evidence", None, [], 2, ""),
    ("F5", "manifest without PIN: no evidence", "# x\nFILE z\n", [], 2, ""),
    ("F6", "malformed PIN line: no evidence", "PIN abc a.py\n", [("a.py", "1")], 2, ""),
    ("F7", "path escaping the repository: no evidence", "PIN %s ../a.py\n" % sha("1"), [], 2, ""),
    ("F8", "absolute path: no evidence", "PIN %s /etc/passwd\n" % sha("1"), [], 2, "")]:
    with tempfile.TemporaryDirectory() as t:
        cp = fg(t, man, files); ok = cp.returncode == rc and (cp.stdout.startswith(prefix) if prefix else cp.stdout == "")
        rec(tid, desc, ok, "rc %d %s" % (cp.returncode, cp.stdout.strip()[:80]))

def build(collect_rc=0, fg_stub=None, **env):
    with tempfile.TemporaryDirectory() as t:
        d = os.path.join(t, "p"); os.makedirs(d); open(os.path.join(d, "collect_ids_after.sh"), "w").write("exit %d\n" % collect_rc)
        if fg_stub: open(os.path.join(d, "frozen_guard_check.py"), "w").write("import sys\nprint(%r, end='')\nsys.exit(%d)\n" % fg_stub)
        e = {k: v for k, v in os.environ.items() if not k.startswith("ARCHIVIRT_")}; e.update(env, PROCESSORS=d, CAMPAIGN_DIR="/camp", ROOT=d)
        cp = subprocess.run(["bash", "-c", 'set -euo pipefail\nlog() { :; }\n' + BUILD + '\nprintf "%s\\n" "${ACCEPT_EVIDENCE[@]}"; echo END'], capture_output=True, text=True, env=e)
        return cp.returncode, [x for x in cp.stdout.split("\n") if x and x != "END"], "END" in cp.stdout
rc, a, end = build(); rec("A1", "only --ids-after when nothing is declared", rc == 0 and end and a == ["--ids-after", "/camp/ids_deployed_after.json"], str(a))
rc, a, end = build(1); rec("A2", "collection failure: no --ids-after, campaign tail not aborted", rc == 0 and end and a == [], str(a))
rc, a, end = build(0, ARCHIVIRT_DECLARED_MEM=MEM, ARCHIVIRT_EGRESS_SHA256=SHA)
rec("A3", "declared values are passed", rc == 0 and end and a == ["--declared-mem", MEM, "--egress-sha", SHA, "--ids-after", "/camp/ids_deployed_after.json"], str(a))

IA = ["--ids-after", "/camp/ids_deployed_after.json"]
rc, a, end = build(0, ("PASS:2 pinned files identical", 0), ARCHIVIRT_FROZEN_MANIFEST="/m"); rec("A4", "frozen guard PASS is passed", rc == 0 and end and a == IA + ["--manual", "frozen_guard=PASS:2 pinned files identical"], str(a))
rc, a, end = build(0, ("FAIL:1/2 differ", 1), ARCHIVIRT_FROZEN_MANIFEST="/m"); rec("A5", "frozen guard FAIL is passed, tail not aborted", rc == 0 and end and a == IA + ["--manual", "frozen_guard=FAIL:1/2 differ"], str(a))
rc, a, end = build(0, ("", 2), ARCHIVIRT_FROZEN_MANIFEST="/m"); rec("A6", "no frozen evidence: nothing passed, tail not aborted", rc == 0 and end and a == IA, str(a))
rc, a, end = build(0); rec("A7", "manifest not set: nothing passed", rc == 0 and end and a == IA, str(a))
with tempfile.TemporaryDirectory() as t:
    m = os.path.join(t, "m"); open(m, "w").write("x")
    rec("V6", "readable manifest accepted", validate(ARCHIVIRT_FROZEN_MANIFEST=m).returncode == 0)
    rec("V7", "unreadable manifest refused", validate(ARCHIVIRT_FROZEN_MANIFEST=m + ".absent").returncode == 4)

n_fail = results.count(False)
print("%d/%d PASS" % (len(results) - n_fail, len(results)))
sys.exit(0 if n_fail == 0 else 1)
