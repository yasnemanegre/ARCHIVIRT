#!/usr/bin/env python3
"""Isolated tests of engine_stop_problem() in archivirt_stopwatch_eval.py (r2, D0I 2026-10-25; no lab, no network).
engine_stop.txt is what campaign_v1.sh tees from `ansible -m script stop.sh` (ad-hoc callback "<host> | CHANGED => {json}").
Cases: synthetic ansible / raw stop.sh outputs (ansible rc must be a JSON integer equal to 0), plus the three original
D0I files (fixtures/d0i_engine_stop, sha256-checked against their SHA256SUMS before use). A counter-proof runs every case against deliberately weakened copies of the
evaluator: each weakening must be detected.
Usage: test_engine_stop.py <archivirt_stopwatch_eval.py> <fixtures/d0i_engine_stop> [out_json]   -> rc 0 iff all PASS"""
import hashlib, importlib.util, json, os, shutil, sys, tempfile
sys.dont_write_bytecode = True
EV, FX = [os.path.abspath(x) for x in sys.argv[1:3]]; OUT = sys.argv[3] if len(sys.argv) > 3 else None
results = []
def rec(tid, desc, ok, detail=""):
    results.append({"id": tid, "desc": desc, "result": "PASS" if ok else "FAIL", "detail": detail}); print("%-4s %s %s %s" % (tid, "PASS" if ok else "FAIL", desc, detail[:200]))
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()

def load(path):
    sys.path.insert(0, os.path.dirname(path))     # p2_stopcriteria.py next to the evaluator
    spec = importlib.util.spec_from_file_location("ev_%d" % len(results), path); m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m); sys.path.pop(0); return m

def ansible(stdout_lines, status="CHANGED", rc=0, host="archivirt-monitor-ids", extra=None):
    d = {"changed": True, "rc": rc, "stderr": "Shared connection to 10.0.3.10 closed.\r\n",
         "stderr_lines": ["Shared connection to 10.0.3.10 closed."],
         "stdout": "".join(l + "\r\n" for l in stdout_lines), "stdout_lines": stdout_lines}
    if extra: d.update(extra)
    return "%s | %s => %s\n" % (host, status, json.dumps(d, indent=4))

C, F = "ARCHIVIRT_ENGINE=STOPPED_CLEAN", "ARCHIVIRT_ENGINE=STOPPED_FORCED"
NR, FORCED = "engine stop status not recorded", "engine stopped by SIGKILL (STOPPED_FORCED): no final stats dump, EVE flush not guaranteed"
CASES = [  # (id, description, content or None for an absent file, expected reason; None = clean stop accepted)
    ("A1", "ansible CHANGED, one CLEAN", ansible([C]), None),
    ("A2", "ansible SUCCESS, one CLEAN", ansible([C], status="SUCCESS"), None),
    ("A3", "ansible FORCED", ansible([F]), FORCED),
    ("A4", "ansible CLEAN and FORCED", ansible([C, F]), "engine stop status contradictory (CLEAN and FORCED)"),
    ("A5", "ansible CLEAN twice", ansible([C, C]), "engine stop status repeated (2 STOPPED_CLEAN lines)"),
    ("A6", "ansible empty stdout", ansible([]), NR),
    ("A7", "ansible CLEAN only in stderr", ansible([], extra={"stderr": C, "stderr_lines": [C]}), NR),
    ("A8", "ansible CLEAN as a substring", ansible(["x" + C]), NR),
    ("A9", "ansible CHANGED but rc 1", ansible([C], rc=1), "engine stop status unreadable (ansible rc 1, stdout_lines present)"),
    ("A10", "ansible FAILED!", ansible([C], status="FAILED!", rc=1), "engine stop command not successful (ansible FAILED!)"),
    ("A11", "ansible UNREACHABLE!", 'archivirt-monitor-ids | UNREACHABLE! => {\n    "msg": "x",\n    "unreachable": true\n}\n',
     "engine stop command not successful (ansible UNREACHABLE!)"),
    ("A12", "ansible truncated JSON", ansible([C])[:-20], "engine stop status unreadable (ansible output is not valid JSON)"),
    ("A13", "two ansible host blocks", ansible([C]) + ansible([C], host="other"), "engine stop status ambiguous (2 ansible host blocks)"),
    ("A14", "text after the ansible block", ansible([C]) + C + "\n", "engine stop status unreadable (text outside the ansible block)"),
    ("A15", "text before the ansible block", C + "\n" + ansible([C]), "engine stop status unreadable (text outside the ansible block)"),
    ("A16", "ansible block without stdout_lines", 'h | CHANGED => {\n "rc": 0, "stdout": "%s"\n}\n' % C,
     "engine stop status unreadable (ansible rc 0, stdout_lines absent)"),
    ("A17", "ansible rc is JSON false", ansible([C], rc=False), "engine stop status unreadable (ansible rc False, stdout_lines present)"),
    ("A18", "ansible rc is JSON 0.0", ansible([C], rc=0.0), "engine stop status unreadable (ansible rc 0.0, stdout_lines present)"),
    ("A19", "ansible rc is JSON null", ansible([C], rc=None), "engine stop status unreadable (ansible rc None, stdout_lines present)"),
    ("A20", "ansible rc absent", "h | CHANGED => %s\n" % json.dumps({"changed": True, "stdout_lines": [C]}, indent=4),
     "engine stop status unreadable (ansible rc absent, stdout_lines present)"),
    ("A21", "ansible rc is the string \"0\"", ansible([C], rc="0"), "engine stop status unreadable (ansible rc '0', stdout_lines present)"),
    ("R1", "raw stop.sh CLEAN", C + "\n", None),
    ("R2", "raw stop.sh FORCED", F + "\n", FORCED),
    ("R3", "raw CLEAN twice", C + "\n" + C + "\n", "engine stop status repeated (2 STOPPED_CLEAN lines)"),
    ("R4", "raw empty file", "", NR),
    ("R5", "absent file", None, "engine stop status absent"),
]

# --- original D0I fixtures: verified copies, never modified ---
sums = {}
for l in open(os.path.join(FX, "SHA256SUMS")):
    h, n = l.split(None, 1); sums[n.strip()] = h
ok = sorted(sums) == sorted(f for f in os.listdir(FX) if f.endswith(".engine_stop.txt")) and all(sha(os.path.join(FX, n)) == h for n, h in sums.items())
rec("F0", "D0I fixtures match SHA256SUMS", ok, "%d files" % len(sums))
REAL = [("D%d" % i, "original D0I %s" % n.split(".")[0], open(os.path.join(FX, n)).read(), None) for i, n in enumerate(sorted(sums), 1)]

def run_cases(mod, cases):
    out = {}
    with tempfile.TemporaryDirectory() as td:
        for tid, desc, content, want in cases:
            p = os.path.join(td, tid + ".txt")
            if content is not None: open(p, "w").write(content)
            out[tid] = mod.engine_stop_problem(p)
    return out

ev = load(EV)
got = run_cases(ev, CASES + REAL)
for tid, desc, content, want in CASES + REAL:
    rec(tid, desc, got[tid] == want, "got=%r" % (got[tid],) + ("" if got[tid] == want else " want=%r" % (want,)))

# --- counter-proof: each weakening of the r2 reader must make at least one case fail ---
src = open(EV).read()
MUTANTS = {
    "set instead of count (r1 behaviour: duplicates accepted)": ('clean, forced = lines.count("ARCHIVIRT_ENGINE=STOPPED_CLEAN"), lines.count("ARCHIVIRT_ENGINE=STOPPED_FORCED")',
                                                                  'clean, forced = int("ARCHIVIRT_ENGINE=STOPPED_CLEAN" in lines), int("ARCHIVIRT_ENGINE=STOPPED_FORCED" in lines)'),
    "substring search over the whole file": ('lines, problem = engine_stop_lines(text)', 'lines, problem = ([l for l in ("ARCHIVIRT_ENGINE=STOPPED_CLEAN", "ARCHIVIRT_ENGINE=STOPPED_FORCED") if l in text], None)'),
    "ansible status not checked": ('if status not in ("CHANGED", "SUCCESS"):', 'if False:'),
    "ansible rc not checked": ('type(d.get("rc")) is not int or d["rc"] != 0 or ', ''),
    "ansible rc compared by value only (r2 435f9496 behaviour)": ('type(d.get("rc")) is not int or d["rc"] != 0', 'd.get("rc") != 0'),
    "text outside the block tolerated": ('return None, "engine stop status unreadable (text outside the ansible block)"', 'pass'),
    "several host blocks tolerated": ('if len(heads) != 1:', 'if not heads:'),
    "r1 reader (bare lines only)": ('heads = [i for i, l in enumerate(raw) if ANSIBLE_ADHOC_HEAD.match(l)]', 'heads = []'),
}
td = tempfile.mkdtemp(); shutil.copy(os.path.join(os.path.dirname(EV), "p2_stopcriteria.py"), td)
for i, (name, (old, new)) in enumerate(MUTANTS.items()):
    if src.count(old) != 1: rec("CP", "mutant applies: %s" % name, False, "pattern found %d times (test defect)" % src.count(old)); continue
    mp = os.path.join(td, "mutant%d.py" % i); open(mp, "w").write(src.replace(old, new))
    mg = run_cases(load(mp), CASES + REAL)
    caught = [t for t, d, c, w in CASES + REAL if mg[t] != w]
    rec("CP", "weakened evaluator detected: %s" % name, bool(caught), "caught by %s" % caught[:6])
shutil.rmtree(td)

if OUT: json.dump(results, open(OUT, "w"), indent=1)
nf = sum(r["result"] == "FAIL" for r in results); print("TOTAL %d tests: %d PASS, %d FAIL" % (len(results), len(results) - nf, nf)); sys.exit(1 if nf else 0)
