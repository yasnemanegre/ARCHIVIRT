#!/usr/bin/env python3
"""ARCHIVIRT — per-run stop-criteria lifecycle (PROPOSAL C1.3, F-02).

  start    : launch the recorder for one run (detached), prove it works (first sample within
             --first-sample-timeout s); writes <run>/stopwatch.pid. Exit 6 on failure
             (recorder_failure.json written; the run must not start).
  check    : 0 = recorder alive and no abort; 7 = immediate abort requested (abort.json);
             6 = recorder dead / no recent sample (stale > 3 intervals).
  stop     : SIGTERM, wait, require the {"end": true} record. Exit 6 if not clean.
  finalize : run the evaluator on the run's data and write the stop_criteria block into
             result.json (creates an INVALID result.json for an interrupted run). Always
             keeps stopwatch.jsonl / abort.json / remote data. --note REASON forces
             run_status=INVALID with that reason (interruption, agent failure...).
  mark-invalid : force run_status=INVALID + reason in result.json (guarded; used when the
             evaluator itself failed). Never touches a protected zone.
STEP0 (BL-1): stop/check act ONLY on the recorder of THIS run: the PID read from
stopwatch.pid must belong to a live process whose command line contains
archivirt_stopwatch.py AND this run's stopwatch.jsonl path (no foreign process can be
signalled after PID reuse).
Remote command per metrics source (T1, owner decision): ssh -> remote_metrics_ssh.sh;
telegraf -> remote_metrics_telegraf.sh (refuses: needs the Vault token); agent -> no live
remote metrics (agent stream evaluated post-run via --remote-jsonl); none -> no remote metrics
(remote criteria become NOT_EVALUABLE -> INVALID: never a silent VALID).
"""
import argparse, json, os, signal, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
PY = [sys.executable, "-B"]

def remote_cmd(source, mode):
    if source == "ssh": return "bash %s %s" % (os.path.join(HERE, "remote_metrics_ssh.sh"), mode)
    if source == "telegraf": return "bash %s %s" % (os.path.join(HERE, "remote_metrics_telegraf.sh"), mode)
    return ""

def pid_alive(pid):
    try: os.kill(pid, 0); return True
    except OSError: return False

def is_our_recorder(pid, jsonl):
    """True only if <pid> is alive AND is the archivirt_stopwatch.py writing <jsonl>."""
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            argv = f.read().split(b"\0")
    except OSError:
        return False
    a = [x.decode(errors="replace") for x in argv]
    return any(x.endswith("archivirt_stopwatch.py") for x in a) and jsonl in a

def guarded_mark_invalid(rd, reason, repo, protect):
    guard = os.path.join(HERE, "results_guard.py")
    cmd = PY + [guard, "--repo", repo or "", "--dest", rd] + sum([["--protect", x] for x in protect], [])
    if not repo or subprocess.run(cmd, capture_output=True).returncode != 0:
        print("REFUSED: run directory is protected (or --repo missing)", file=sys.stderr); return 4
    rj = os.path.join(rd, "result.json")
    try: r = json.load(open(rj))
    except Exception: r = {}
    prev = r.get("invalid_reason") or ""
    r["run_status"] = "INVALID"
    r["invalid_reason"] = "; ".join(x for x in (prev, reason) if x)
    tmp = rj + ".tmp"
    with open(tmp, "w") as f: json.dump(r, f, indent=2)
    os.replace(tmp, rj); return 0

def last_record(path):
    try:
        lines = [l for l in open(path).read().splitlines() if l.strip()]
        return json.loads(lines[-1]) if lines else None
    except Exception:
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=("start", "check", "stop", "finalize", "mark-invalid"))
    ap.add_argument("--note"); ap.add_argument("--reason")
    ap.add_argument("--run-dir", required=True); ap.add_argument("--run-id"); ap.add_argument("--mode")
    ap.add_argument("--params"); ap.add_argument("--metrics-source", default="none")
    ap.add_argument("--first-sample-timeout", type=float, default=15); ap.add_argument("--proc", default="/proc")
    ap.add_argument("--interval", type=float); ap.add_argument("--repo"); ap.add_argument("--stats-log")
    ap.add_argument("--remote-jsonl"); ap.add_argument("--protect", action="append", default=[])
    ap.add_argument("--engine-stop")   # B-1 option B (opt-in): passed through to the evaluator
    a = ap.parse_args()
    rd = a.run_dir; jsonl = os.path.join(rd, "stopwatch.jsonl"); pidf = os.path.join(rd, "stopwatch.pid")
    abortf = os.path.join(rd, "abort.json")
    if a.action == "start":
        if os.path.exists(jsonl):
            print("REFUSED: stopwatch.jsonl already exists (no reuse of a run directory)", file=sys.stderr); return 6
        cmd = PY + [os.path.join(HERE, "archivirt_stopwatch.py"), "--out", jsonl, "--run-id", a.run_id, "--mode", a.mode,
                    "--params", a.params, "--abort-file", abortf, "--proc", a.proc]
        rc = remote_cmd(a.metrics_source, a.mode)
        if rc: cmd += ["--remote-cmd", rc]
        if a.interval: cmd += ["--interval", str(a.interval)]
        with open(os.path.join(rd, "stopwatch.stderr"), "w") as err:
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=err, start_new_session=True)
        open(pidf, "w").write(str(p.pid))
        t_end = time.time() + a.first_sample_timeout
        while time.time() < t_end:
            r = last_record(jsonl)
            if r and "seq" in r: print("recorder started pid=%d" % p.pid); return 0
            if p.poll() is not None: break
            time.sleep(0.1)
        if p.poll() is None: p.terminate()
        json.dump({"recorder_failure": "no first sample within %ss" % a.first_sample_timeout, "exit": p.poll()},
                  open(os.path.join(rd, "recorder_failure.json"), "w"))
        print("RECORDER_START_FAILED", file=sys.stderr); return 6
    if a.action == "check":
        if os.path.isfile(abortf): return 7
        try: pid = int(open(pidf).read())
        except Exception: return 6
        r = last_record(jsonl)
        stale = (a.interval or 5) * 3
        if not is_our_recorder(pid, jsonl) or not r or "ts_epoch" not in r or time.time() - r["ts_epoch"] > stale: return 6
        return 0
    if a.action == "stop":
        try: pid = int(open(pidf).read())
        except Exception: return 6
        if is_our_recorder(pid, jsonl):
            os.kill(pid, signal.SIGTERM)
            for _ in range(100):
                if not is_our_recorder(pid, jsonl): break
                time.sleep(0.1)
            if is_our_recorder(pid, jsonl):          # still alive after 10 s: last resort, same identity check
                os.kill(pid, signal.SIGKILL)
        elif pid_alive(pid):
            print("NOT_OURS: pid %d is not this run's recorder - not signalled" % pid, file=sys.stderr)
        r = last_record(jsonl)
        return 0 if (r and r.get("end")) else 6
    if a.action == "finalize":
        cmd = PY + [os.path.join(HERE, "archivirt_stopwatch_eval.py"), "--jsonl", jsonl, "--params", a.params, "--mode", a.mode,
                    "--abort-file", abortf, "--result-json", os.path.join(rd, "result.json"), "--repo", a.repo or ""]
        if a.stats_log: cmd += ["--stats-log", a.stats_log]
        if a.engine_stop: cmd += ["--engine-stop", a.engine_stop]
        if a.remote_jsonl: cmd += ["--remote-jsonl", a.remote_jsonl]
        for x in a.protect: cmd += ["--protect", x]
        r = subprocess.run(cmd, capture_output=True, text=True)
        open(os.path.join(rd, "stop_criteria_verdict.json"), "w").write(r.stdout)
        if r.returncode in (2, 4): sys.stderr.write(r.stderr)
        if a.note and r.returncode != 4:
            m = guarded_mark_invalid(rd, a.note, a.repo, a.protect)
            if m != 0: return m
            return 3 if r.returncode in (0, 3) else r.returncode
        return r.returncode
    if a.action == "mark-invalid":
        return guarded_mark_invalid(rd, a.reason or "INVALID (unspecified)", a.repo, a.protect)

if __name__ == "__main__":
    sys.exit(main())
