#!/usr/bin/env python3
"""ARCHIVIRT — phase-2 campaign contract (PROPOSAL C1.3, F-01/F-03/F-08/F-09).

Single, side-effect-free validation of the interface between the cycle (04/06) and
campaign_v1.sh. Reads the environment, validates EVERY mandatory parameter, and prints
either shell assignments (shlex-quoted) or JSON. Nothing is created or written.
Exit 0 = valid, 4 = invalid (all problems listed on stderr).

Mandatory variables (no default; owner decisions D-A1, D-A3, T1):
  ARCHIVIRT_RESULTS_ROOT       absolute, outside repo and protected zones (results_guard)
  ARCHIVIRT_EXPERIMENT_SERIES  ^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$, not ARTICLE* / UNSET (case-insensitive)
  ARCHIVIRT_CAMPAIGN_PREFIX    ^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$, not ARTICLE* (case-insensitive)
  ARCHIVIRT_STOP_CRITERIA      readable JSON, schema archivirt-stop-criteria/2
  ARCHIVIRT_OFFLINE_MANIFEST   readable JSON, schema v1 (manifest_version 1.0) or v2 (explicit)
  ARCHIVIRT_METRICS_SOURCE     one of: ssh | telegraf | agent | none   (T1)
Optional: MODE (ids|ips|baseline, default ids), ENFORCE_OFFLINE must be 1 in series mode.
Usage: p2_contract.py --repo R [--protect P]... [--format sh|json]
"""
import argparse, json, os, re, shlex, subprocess, sys
SERIES_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
SOURCES = ("ssh", "telegraf", "agent", "none")

def manifest_schema(path):
    m = json.load(open(path))
    if m.get("schema") == "archivirt-offline-manifest/2":
        return 2
    if m.get("manifest_version") == "1.0" and "schema" not in m:
        return 1
    raise ValueError("unknown manifest schema")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True); ap.add_argument("--protect", action="append", default=[])
    ap.add_argument("--format", choices=("sh", "json"), default="sh")
    a = ap.parse_args()
    env, errs, out = os.environ, [], {}
    def need(k):
        v = env.get(k, "").strip()
        if not v: errs.append("%s is required" % k)
        return v
    root, series, prefix = need("ARCHIVIRT_RESULTS_ROOT"), need("ARCHIVIRT_EXPERIMENT_SERIES"), need("ARCHIVIRT_CAMPAIGN_PREFIX")
    stop, mani, src = need("ARCHIVIRT_STOP_CRITERIA"), need("ARCHIVIRT_OFFLINE_MANIFEST"), need("ARCHIVIRT_METRICS_SOURCE")
    if series and (not SERIES_RE.match(series) or series.casefold().startswith("article") or series.casefold() == "unset"):
        errs.append("invalid series %r (pattern, or reserved ARTICLE*/UNSET, case-insensitive)" % series)
    if prefix and (not PREFIX_RE.match(prefix) or prefix.casefold().startswith("article")):
        errs.append("invalid campaign prefix %r (pattern, or reserved ARTICLE*, case-insensitive)" % prefix)
    if src and src not in SOURCES:
        errs.append("ARCHIVIRT_METRICS_SOURCE must be one of %s" % "|".join(SOURCES))
    mode = env.get("MODE", "ids")
    if mode not in ("ids", "ips", "baseline"): errs.append("MODE must be ids|ips|baseline")
    if env.get("ENFORCE_OFFLINE", "1") != "1": errs.append("ENFORCE_OFFLINE=0 is refused in series mode")
    if stop:
        try:
            sc = json.load(open(stop))
            if sc.get("schema") != "archivirt-stop-criteria/2": errs.append("stop criteria schema must be archivirt-stop-criteria/2")
            # Owner reference 2026-10-21: host MemAvailable >= 900 MiB; a run with any sample below it is INVALID
            # (distinct from the < 300 MiB immediate safety stop). Refuse criteria files that do not carry it.
            if not any(c.get("metric") == "host_mem_available_mib" and c.get("op") == "<" and not c.get("immediate")
                       and isinstance(c.get("value"), (int, float)) and c["value"] >= 900 and c.get("sustain_samples") == 1
                       for c in (sc.get("criteria") or {}).values()):
                errs.append("stop criteria lack the host memory reference (host_mem_available_mib < 900, sustain_samples 1, not immediate)")
            out["STOP_CRITERIA_STATUS"] = str(sc.get("status"))
        except Exception as e: errs.append("stop criteria unreadable: %s" % e)
    if mani:
        try: out["OFFLINE_MANIFEST_SCHEMA"] = str(manifest_schema(mani))
        except Exception as e: errs.append("offline manifest invalid: %s" % e)
    if root:
        if not os.path.isabs(root): errs.append("ARCHIVIRT_RESULTS_ROOT must be absolute")
        else:
            g = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_guard.py"),
                 "--repo", a.repo, "--dest", root] + sum([["--protect", p] for p in a.protect], [])
            r = subprocess.run(g, capture_output=True, text=True)
            if r.returncode != 0: errs.append("results root refused: %s" % r.stderr.strip())
            else: root = r.stdout.strip()
    if errs:
        for e in errs: print("CONTRACT_ERROR: " + e, file=sys.stderr)
        return 4
    out.update({"RESULTS": root, "SERIES": series, "CAMPAIGN_PREFIX": prefix, "STOP_CRITERIA": os.path.abspath(stop),
                "ARCHIVIRT_OFFLINE_MANIFEST": os.path.abspath(mani), "METRICS_SOURCE": src, "MODE": mode})
    if a.format == "json": print(json.dumps(out, sort_keys=True))
    else:
        for k in sorted(out): print("%s=%s" % (k, shlex.quote(out[k])))
    return 0

if __name__ == "__main__":
    sys.exit(main())
