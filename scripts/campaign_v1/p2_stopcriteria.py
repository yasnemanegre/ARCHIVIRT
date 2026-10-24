"""ARCHIVIRT — shared stop-criteria logic (PROPOSAL C1.3). Pure functions, no I/O side effects.

Sample record (JSONL): {"seq", "ts_epoch", "ts_iso", "run_id", "mode",
  "values": {metric: number}, "status": {metric: MEASURED|MISSING|NOT_APPLICABLE|ERROR}}
A metric has a numeric value ONLY when its status is MEASURED; 0 is a valid measurement.
"""
import json, operator
OPS = {"<": operator.lt, ">": operator.gt}
STATUSES = ("MEASURED", "MISSING", "NOT_APPLICABLE", "ERROR")

class ParamsError(ValueError):
    pass

def load_params(raw_bytes):
    p = json.loads(raw_bytes)
    if p.get("schema") != "archivirt-stop-criteria/2":
        raise ParamsError("schema must be archivirt-stop-criteria/2")
    iv = p.get("interval_s")
    if not isinstance(iv, (int, float)) or iv <= 0:
        raise ParamsError("interval_s must be > 0")
    mets = p.get("metrics") or {}
    for name, c in (p.get("criteria") or {}).items():
        if c.get("metric") not in mets: raise ParamsError("criterion %s: unknown metric" % name)
        if c.get("op") not in OPS: raise ParamsError("criterion %s: op must be < or >" % name)
        if ("sustain_s" in c) == ("sustain_samples" in c): raise ParamsError("criterion %s: exactly one of sustain_s / sustain_samples" % name)
        if "sustain_s" in c and c["sustain_s"] < 0: raise ParamsError("criterion %s: sustain_s < 0" % name)
        if "sustain_samples" in c and (not isinstance(c["sustain_samples"], int) or c["sustain_samples"] < 1):
            raise ParamsError("criterion %s: sustain_samples must be an int >= 1" % name)
        # a moving-average metric cannot be meaningfully sampled slower than its window
        if c["metric"].endswith("_avg10") and iv > 10: raise ParamsError("interval_s > 10 s for an avg10 metric")
    gp = (p.get("gap_policy") or {}).get("value")
    if gp not in ("unknown_invalidates", "break"): raise ParamsError("gap_policy.value must be unknown_invalidates|break")
    if not 0 <= p.get("max_missing_fraction", -1) < 1: raise ParamsError("max_missing_fraction must be in [0,1)")
    return p

def applicable(params, metric, mode):
    return mode in params["metrics"][metric]["modes"]

class CriterionState:
    """Incremental evaluation of ONE criterion (used live by the recorder and offline by the evaluator)."""
    def __init__(self, name, c, gap_policy):
        self.name, self.c, self.gap = name, c, gap_policy
        self.op = OPS[c["op"]]
        self.run = []            # consecutive exceeding samples (ts, value)
        self.gap_in_run = False
        self.hit = None          # confirmed exceedance
        self.unknown = False     # NOT_EVALUABLE because of a gap inside an exceeding run

    def _confirmed(self):
        if "sustain_samples" in self.c:
            return len(self.run) >= self.c["sustain_samples"]
        return len(self.run) >= 1 and (self.run[-1][0] - self.run[0][0]) >= self.c["sustain_s"]

    def feed(self, ts, status, value):
        if status != "MEASURED":
            if self.run:
                if self.gap == "unknown_invalidates":
                    self.unknown = True      # cannot tell whether the exceedance continued
                self.run = []
            return
        if self.op(value, self.c["value"]):
            self.run.append((ts, value))
            if self._confirmed():
                peak = (min if self.c["op"] == "<" else max)(v for _, v in self.run)
                if self.hit is None:
                    self.hit = {"criterion": self.name, "metric": self.c["metric"], "origin": self.c.get("origin"),
                                "first_ts": self.run[0][0], "last_ts": ts, "peak": peak}
                else:
                    self.hit["last_ts"] = ts
                    self.hit["peak"] = (min if self.c["op"] == "<" else max)(self.hit["peak"], peak)
        else:
            self.run = []
