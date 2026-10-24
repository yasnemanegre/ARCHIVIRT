#!/usr/bin/env python3
"""ARCHIVIRT P2 — reproducible DBSCAN over Suricata eve.json FLOW events (experimental, series-scoped).

Replaces nothing: scripts/dbscan_from_fetched.py and results/dbscan_latest.json stay untouched.
Design (see DBSCAN_ML_ETAT_ET_PLAN.md):
  * inputs are explicit run directories; every eve.json is hashed into the output (provenance);
  * features are per-flow traffic properties only. No SID, no alert field, no IP address, so the
    clustering cannot rediscover the rules (no label leakage);
  * every random step uses the declared seed; parameters are read from a JSON file and copied out;
  * invalid input fails loudly (malformed JSON line, no flow event, too few flows), never silently;
  * the output directory must not exist (results are never overwritten).
Optional ground truth (--labels): JSON {"attack_windows": [[start_iso, end_iso, dest_ip], ...]}. A flow is
"attack" when it starts inside a window towards that destination. Precision/recall/F1 of "DBSCAN noise
= anomaly" are reported ONLY when labels are given.
Usage: dbscan_p2.py --params P.json --out OUTDIR RUN_DIR [RUN_DIR ...] [--labels L.json]
"""
import argparse, hashlib, json, math, os, resource, sys, time
from datetime import datetime

FEATURES = ("duration_s", "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "dest_port")
LOG_FEATURES = {"pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient"}


class InputError(Exception):
    pass


def ts(s):
    return datetime.strptime(s[:26] + s[-5:] if "." in s else s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def load_flows(run_dirs):
    flows, sources = [], []
    for d in run_dirs:
        p = os.path.join(d, "eve.json")
        if not os.path.isfile(p):
            p = os.path.join(d, "logs", "eve.json")
        if not os.path.isfile(p):
            raise InputError(f"no eve.json in {d}")
        with open(p, "rb") as fh:
            raw = fh.read()
        sources.append({"path": os.path.abspath(p), "sha256": hashlib.sha256(raw).hexdigest()})
        for n, line in enumerate(raw.decode().splitlines(), 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except ValueError as exc:
                raise InputError(f"{p}:{n}: malformed JSON ({exc})")
            if e.get("event_type") != "flow":
                continue
            f = e.get("flow") or {}
            try:
                start, end = ts(f["start"]), ts(f["end"])
                flows.append({"start": start, "dest_ip": e["dest_ip"], "values": {
                    "duration_s": max(0.0, end - start),
                    "pkts_toserver": int(f["pkts_toserver"]), "pkts_toclient": int(f["pkts_toclient"]),
                    "bytes_toserver": int(f["bytes_toserver"]), "bytes_toclient": int(f["bytes_toclient"]),
                    "dest_port": int(e.get("dest_port", 0))}})
            except (KeyError, ValueError, TypeError) as exc:
                raise InputError(f"{p}:{n}: flow event lacks a required field ({exc})")
    return flows, sources


def matrix(flows):
    import numpy as np
    rows = []
    for fl in flows:
        v = fl["values"]
        rows.append([math.log1p(v[k]) if k in LOG_FEATURES else float(v[k]) for k in FEATURES])
    return np.array(rows, dtype=float)


def labels_for(flows, labels_path):
    """Return (labels, sha256 of the labels file); the file is read once."""
    with open(labels_path, "rb") as fh:
        raw = fh.read()
    lab = json.loads(raw)
    win = [(ts(a), ts(b), ip) for a, b, ip in lab["attack_windows"]]
    return [any(a <= fl["start"] <= b and fl["dest_ip"] == ip for a, b, ip in win) for fl in flows], hashlib.sha256(raw).hexdigest()


def run(args):
    import numpy as np
    from sklearn.cluster import DBSCAN
    from sklearn.metrics import adjusted_rand_score, silhouette_score
    from sklearn.preprocessing import StandardScaler
    with open(args.params) as fh:
        params = json.load(fh)
    for k in ("eps", "min_samples", "seed", "stability_subsample", "stability_repeats", "min_flows"):
        if k not in params:
            raise InputError(f"parameter {k} missing in {args.params}")
    if os.path.exists(args.out):
        raise InputError(f"output {args.out} exists (results are never overwritten)")
    t0 = time.process_time()
    flows, sources = load_flows(args.run_dirs)
    if len(flows) < params["min_flows"]:
        raise InputError(f"{len(flows)} flow events < min_flows={params['min_flows']} "
                         "(is eve 'flow' logging enabled in suricata.yaml?)")
    X = StandardScaler().fit_transform(matrix(flows))
    lab = DBSCAN(eps=params["eps"], min_samples=params["min_samples"]).fit_predict(X)
    noise = int((lab == -1).sum())
    clusters = len(set(lab.tolist()) - {-1})
    core = lab != -1
    sil = (float(silhouette_score(X[core], lab[core])) if clusters >= 2 and core.sum() > clusters else None)
    rng = np.random.default_rng(params["seed"])
    aris = []
    m = max(params["min_samples"] + 1, int(len(flows) * params["stability_subsample"]))
    for _ in range(params["stability_repeats"]):
        idx = np.sort(rng.choice(len(flows), size=m, replace=False))
        sub = DBSCAN(eps=params["eps"], min_samples=params["min_samples"]).fit_predict(X[idx])
        aris.append(float(adjusted_rand_score(lab[idx], sub)))
    k = params["min_samples"]
    d = np.sort(np.linalg.norm(X[:, None, :] - X[None, :, :], axis=2), axis=1)[:, min(k, len(flows) - 1)]
    out = {"schema": "archivirt-dbscan-p2/1", "series": params.get("series"), "params": params,
           "features": list(FEATURES), "log_features": sorted(LOG_FEATURES), "inputs": sources,
           "n_flows": len(flows), "n_clusters": clusters, "n_noise": noise,
           "noise_fraction": round(noise / len(flows), 6), "silhouette_non_noise": sil,
           "stability_ari": {"mean": round(float(np.mean(aris)), 6), "min": round(float(np.min(aris)), 6),
                             "repeats": len(aris), "subsample": params["stability_subsample"]},
           "k_distance_percentiles": {p: round(float(np.percentile(d, p)), 6) for p in (50, 90, 95, 99)},
           "cpu_time_s": round(time.process_time() - t0, 6),
           "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    if args.labels:
        y, labels_sha = labels_for(flows, args.labels)
        pred = (lab == -1).tolist()
        tp = sum(p and t for p, t in zip(pred, y)); fp = sum(p and not t for p, t in zip(pred, y))
        fn = sum((not p) and t for p, t in zip(pred, y)); tn = len(y) - tp - fp - fn
        r = lambda a, b: round(a / b, 6) if b else None
        out["noise_as_anomaly"] = {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": r(tp, tp + fp),
                                   "recall": r(tp, tp + fn), "f1": r(2 * tp, 2 * tp + fp + fn), "fpr": r(fp, fp + tn),
                                   "labels_sha256": labels_sha}
    os.makedirs(args.out)
    with open(os.path.join(args.out, "dbscan_p2.json"), "w") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--params", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--labels")
    ap.add_argument("run_dirs", nargs="+")
    args = ap.parse_args(argv)
    try:
        out = run(args)
    except InputError as exc:
        print(f"INPUT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({k: out[k] for k in ("n_flows", "n_clusters", "noise_fraction", "stability_ari")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
