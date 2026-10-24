#!/usr/bin/env python3
"""ARCHIVIRT P2 (option F1) — engine-neutral flow records derived OFFLINE from a preserved pcap.

No dependency (pure Python pcap reader, Ethernet/IPv4, TCP/UDP/ICMP). Writes into a NEW directory:
  eve.json      one {"event_type": "flow", ...} line per bidirectional flow (format read by dbscan_p2.py);
                carries dest_ip/dest_port only for labelling and the dbscan_p2 port feature; no alert, no SID
  labels.json   (optional, --ground-truth) attack windows derived from validate_engine.sh ground_truth.txt,
                kept SEPARATE from the features
  metadata.json pcap sha256, tool sha256, parameters, packet/flow counts, skipped frames by reason
Flow key: protocol + unordered (ip, port) pair; the initiator (first packet) is the "client" (to-server side).
Usage: pcap_flows.py --pcap CAP.pcap --out OUTDIR [--ground-truth ground_truth.txt] [--idle-timeout 60]
"""
import argparse, hashlib, json, os, struct, sys
from datetime import datetime, timezone

VERSION = "1"


class InputError(Exception):
    pass


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def read_pcap(raw):
    if len(raw) < 24:
        raise InputError("pcap shorter than its global header")
    magic = raw[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        e, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        e, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        e, nano = "<", True
    else:
        raise InputError("not a classic pcap file (pcapng is not supported)")
    linktype = struct.unpack(e + "I", raw[20:24])[0]
    if linktype != 1:
        raise InputError(f"linktype {linktype} is not Ethernet")
    off = 24
    while off + 16 <= len(raw):
        sec, frac, incl, orig = struct.unpack(e + "IIII", raw[off:off + 16])
        frame = raw[off + 16:off + 16 + incl]
        if len(frame) < incl:
            raise InputError(f"truncated record at byte {off}")
        off += 16 + incl
        yield sec + frac / (1e9 if nano else 1e6), frame, orig


def flows_from(raw, idle):
    flows, skipped, n = {}, {}, 0
    done = []
    for t, fr, orig in read_pcap(raw):
        n += 1
        if len(fr) < 34 or struct.unpack("!H", fr[12:14])[0] != 0x0800:
            skipped["non-ipv4"] = skipped.get("non-ipv4", 0) + 1
            continue
        ihl = (fr[14] & 15) * 4
        total = struct.unpack("!H", fr[16:18])[0]
        proto = fr[23]
        src, dst = ".".join(map(str, fr[26:30])), ".".join(map(str, fr[30:34]))
        l4 = fr[14 + ihl:]
        if proto in (6, 17) and len(l4) >= 4:
            sp, dp = struct.unpack("!HH", l4[:4])
        elif proto == 1:
            sp = dp = 0
        else:
            skipped[f"proto-{proto}"] = skipped.get(f"proto-{proto}", 0) + 1
            continue
        key = (proto,) + tuple(sorted([(src, sp), (dst, dp)]))
        f = flows.get(key)
        if f and t - f["last"] > idle:
            done.append(flows.pop(key)); f = None
        if f is None:
            f = flows[key] = {"proto": proto, "client": (src, sp), "server": (dst, dp), "first": t, "last": t,
                              "pkts_toserver": 0, "pkts_toclient": 0, "bytes_toserver": 0, "bytes_toclient": 0}
        side = "toserver" if (src, sp) == f["client"] else "toclient"
        f["pkts_" + side] += 1
        f["bytes_" + side] += total          # IP datagram length (independent of capture snaplen)
        f["last"] = t
    return done + list(flows.values()), n, skipped


def attack_windows(gt_path, margin):
    """CANARY / ATTACK lines of ground_truth.txt -> [start, end, dest_ip] windows (labels only)."""
    wins = []
    with open(gt_path) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 2 or not parts[1].startswith("CANARY"):
                continue
            t = datetime.strptime(parts[0], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()
            dst = next((p for p in parts if p.count(".") == 3 and p[0].isdigit()), None)
            if dst:
                wins.append([iso(t - margin), iso(t + margin), dst])
    if not wins:
        raise InputError(f"no CANARY line with a destination in {gt_path}")
    return wins


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--ground-truth")
    ap.add_argument("--idle-timeout", type=float, default=60.0)
    ap.add_argument("--label-margin-s", type=float, default=2.0)
    a = ap.parse_args(argv)
    try:
        if os.path.exists(a.out):
            raise InputError(f"output {a.out} exists (results are never overwritten)")
        with open(a.pcap, "rb") as fh:
            raw = fh.read()
        flows, npk, skipped = flows_from(raw, a.idle_timeout)
        if not flows:
            raise InputError("no IPv4 flow in the pcap")
        labels = attack_windows(a.ground_truth, a.label_margin_s) if a.ground_truth else None
    except InputError as exc:
        print(f"INPUT_ERROR: {exc}", file=sys.stderr)
        return 2
    os.makedirs(a.out)
    with open(os.path.join(a.out, "eve.json"), "w") as fh:
        for f in sorted(flows, key=lambda x: x["first"]):
            fh.write(json.dumps({"event_type": "flow", "proto": {6: "TCP", 17: "UDP", 1: "ICMP"}[f["proto"]],
                                 "dest_ip": f["server"][0], "dest_port": f["server"][1],
                                 "flow": {"start": iso(f["first"]), "end": iso(f["last"]),
                                          **{k: f[k] for k in ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient")}}},
                                sort_keys=True) + "\n")
    if labels:
        with open(os.path.join(a.out, "labels.json"), "w") as fh:
            json.dump({"attack_windows": labels, "source": os.path.abspath(a.ground_truth)}, fh, indent=1)
    with open(os.path.abspath(__file__), "rb") as fh:
        tool_sha = hashlib.sha256(fh.read()).hexdigest()
    meta = {"schema": "archivirt-pcap-flows/1", "tool": "pcap_flows.py", "tool_version": VERSION, "tool_sha256": tool_sha,
            "python": sys.version.split()[0], "pcap": os.path.abspath(a.pcap), "pcap_sha256": hashlib.sha256(raw).hexdigest(),
            "params": {"idle_timeout_s": a.idle_timeout, "label_margin_s": a.label_margin_s},
            "packets": npk, "flows": len(flows), "skipped_frames": skipped, "labels": bool(labels)}
    with open(os.path.join(a.out, "metadata.json"), "w") as fh:
        json.dump(meta, fh, indent=1, sort_keys=True)
    print(json.dumps({k: meta[k] for k in ("packets", "flows", "skipped_frames", "labels")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
