#!/bin/bash
# ARCHIVIRT campaign_v1 — effective AF_PACKET ring geometry of THIS run's Suricata instance (READ-ONLY).
# Runs ON the monitor host (ansible -m script), after experiment_end and BEFORE stop_engine (outside the burst).
# Prints ONE JSON line (ARCHIVIRT_GEOMETRY=...) and writes it to <logdir>/capture_geometry.json.
#
# Why (RCA D0 2026-10-22): the yaml said tpacket-v3, but Suricata 6.0.4 enables v3 only in runmode 'workers';
# with autofp the rings were TPACKET_V2 (2060 frames/socket). The mmap size alone cannot tell v2 from v3
# (same 103 x 32 KiB), so the frame/block headers are read: tpacket2_hdr every <frame_size> bytes (v2) or a
# tpacket_block_desc + tpacket3_hdr chain (v3). Nothing is written to the process or the sockets.
#
# Top-level "status" (r2, 2026-10-23, B-2): OK only if at least one ring socket was observed AND every observed socket
# has a determined layout AND all determined sockets agree (layout, frames); otherwise NO_SOCKET / INCOMPLETE /
# INCONSISTENT (per-socket details kept). UNREADABLE / NO_INSTANCE unchanged. The probe reports OBSERVED sockets only:
# how many sockets are REQUIRED is decided by the consumer's criteria, never here. "memory_read" keeps the r1 meaning.
#
# Usage: capture_geometry.sh <logdir>
# Test hooks (offline only): ARCHIVIRT_GEOM_MAPS / ARCHIVIRT_GEOM_MEM (files), ARCHIVIRT_GEOM_PID, ARCHIVIRT_SUDO="".
set -uo pipefail
LOGDIR="${1:?usage: capture_geometry.sh <logdir>}"
SUDO="${ARCHIVIRT_SUDO-sudo}"
if [ -n "${ARCHIVIRT_GEOM_PID:-}" ]; then
    pid="$ARCHIVIRT_GEOM_PID"
else
    pid=""
    for p in $(pgrep -f "[s]uricata .* -l ${LOGDIR}" 2>/dev/null); do        # same identity rule as suricata.sh find_daemon
        [ "$(cat "/proc/$p/comm" 2>/dev/null)" = Suricata-Main ] || continue
        tr '\0' '\n' < "/proc/$p/cmdline" 2>/dev/null | awk -v d="$LOGDIR" 'prev == "-l" && $0 == d {f = 1} {prev = $0} END {exit !f}' \
            && { pid="$p"; break; }
    done
fi
if [ -z "$pid" ]; then
    out='{"status":"NO_INSTANCE","logdir":"'"$LOGDIR"'"}'
else
    out=$($SUDO python3 -I - "$pid" "${ARCHIVIRT_GEOM_MAPS:-/proc/$pid/maps}" "${ARCHIVIRT_GEOM_MEM:-/proc/$pid/mem}" <<'PY'
import json, struct, sys
pid, maps, mem = sys.argv[1:4]
BLK = 32768                                         # Suricata 6 ring block (getpagesize() << 3)
def v2_headers(buf):
    """offsets of plausible tpacket2_hdr: tp_len/tp_snaplen, tp_mac, tp_net = tp_mac + 14 (+4 per VLAN tag)."""
    hits = []
    for o in range(0, len(buf) - 32, 16):
        st, ln, sn, mac, net, sec = struct.unpack_from("<IIIHHI", buf, o)
        if 0 < sn <= ln <= 65535 and 32 <= mac < 512 and net - mac in (14, 18, 22) and sec > 0: hits.append(o)
    return hits
def v3_block(buf):
    if len(buf) < 48: return None
    st, npk, off, blen = struct.unpack_from("<IIII", buf, 8)
    if not (npk > 0 and 32 <= off < 512 and off < blen <= len(buf)): return None
    nxt, sec, nsec, sn, ln, pst, mac, net = struct.unpack_from("<IIIIIIHH", buf, off)
    if 0 < sn <= ln <= 65535 and net - mac in (14, 18, 22): return {"num_pkts": npk, "offset_to_first_pkt": off}
    return None
res = {"status": "OK", "pid": int(pid), "sockets": []}
try:
    regions = []
    for line in open(maps):
        f = line.split()
        if len(f) >= 6 and f[5].startswith("socket:["):
            a, b = (int(x, 16) for x in f[0].split("-")); regions.append((a, b, f[5]))
    with open(mem, "rb") as m:
        for a, b, name in regions:
            size = b - a; blocks = size // BLK; s = {"socket": name, "mmap_bytes": size, "blocks_32k": blocks}
            layout = None
            for k in range(min(blocks, 16)):                                      # first 16 blocks only: bounded read
                m.seek(a + k * BLK); buf = m.read(BLK)
                v3 = v3_block(buf)
                if v3: layout = {"layout": "TPACKET_V3", "first_block": k, **v3}; break
                h = v2_headers(buf)
                if len(h) >= 2:
                    # r1 (2026-10-22): the gcd of the header offsets is NOT the frame size when the kernel ring uses
                    # blocks smaller than 32 KiB (Suricata retries a lower block order on ENOMEM): 16 KiB blocks gave
                    # gcd 64 -> "frame_size 64, frames 52736" reported OK. Now: frame = most frequent gap, block size =
                    # the only candidate on which EVERY header sits on a frame slot; otherwise UNDETERMINED.
                    gaps = [y - x for x, y in zip(h, h[1:])]
                    frame = max(set(gaps), key=gaps.count)
                    fits = [b for b in (4096, 8192, 16384, 32768) if frame <= b and size % b == 0
                            and all((x % b) % frame == 0 and (x % b) // frame < b // frame for x in h)]
                    if frame >= 64 and len(fits) == 1:
                        bsz = fits[0]; fpb = bsz // frame
                        layout = {"layout": "TPACKET_V2", "frame_size": frame, "block_size": bsz, "frames_per_block": fpb,
                                  "frames": fpb * (size // bsz), "headers_seen_in_block": len(h), "first_block": k}
                        break
            s.update(layout or {"layout": "UNDETERMINED", "reason": "no packet header found in the ring"})
            res["sockets"].append(s)
    socks = res["sockets"]; det = [s for s in socks if s.get("layout") in ("TPACKET_V2", "TPACKET_V3")]
    res["memory_read"] = "OK"; res["sockets_observed"] = len(socks); res["sockets_determined"] = len(det)
    if not socks: res["status"] = "NO_SOCKET"
    elif len(det) != len(socks): res["status"] = "INCOMPLETE"
    elif len({(s["layout"], s.get("frames")) for s in det}) != 1: res["status"] = "INCONSISTENT"
except Exception as e:
    res = {"status": "UNREADABLE", "pid": int(pid), "error": type(e).__name__}
print(json.dumps(res, sort_keys=True))
PY
) || out='{"status":"UNREADABLE","pid":'"$pid"'}'
fi
echo "ARCHIVIRT_GEOMETRY=$out"
printf '%s\n' "$out" | $SUDO tee "$LOGDIR/capture_geometry.json" >/dev/null 2>&1 || true
exit 0
