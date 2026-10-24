#!/usr/bin/env python3
"""Unit tests for pcap_flows.py (synthetic pcap built in memory; no lab access). Run: python3 test_pcap_flows.py -v"""
import json, os, shutil, struct, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcap_flows  # noqa: E402


def ip(a):
    return bytes(int(x) for x in a.split("."))


def frame(src, dst, proto, sp=0, dp=0, payload=b""):
    l4 = struct.pack("!HH", sp, dp) + b"\x00" * 16 + payload if proto in (6, 17) else b"\x08\x00\x00\x00\x00\x00\x00\x00" + payload
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, ip(src), ip(dst))
    return b"\x00" * 12 + b"\x08\x00" + iph + l4


def pcap(records):
    out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for t, fr in records:
        out += struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(fr), len(fr)) + fr
    return out


def write(path, data, mode="wb"):
    with open(path, mode) as fh:
        fh.write(data)


class T(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        t0 = 1792530000.0
        recs = []
        for i in range(3):   # 3 HTTP flows attacker -> target, 3 packets each way
            for k in range(3):
                recs.append((t0 + i + k * 0.01, frame("10.0.4.10", "10.0.2.11", 6, 40000 + i, 80, b"x" * 100)))
                recs.append((t0 + i + k * 0.01 + 0.005, frame("10.0.2.11", "10.0.4.10", 6, 80, 40000 + i, b"y" * 500)))
        recs.append((t0 + 5, frame("10.0.4.10", "10.0.2.11", 1, payload=b"ARCHIVIRT-ICMP-CANARY")))
        recs.append((t0 + 6, b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28))   # ARP -> skipped
        self.pcap = os.path.join(self.tmp, "c.pcap"); write(self.pcap, pcap(recs))
        self.gt = os.path.join(self.tmp, "gt.txt")
        write(self.gt, "2026-10-20T22:20:05.000Z CANARY icmp payload x3 -> 10.0.2.11 -> 0 packets\n"
                       "2026-10-20T22:20:09.000Z LEGIT-AFTER http GET 10.0.2.11 -> 200\n", "w")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_tool(self, name, *extra):
        out = os.path.join(self.tmp, name)
        rc = pcap_flows.main(["--pcap", self.pcap, "--out", out, *extra])
        return rc, out

    def test_flows_and_directions(self):
        rc, out = self.run_tool("a")
        self.assertEqual(rc, 0)
        with open(os.path.join(out, "eve.json")) as fh:
            ev = [json.loads(l) for l in fh]
        self.assertEqual(len(ev), 4)                                    # 3 TCP + 1 ICMP
        tcp = [e for e in ev if e["proto"] == "TCP"]
        self.assertTrue(all(e["dest_port"] == 80 and e["flow"]["pkts_toserver"] == 3 and e["flow"]["pkts_toclient"] == 3 for e in tcp))
        self.assertTrue(all(e["flow"]["bytes_toclient"] > e["flow"]["bytes_toserver"] for e in tcp))
        with open(os.path.join(out, "metadata.json")) as fh:
            meta = json.load(fh)
        self.assertEqual((meta["packets"], meta["flows"], meta["skipped_frames"]), (20, 4, {"non-ipv4": 1}))

    def test_reproducible_byte_identical(self):
        _, a = self.run_tool("a"); _, b = self.run_tool("b")
        with open(os.path.join(a, "eve.json"), "rb") as f1, open(os.path.join(b, "eve.json"), "rb") as f2:
            self.assertEqual(f1.read(), f2.read())

    def test_no_label_or_alert_field_in_records(self):
        _, out = self.run_tool("a", "--ground-truth", self.gt)
        with open(os.path.join(out, "eve.json")) as fh:
            for l in fh:
                e = json.loads(l)
                self.assertNotIn("alert", e); self.assertNotIn("label", json.dumps(e)); self.assertNotIn("src_ip", e)
        with open(os.path.join(out, "labels.json")) as fh:
            lab = json.load(fh)
        self.assertEqual(len(lab["attack_windows"]), 1)
        self.assertEqual(lab["attack_windows"][0][2], "10.0.2.11")

    def test_refuses_existing_output_and_bad_input(self):
        os.makedirs(os.path.join(self.tmp, "x"))
        self.assertEqual(self.run_tool("x")[0], 2)
        write(self.pcap, b"not a pcap at all, definitely")
        self.assertEqual(self.run_tool("y")[0], 2)


if __name__ == "__main__":
    unittest.main()
