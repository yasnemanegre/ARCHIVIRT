#!/usr/bin/env python3
"""Low-cost unit tests for dbscan_p2.py (synthetic eve.json; no lab access). Run: python3 -I -m unittest -v test_dbscan_p2"""
import json, os, random, shutil, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dbscan_p2  # noqa: E402

def write(path, text):
    with open(path, "w") as fh:
        fh.write(text)


PARAMS = {"series": "TEST", "eps": 0.8, "min_samples": 4, "seed": 7, "stability_subsample": 0.8,
          "stability_repeats": 5, "min_flows": 20}


def flow(i, start, dur, pts, ptc, bts, btc, port, dst="10.0.2.11"):
    s = f"2026-10-20T20:{10 + i // 60:02d}:{i % 60:02d}.000000+0000"
    e = f"2026-10-20T20:{10 + i // 60:02d}:{i % 60:02d}.{int(dur * 1e5):06d}+0000"
    return json.dumps({"event_type": "flow", "src_ip": "10.0.4.10", "dest_ip": dst, "dest_port": port, "proto": "TCP",
                       "flow": {"start": s, "end": e, "pkts_toserver": pts, "pkts_toclient": ptc,
                                "bytes_toserver": bts, "bytes_toclient": btc},
                       "alert": {"signature_id": 9999}})


class T(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        rnd = random.Random(1)
        lines = [flow(i, 0, 0.05, 6 + rnd.randint(0, 2), 5 + rnd.randint(0, 2), 500 + rnd.randint(0, 50),
                      900 + rnd.randint(0, 50), 80) for i in range(60)]
        # 3 dispersed scan-like outliers (< min_samples=4, so they cannot form their own cluster)
        lines += [flow(60 + i, 0, 0.001 * (i + 1), 1 + 3 * i, 1, 60 * (i + 1), 54, 1000 + 9000 * i) for i in range(3)]
        self.run_dir = os.path.join(self.tmp, "run1"); os.makedirs(self.run_dir)
        self.lines = lines
        write(os.path.join(self.run_dir, "eve.json"), "\n".join(lines + [json.dumps({"event_type": "alert"})]) + "\n")
        self.params = os.path.join(self.tmp, "p.json"); write(self.params, json.dumps(PARAMS))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def out(self, name):
        return os.path.join(self.tmp, name)

    def test_deterministic_with_seed(self):
        a = dbscan_p2.run(dbscan_p2.argparse.Namespace(params=self.params, out=self.out("a"), labels=None, run_dirs=[self.run_dir]))
        b = dbscan_p2.run(dbscan_p2.argparse.Namespace(params=self.params, out=self.out("b"), labels=None, run_dirs=[self.run_dir]))
        for k in ("n_clusters", "n_noise", "stability_ari", "k_distance_percentiles"):
            self.assertEqual(a[k], b[k])
        # fixture: 60 tight HTTP-like flows + 3 dispersed outliers -> exactly 1 cluster and 3 noise points
        self.assertEqual((a["n_flows"], a["n_clusters"], a["n_noise"]), (63, 1, 3))
        self.assertEqual(a["inputs"][0]["sha256"], b["inputs"][0]["sha256"])

    def test_no_label_leakage_in_features(self):
        for f in dbscan_p2.FEATURES:
            self.assertNotIn("sid", f.lower()); self.assertNotIn("ip", f.lower()); self.assertNotIn("alert", f.lower())

    def test_outliers_are_noise_and_labels_metrics(self):
        lab = self.out("lab.json")
        write(lab, json.dumps({"attack_windows": [["2026-10-20T20:11:00.000000+0000", "2026-10-20T20:11:59.000000+0000", "10.0.2.11"]]}))
        r = dbscan_p2.run(dbscan_p2.argparse.Namespace(params=self.params, out=self.out("c"), labels=lab, run_dirs=[self.run_dir]))
        self.assertEqual(r["n_noise"], 3)
        self.assertIn("noise_as_anomaly", r)
        self.assertEqual(r["noise_as_anomaly"]["TP"] + r["noise_as_anomaly"]["FN"], 3)
        self.assertEqual((r["noise_as_anomaly"]["TP"], r["noise_as_anomaly"]["FP"], r["noise_as_anomaly"]["FN"], r["noise_as_anomaly"]["TN"]), (3, 0, 0, 60))

    def test_refuses_existing_output(self):
        os.makedirs(self.out("d"))
        self.assertEqual(dbscan_p2.main(["--params", self.params, "--out", self.out("d"), self.run_dir]), 2)

    def test_fails_on_malformed_line(self):
        with open(os.path.join(self.run_dir, "eve.json"), "a") as fh:
            fh.write("{not json\n")
        self.assertEqual(dbscan_p2.main(["--params", self.params, "--out", self.out("e"), self.run_dir]), 2)

    def test_fails_without_flow_events(self):
        d = os.path.join(self.tmp, "noflow"); os.makedirs(d)
        write(os.path.join(d, "eve.json"), json.dumps({"event_type": "alert"}) + "\n")
        self.assertEqual(dbscan_p2.main(["--params", self.params, "--out", self.out("f"), d]), 2)

    def test_alert_fields_do_not_change_the_result(self):
        """Leakage check: changing SID / alert content must not change the clustering."""
        a = dbscan_p2.run(dbscan_p2.argparse.Namespace(params=self.params, out=self.out("g"), labels=None, run_dirs=[self.run_dir]))
        d = os.path.join(self.tmp, "run2"); os.makedirs(d)
        changed = [l.replace('"signature_id": 9999', '"signature_id": %d' % (2000000 + i)) for i, l in enumerate(self.lines)]
        write(os.path.join(d, "eve.json"), "\n".join(changed) + "\n")
        b = dbscan_p2.run(dbscan_p2.argparse.Namespace(params=self.params, out=self.out("h"), labels=None, run_dirs=[d]))
        self.assertNotEqual(a["inputs"][0]["sha256"], b["inputs"][0]["sha256"])
        for k in ("n_clusters", "n_noise", "stability_ari", "k_distance_percentiles"):
            self.assertEqual(a[k], b[k])


if __name__ == "__main__":
    unittest.main()
