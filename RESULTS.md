# ARCHIVIRT — Article 2 Experimental Results

> **Results characterize the tested ARCHIVIRT configuration and controlled Article-2 signature set; they are not a universal benchmark of Suricata.**
> All statements hold *in the experimental conditions considered*.

- **Campaign date (UTC):** 2026-10-08
- **Engine:** Suricata 6.0.4 (IDS: af-packet ens6/ens7 · IPS: inline NFQUEUE queue 0)
- **Methodology:** `campaign_v1` — ground-truth mapping scenario → expected signature; run-level confusion matrix; real timestamps; no fabricated metric.
- **Signature set:** 4 discriminative threshold signatures (SID 2000001–2000004 / IPS 2100001–2100004) + 1 benign negative control.

## Campaigns & run accounting

| Campaign | Mode | Runs/scn | Runs | VALID | INVALID | PREREQ_MISSING | Raw dir |
|---|---|---|---|---|---|---|---|
| ARTICLE-20261008T163655Z | IDS | 10 | 50 | 50 | 0 | 0 | `results/campaign-v1/ARTICLE-20261008T163655Z/` |
| ARTICLE-20261008T165841Z | IPS | 10 | 50 | 50 | 0 | 0 | `results/campaign-v1/ARTICLE-20261008T165841Z/` |
| ARTICLE-20261008T165327Z | baseline | 3 | 15 | 0 | 15* | 0 | `results/campaign-v1/ARTICLE-20261008T165327Z/` |

*Baseline is INVALID **by design** (no engine → no EVE); its system/traffic measurements are aggregated separately and it is **excluded** from detection statistics.

## Scenarios

| Scenario | Ground truth | Description | Expected SID (IDS) |
|---|---|---|---|
| SCN-001 | attack | Nmap SYN scan | 2000001 |
| SCN-002 | attack | SSH connection-rate attack pattern † | 2000002 |
| SCN-003 | attack | SQLMap (tool User-Agent) | 2000003 |
| SCN-004 | attack | Slowloris HTTP DoS | 2000004 |
| SCN-005 | benign | Benign HTTP (negative control) | — |

† The SSH target enforces public-key-only authentication; hydra cannot perform password guessing, so SCN-002 measures an **SSH connection-rate attack pattern**, not a successful brute-force.

## IDS — detection metrics (run-level confusion, VALID runs)

TP=40 · TN=10 · FP=0 · FN=0 → **Accuracy=1.0 · Precision=1.0 · Recall=1.0 · F1=1.0 · FPR=0 · FNR=0** *(for this signature set)*.

## IPS — detection + blocking

TP=40 · TN=10 · FP=0 · FN=0 (same derived metrics). Real `action:blocked`/`drop` events observed.
Blocking rate: **100 % of attack runs** (SCN-001..004: 10/10 each), **0 %** of benign runs (SCN-005: 0/10 → no false blocking).

## Detection latency (ms, n=10 per scenario; real timestamps, excl. SSH/sync/collection/post-processing)

| Scenario | IDS mean | IDS SD | IDS CI95 | IPS mean | IPS SD | IPS CI95 |
|---|---|---|---|---|---|---|
| SCN-001 | 105.7 | 4.86 | [102.2, 109.2] | 105.2 | 4.85 | [101.7, 108.7] |
| SCN-002 | 175.5 | 19.39 | [161.6, 189.4] | 217.4 | 25.16 | [199.4, 235.4] |
| SCN-003 | 310.6 | 10.90 | [302.8, 318.4] | 309.2 | 11.35 | [301.1, 317.3] |
| SCN-004 | 114.7 | 10.31 | [107.3, 122.1] | 164.3 | 16.76 | [152.3, 176.3] |

For IPS, blocking latency equals the first blocked-event latency (inline), numerically equal to the detection latency above.

## Performance / resource impact (engine process; means over scenarios)

| Metric | Baseline | IDS | IPS |
|---|---|---|---|
| CPU % (engine) | NOT_APPLICABLE (no engine) | ≈13.2 | ≈14.5 |
| RSS MB (engine) | NOT_APPLICABLE (no engine) | ≈50.1 | ≈44.3 |
| Captured throughput (ens6/7) | 0.327 Mbps / 559 pps | 0.327 Mbps / 560 pps | NOT_APPLICABLE (inline path ens4/ens5 not mirrored) |
| Capture drops | 0 | 0 | NOT_APPLICABLE |

CPU/RAM are not comparable to baseline (no engine process exists in baseline). Throughput values reflect the mirror interfaces only.

## Limitations

- Metrics are a property of the **controlled Article-2 signature set**, not of Suricata in general.
- SCN-002 measures a connection-rate pattern (public-key-only target), not password guessing.
- Documented IDS cross-firing between threshold signatures within attack runs (no effect on the confusion matrix; benign control stays clean).
- IPS throughput not measured on the inline path; rockyou present as a short stub; lab currently not air-gapped (offline is Phase 2).

## Provenance & data location

- **Per-campaign provenance:** `results/campaign-v1/ARTICLE-*/provenance.json` (git commit, Suricata/Python/Terraform/Ansible versions, artifact SHA-256).
- **Aggregated metrics & statistics:** `results/campaign-v1/article2/aggregated_metrics.json`, `statistical_summary.json`.
- **Flat per-run dataset:** `results/campaign-v1/article2/article2_results.csv`.
- **Tables:** `results/campaign-v1/article2/tables/` (+ `tables/publication/`). **Figures:** `results/campaign-v1/article2/figures/`.
- **Scientific audit:** `results/campaign-v1/article2/scientific_audit.md`. **Synthesis:** `synthesis.md`.
- **Raw per-run records (committed):** `result.json`, `perf.json`, timestamps, `summary.json` under each `ARTICLE-*/`.
- **Bulky raw evidence (`eve.json`, `*_raw.txt`, `attack.log`, `stats.log`):** retained locally, not committed (size) — see `.gitignore`. 545 files / 532 432 985 bytes across the three official campaigns.
- **Raw evidence checksum manifest (committed):** `results/campaign-v1/article2/RAW_SHA256SUMS` — `sha256sum`-compatible, one line per raw file, paths relative to the repository root. Verify from the repo root with `sha256sum -c --strict results/campaign-v1/article2/RAW_SHA256SUMS`. The manifest file itself has SHA-256 `a36d4be0b4581dc03f3103b040c1eef7dce6cbb11f82b7f2a291d82f5c6f7748`.

## Provenance notes (audit 2026-10-17)

These notes document traceability limits found during the pre-merge audit. No result, aggregate, table or figure was modified.

1. **Recorded commit vs executed code.** The three `provenance.json` files record `git_commit = 1a64170` with `git_dirty = true`: the campaigns ran from a working tree with uncommitted changes, and `1a64170` does not contain `campaign_v1/scenarios/` or `campaign_v1/engines/`. All 10 artifacts hashed in each `provenance.json` (5 scenarios, 3 engine scripts, `configs/suricata/suricata.yaml`, `offline_manifest.json`) match **bit-for-bit** the frozen commit `1132cd9d629a973f1b5a0984b9f9f89fd55fdb06` (30/30 verified). The executed code is therefore identified by `1132cd9`, not by the recorded commit.
2. **Rulesets not hashed in provenance.** `campaign_v1/rules/archivirt-article2-{ids,ips}.rules` were deployed from the repository by `scripts/campaign_v1/campaign_v1.sh` but their SHA-256 was not recorded (only `suricata_rules_archivirt_file=PRESENT`). Their last modification (2026-10-08 16:35:16 UTC) precedes the IDS campaign start (16:36:55 UTC) and they are unchanged in `1132cd9` (SHA-256 `9934ae6a…c0459` IDS, `4782668e…46e19` IPS). This is consistent evidence, not cryptographic proof.
3. **Provenance granularity.** Provenance is recorded per campaign, not per run; per-run directories hold `result.json`, `perf.json`, timestamps and raw logs.
4. **Raw-evidence checksums are post hoc.** `RAW_SHA256SUMS` was computed on 2026-10-17, after capture (file mtimes 2026-10-08 16:37–17:38 UTC). It guarantees integrity from that date onward, not since capture. 115 raw files are empty by design (15 baseline `eve.json`: no engine; 100 `stats.log`: EVE `stats` type not enabled), and `attack.log` is byte-identical to `attack_raw.txt` in every run.
5. **No off-host copy yet.** The raw evidence exists only on the lab host disk.

> Historical pre-Article-2 results used a different methodology and are superseded; see git history and the note in `README.md`.
