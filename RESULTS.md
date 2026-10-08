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
- **Bulky raw EVE (`eve.json`, `*_raw.txt`):** retained locally, not committed (size) — see `.gitignore`.

> Historical pre-Article-2 results used a different methodology and are superseded; see git history and the note in `README.md`.
