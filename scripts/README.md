# scripts/

## campaign_v1/ — Article 2 orchestrator, processors, analysis
- `campaign_v1.sh` — orchestrator: engine dispatch (`ENGINE`), offline readiness gate, provenance, perf snapshots, per-run collection.
- `validate_run.py` — per-run validation + ground-truth TP/FP/FN/TN classification, latency from real timestamps.
- `summarize.py` — campaign summary (keeps INVALID / PREREQUISITE_MISSING).
- `compute_perf.py` — Suricata CPU/RSS + capture throughput/drops per run.
- `offline_audit.sh` / `offline_audit.py` — offline readiness (READY/MISSING/VERSION_MISMATCH/OFFLINE_ARTIFACT_MISSING/NOT_REQUIRED).
- `analyze.py` — metrics, confusion matrix, statistics, tables.
- `figures.py` — figures (matplotlib).
- `synthesize.py` — scientific synthesis. `scientific_audit.py` — audit answers.
- `make_publication_tables.py` — publication-source tables A–K.

Other scripts in this directory belong to the legacy pipeline and are out of scope for the Article-2 freeze.
