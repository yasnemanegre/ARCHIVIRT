# campaign_v1 — ARCHIVIRT experimental engine (Article 2)

Single source of truth for the Article-2 IDS/IPS evaluation. Independent of the
legacy `archivirt-reset.sh` pipeline.

## Layout
- `engines/suricata.sh` — Suricata IDS (af-packet ens6/ens7) / IPS (inline NFQUEUE). Loads the Article-2 ruleset exclusively (`-S`).
- `engines/snort3.sh` — common-interface Snort 3 engine; offline-gated, refuses with `SNORT3_NOT_READY_OFFLINE` until genuinely provisioned (never downloads).
- `engines/stop.sh` — graceful stop (SIGTERM flush) targeting only the campaign instance.
- `scenarios/SCN-001..005.sh` — attack scenarios + benign control; emit machine-readable markers (`ARCHIVIRT_ATTACK_START/END`, `ARCHIVIRT_PREREQUISITE_MISSING`).
- `rules/archivirt-article2-{ids,ips}.rules` — 4 discriminative threshold signatures (ground-truth mapping scenario→SID).
- `manifest/offline_manifest.json` — offline artifact set declaration.
- `schema/result.json` — canonical per-run result schema.
- `preflight.sh` — per-scenario prerequisite report (installs nothing).

Orchestrator & processors live in `scripts/campaign_v1/` (see `scripts/README.md`).

## Run
```bash
bash campaign_v1/preflight.sh
MODE=ids RUNS=1 SCENARIOS_LIST="SCN-001" bash scripts/campaign_v1/campaign_v1.sh
```
`MODE=ids|ips|baseline`, `ENGINE=suricata-6.0.4|snort3`, `ENFORCE_OFFLINE=1` (default; aborts on missing local artifact, never downloads).

## Ground truth & validation
Attack scenarios (SCN-001..004) must fire their expected SID → TP, else FN.
Benign SCN-005 → TN if no attack SID fires, else FP. A run is VALID only with real
attack + real EVE (+ expected detection for attacks). INVALID/PREREQUISITE_MISSING
runs are kept and excluded from VALID statistics.
