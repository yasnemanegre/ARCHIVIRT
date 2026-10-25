# T-A evaluator (engine_drops mechanism test, arm D0I)

`ta_evaluator.py` evaluates, read-only, the T-A criteria of a Suricata IDS series (capture geometry and zero-copy, per-RX drops, residual) and gives a series verdict: DEMONSTRATED / REFUTED / NOT_MET / NOT_EVALUABLE. It is fail-safe: any missing, invalid or contradictory evidence gives NOT_EVALUABLE.

- **Criteria**: `ta_criteria.D0I.APPROVED_PARTIAL.json` (M-6, partial approval signed by the project owner on 2026-10-24; see `docs/decisions/M6_TA_criteria.SIGNED.md`). TA-b1/b2 (per-RX drop source, D-TA-3) stay deferred until V-1. As long as the status is not `APPROVED`, every verdict is **provisional** (exit code 5). `ta_criteria.D0I.PROPOSED.json` is kept unchanged as the source.
- **r1**: D-B2-2 is applied explicitly (a missing required socket gives NOT_EVALUABLE, never REFUTED). No verdict changes compared with the previous evaluator.
- **vendor/**: pinned copies of the stop-criteria evaluator and the APPROVED stop criteria (`VENDOR.sha256`).
- **Tests**: `tests/test_ta_evaluator.py <evaluator_dir> <D0 run copies>/ids/SCN-001 <workdir> <out.json>`. It needs copies of the D0 runs, which are raw experimental data and are **not** versioned. Result on 2026-10-24: 64/64 PASS.

Usage: `ta_evaluator.py --series <series> --scenario SCN-001 --criteria ta_criteria.D0I.APPROVED_PARTIAL.json --emergency-flush disabled|enabled --out <file outside the series>`
