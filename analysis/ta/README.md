# T-A evaluator (engine_drops mechanism test, arm D0I)

`ta_evaluator.py` evaluates, read-only, the T-A criteria of a Suricata IDS series (capture geometry and zero-copy, per-RX drops, residual) and gives a series verdict: DEMONSTRATED / REFUTED / NOT_MET / NOT_EVALUABLE. It is fail-safe: any missing, invalid or contradictory evidence gives NOT_EVALUABLE.

- **Criteria**: `ta_criteria.D0I.APPROVED.json` (M-6 FINAL, signed by the project owner on 2026-10-25; see `docs/decisions/M6_TA_criteria_FINAL.SIGNED.md`). The earlier `ta_criteria.D0I.APPROVED_PARTIAL.json` (2026-10-24) and `ta_criteria.D0I.PROPOSED.json` are kept unchanged for traceability. With any status other than `APPROVED`, every verdict is **provisional** (exit code 5).
- **r1**: D-B2-2 is applied explicitly (a missing required socket gives NOT_EVALUABLE, never REFUTED).
- **r2 (D-TA-3, option A)**: per-RX drops come from the eve `stats` event emitted in the same second as the final `stats.log` record, i.e. the same snapshot as the Total. The per-RX exit statistics of `suricata.log` corroborate them: same RX threads, equal drops, packets >= snapshot. Anything else gives NOT_EVALUABLE. This principle does not depend on the engine.
- **vendor/**: pinned copies of the stop-criteria evaluator and the APPROVED stop criteria (`VENDOR.sha256`).
- **Tests**: `tests/test_ta_evaluator.py <evaluator_dir> <D0 run copies>/ids/SCN-001 <workdir> <out.json>`. It needs copies of the D0 runs, which are raw experimental data and are **not** versioned. Result on 2026-10-25 (r2): 71/71 PASS.

Usage: `ta_evaluator.py --series <series> --scenario SCN-001 --criteria ta_criteria.D0I.APPROVED.json --emergency-flush disabled|enabled --out <file outside the series>`
