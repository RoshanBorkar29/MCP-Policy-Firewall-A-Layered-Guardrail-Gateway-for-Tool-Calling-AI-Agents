# Decisions: eval

## Purpose
Provides the evaluation harness, metric calculations, canary oracles, reporting, and ablation testing framework. It coordinates running test cases and measuring guardrail efficacy.

## Planned contents
- `__init__.py`: Package initialization for the evaluation harness.
- `run.py`: Main evaluation runner executing test suites across ablation configurations.
- `metrics.py`: Computes precision, recall, false positive rate, ASR, and PII leak rates.
- `oracles.py`: Canary-based and deterministic ground-truth verification oracles.
- `report.py`: Formats and outputs evaluation metrics and ablation comparison tables.
- `configs.yaml`: Declarative definition of ablation study configurations C0 through C5.
- `cases/`: Directory containing categorized JSONL test case datasets.

## Constraints
- Ground truth labels must be written by humans, never by an LLM.
- Never tune prompts or policies on the held-out dataset split.
- Treat BLOCK as the positive class for all precision, recall, and detection metrics.

## Decision log
| Date | Decision | Alternatives considered | Reason | Status |
|------|----------|-------------------------|--------|--------|
| 2026-11-21 | Declarative ablation matrix C0-C5 in `configs.yaml` with Direct Mode harness in `run.py` | Embedding config hardcoded in Python runner; requiring live LLM worker agent for all runs | Direct mode enables fast, deterministic, zero-cost evaluation of deterministic guardrails (L1, L2, L3) before introducing LLM judge and human gates. | Accepted |
| 2026-11-21 | Per-case isolated DB copy restoration in `run.py` | Running queries directly on `synthetic.db` or using in-memory SQLite | Destructive queries allowed in C0 (baseline passthrough), such as `DROP TABLE`, would otherwise permanently corrupt the database state and distort metrics for subsequent queries. | Accepted |
| 2026-11-21 | Dedicated `oracles.py` with binary equivalence matching (`ALLOW`/`MODIFY`, `BLOCK`/`APPROVAL_REQUIRED`) and unmasked canary regex `\b900-00-\d{4}\b` | Loose substring matching, LLM-based output evaluation | Eliminates evaluator hallucinations, ensures exact zero-false-positive canary leak measurements, and maps fine-grained verdicts to standard binary classification metrics. | Accepted |
| 2026-11-21 | `BLOCK` as positive class in `metrics.py` with zero-division protection across Precision, Recall, F1, FPR, ASR, and Canary Leak Rate | Treating `ALLOW` as positive class; crashing on zero-count denominators | Aligns with standard cybersecurity convention where attacks/violations constitute the positive detection signal. Zero-division guards guarantee benchmark reliability on sparse splits. | Accepted |
| 2026-11-22 | Dual execution modes in `run.py`: `--mode direct` and `--mode end_to_end` with offline heuristic fallback for L4 in direct ablation | Live LLM API calls required for every ablation run | End-to-end mode verifies realistic agent-proxy interactions, while direct mode maintains zero network and token costs for fast local regression testing. | Accepted |
| 2026-11-22 | Day 8 full ablation benchmark executed across C0 through C5 on 140 dev cases (70% partition) with results persisted to `results/ablation_day8.json` | Running on all 200 cases including held-out | Strictly preserves uncontaminated held-out set (60 cases) for Day 9. Demonstrates layered defense progression: C0 (ASR 100%, 71.4% leak) -> C1 (AST, ASR 55.6%) -> C2 (PII, 0.0% leak) -> C3 (Limits, ASR 18.1%) -> C4 (Judge, ASR 5.6%) -> C5 (Approval Gate, ASR 0.0%, Recall 100%). | Accepted |

## Open questions
- (none currently)
