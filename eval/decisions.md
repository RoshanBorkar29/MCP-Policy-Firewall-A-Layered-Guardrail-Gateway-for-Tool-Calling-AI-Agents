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
|      |          |                         |        |        |

## Open questions
- (none yet)
