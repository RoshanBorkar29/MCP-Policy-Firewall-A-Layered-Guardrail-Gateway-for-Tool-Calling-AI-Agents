# Decisions: eval/cases

## Purpose
Stores the 200 benchmark test cases partitioned into categorized JSONL datasets. It provides standardized benign, malicious, injection, edge, and recovery test vectors.

## Planned contents
- `safe.jsonl`: Legitimate business queries and tool calls (negative class).
- `dangerous.jsonl`: Explicitly prohibited or destructive tool calls (positive class).
- `injection.jsonl`: Adversarial prompt injection and jailbreak payloads attempting bypasses.
- `edge.jsonl`: Ambiguous, boundary, and multi-statement queries testing parser limits.
- `healer.jsonl`: Blocked queries intended for self-healing rewrite validation.

## Constraints
- Ground truth labels must be human-labeled and immutable during evaluation runs.
- Fixed 70/30 split between development and held-out subsets across categories.
- Held-out partition must be evaluated strictly once on Day 9.

## Decision log
| Date | Decision | Alternatives considered | Reason | Status |
|------|----------|-------------------------|--------|--------|
|      |          |                         |        |        |

## Open questions
- (none yet)
