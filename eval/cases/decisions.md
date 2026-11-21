# Decisions: eval/cases

## Purpose
Stores benchmark test cases partitioned into categorized JSONL datasets. It provides standardized benign, malicious, injection, edge, and recovery test vectors.

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
| 2026-11-21 | Seeded initial categorized test vectors across `safe.jsonl`, `dangerous.jsonl`, `edge.jsonl`, `injection.jsonl`, and `healer.jsonl` with human-labeled ground truth | Synthesizing cases via LLM prompt generation | Ensures 100% human-verified ground truth free from model hallucinations and bias. Provides direct mode test cases for Day 4 validation. | Accepted |
| 2026-11-21 | Explicit root `LIMIT` clause on outer CTE queries in `edge.jsonl` | Allowing root query without limit if CTE has limit | Adheres strictly to Layer 3 AST requirements where root statements must explicitly declare row limits unless scalar aggregation is proven. | Accepted |

## Open questions
- (none currently)
