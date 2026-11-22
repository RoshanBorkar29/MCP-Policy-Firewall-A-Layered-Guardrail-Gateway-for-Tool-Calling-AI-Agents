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
| 2026-11-22 | Expanded test vectors across `injection.jsonl`, `dangerous.jsonl`, `safe.jsonl`, and `edge.jsonl` with prompt injections, exfiltration attempts, and 70/30 dev/held-out split tagging | Single monolithic test file without split labels | Provides standardized evaluation vectors testing multi-turn evasion tactics and reserves an uncontaminated held-out test split for Day 9 validation. | Accepted |
| 2026-11-22 | Assembled 8 self-healing test vectors in `healer.jsonl` covering missing LIMITs, oversized row caps, CTE outer limits, and unhealable destructive/injection queries | Only testing safe queries that can be healed | Benchmarks must verify both sides of remediation: successfully repairing benign policy breaches and adamantly refusing to heal destructive or malicious payloads. | Accepted |
| 2026-11-22 | Expanded benchmark dataset to exactly 200 cases with 70/30 split (140 dev, 60 held-out) across `safe.jsonl` (60), `dangerous.jsonl` (50), `injection.jsonl` (40), `edge.jsonl` (30), and `healer.jsonl` (20) | Generating synthetic cases dynamically at test time; imbalanced splits | Standardizes full 200-vector benchmark suite with strict human-labeled ground truth, ensuring held-out split (60 cases) is locked until Day 9 single-run validation. | Accepted |

## Open questions
- (none currently)
