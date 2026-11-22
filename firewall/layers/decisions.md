# Decisions: firewall/layers

## Purpose
Contains individual guardrail layer implementations (L1 through L5) for tool call inspection, transformation, and policy enforcement. Each layer provides a distinct defense mechanism within the layered security architecture.

## Planned contents
- `__init__.py`: Package initialization for firewall layer modules.
- `l1_sql_rules.py`: Layer 1 SQL AST rule engine using sqlglot for syntax and statement validation.
- `l2_pii.py`: Layer 2 PII masking engine scanning outputs and query parameters for sensitive data.
- `l3_limits.py`: Layer 3 token, rate, and cost budget enforcement limiter.
- `l4_judge.py`: Layer 4 LLM-as-a-judge evaluator inspecting semantic intent and subtle abuse.
- `l5_approval.py`: Layer 5 human-in-the-loop approval gate for high-risk or irreversible operations.

## Constraints
- Layers must be independently toggleable to support ablation configurations (C0 to C5).
- Lower layers (L1 through L3) must be deterministic and never make LLM calls.
- Automated layers (L1 through L4) must never prompt humans or block on external UI input.

## Decision log
| Date | Decision | Alternatives considered | Reason | Status |
|------|----------|-------------------------|--------|--------|
| 2026-11-19 | sqlglot SQLite AST inspection enforcing single-statement SELECT/UNION and rejecting DDL/DML/PRAGMA/ATTACH nodes anywhere in AST walk | Regex keyword filtering, sqlparse token stream scanning, EXPLAIN QUERY PLAN SQLite execution | AST parsing is immune to comment evasion, whitespace obfuscation, and dialect quirks; tree-walking detects nested destructive operations inside subqueries. | Accepted |
| 2026-11-21 | Recursive JSON-aware PII scanner prioritizing canary SSN redactions (`[REDACTED_CANARY_SSN]`) before standard SSN/email/phone regex with policy-driven rules | Pure regex across raw JSON text, external Presidio/Spacy NER packages | Regex on raw JSON risks corrupting JSON syntax (e.g. quotes/escapes); heavy NLP libraries add large dependencies violating CLAUDE.md; recursive structure traversal preserves schema integrity. | Accepted |
| 2026-11-21 | Layer 3 triple-barrier protection: AST-based SQL row caps (mandatory LIMIT <= 50), sliding-window rate limiter, and cumulative session token/cost budget tracker | Post-execution row truncation, fixed-interval rate limiting, static global query quotas | AST-level row cap prevents downstream server memory exhaustion from huge dumps before query runs; sliding window prevents burst flooding; session budget caps total financial exposure. | Accepted |
| 2026-11-22 | Layer 4 structured JSON LLM Judge with rank-based thresholding (LOW/MEDIUM/HIGH/CRITICAL) and fail-safe blocking on API failure | Free-form text judge evaluation, regex classification | Structured JSON output guarantees parseable verdicts; rank-based comparison enforces strict policy thresholding; fail-safe BLOCK protects against API dropouts. | Accepted |
| 2026-11-22 | Layer 5 Human Approval Gate for high-risk tools (`export_csv`, `send_email`) with `APPROVAL_REQUIRED` verdict and pluggable handler callbacks | Hardcoding approval prompts inside proxy, auto-approving based on session count | High-risk tools interfacing with the filesystem or outside network require explicit operator consent; pluggable callbacks allow both interactive CLI prompts and automated mock simulations. | Accepted |

## Open questions
- (none currently)
