# Decisions: tests

## Purpose
Contains automated pytest unit and integration test suites validating individual layers and pipeline behavior. It provides fast local regression testing for parser rules, sanitization, and routing.

## Planned contents
- `test_l1.py`: Unit tests for Layer 1 SQL AST rule enforcement and syntax parsing.
- `test_l2.py`: Unit tests for Layer 2 PII detection and regex/masking mechanics.
- `test_l3.py`: Unit tests for Layer 3 rate limiting, row limits, and cost budgets.
- `test_pipeline.py`: Integration tests for end-to-end pipeline evaluation and layer short-circuiting.
- `test_oracles.py`: Unit tests verifying accuracy of evaluation oracles and canary checkers.

## Constraints
- Tests must execute deterministically without live external network dependencies.
- Unit tests must not make unmocked external LLM API calls.
- Every function that modifies firewall behavior requires a corresponding test.

## Decision log
| Date | Decision | Alternatives considered | Reason | Status |
|------|----------|-------------------------|--------|--------|
|      |          |                         |        |        |

## Open questions
- (none yet)
