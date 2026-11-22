# Decisions: tests

## Purpose
Contains automated pytest unit and integration test suites validating individual layers and pipeline behavior. It provides fast local regression testing for parser rules, sanitization, and routing.

## Planned contents
- `test_l1.py`: Unit tests for Layer 1 SQL AST rule enforcement and syntax parsing.
- `test_l2.py`: Unit tests for Layer 2 PII detection and regex/masking mechanics.
- `test_l3.py`: Unit tests for Layer 3 rate limiting, row limits, and cost budgets.
- `test_pipeline.py`: Integration tests for end-to-end pipeline evaluation and layer short-circuiting.
- `test_oracles.py`: Unit tests verifying accuracy of evaluation oracles and canary checkers.
- `test_l4.py`: Unit tests for Layer 4 LLM semantic judge and prompt injection detection.
- `test_l5.py`: Unit tests for Layer 5 human approval gate, high-risk detection, and CLI prompt simulation.
- `test_attacker.py`: Unit tests for adversarial attacker agent schema conversions, multi-turn loops, and fail-safe behavior.
- `test_healer.py`: Unit tests for self-healing agent remediation, limit adjustment, unhealable refusals, and mandatory pipeline re-entry.

## Constraints
- Tests must execute deterministically without live external network dependencies.
- Unit tests must not make unmocked external LLM API calls.
- Every function that modifies firewall behavior requires a corresponding test.

## Decision log
| Date | Decision | Alternatives considered | Reason | Status |
|------|----------|-------------------------|--------|--------|
| 2026-11-19 | Automated 34 unit test suite across test_l1.py and test_pipeline.py with conftest.py sys.path bootstrap | Manual script runs, mocking entire database instead of testing against synthetic DB | Ensures deterministic verification of all AST parsing branches, layer toggles, and audit events without external network dependencies. | Accepted |
| 2026-11-21 | 27 unit tests across test_l2.py and test_l3.py covering PII regex patterns, JSON schema preservation, canary prioritization, AST row caps, rate limiting, and budget caps | Relying solely on end-to-end evaluation harness, mocking database returns | Fast, deterministic isolation of Layer 2 and Layer 3 guardrails verifying boundary conditions and reset semantics without external dependencies. | Accepted |
| 2026-11-21 | 18 unit tests in `test_oracles.py` covering canary leak detection, decision oracle equivalence, DB mutation detection, metrics calculation edge cases, report formatting, and direct evaluation execution | Manual inspection of eval logs | Provides regression protection for evaluation infrastructure so metrics calculations and oracles remain provably accurate and stable. | Accepted |
| 2026-11-22 | 22 unit tests across `test_l4.py` and `test_l5.py` with mocked Groq client completions and simulated operator inputs | Calling live Groq LLM endpoint during test suite | Ensures zero network latency, zero token cost, and reproducible deterministic assertion of semantic risk scoring and approval gate states. | Accepted |
| 2026-11-22 | 7 synchronous unit tests in `test_attacker.py` covering tool schema conversion, text extraction, single-turn termination, multi-turn tool execution, turn caps, and fail-safe API handling | Async tests with live stdio socket subprocesses | Eliminates Windows IOCP socket loopback permission issues in sandboxed environments while fully validating the attacker agent's decision logic and trace recording. | Accepted |
| 2026-11-22 | 10 unit tests in `test_healer.py` covering prompt loading, limit healing, row cap clamping, refusal of destructive operations, and mandatory pipeline re-entry enforcement | Testing healer in isolation without pipeline | Specifically validates the architectural invariant that rewritten queries must re-enter and satisfy the firewall pipeline, protecting against faulty or adversarial rewriters. | Accepted |

## Open questions
- (none yet)
