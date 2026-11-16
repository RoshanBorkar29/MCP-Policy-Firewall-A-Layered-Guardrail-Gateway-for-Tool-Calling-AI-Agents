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
|      |          |                         |        |        |

## Open questions
- (none yet)
