# Decisions: agents

## Purpose
Defines AI agent implementations (worker, attacker, self-healer) and system prompts for evaluation and interaction. These agents represent benign users, adversaries, and recovery mechanisms in the evaluation harness.

## Planned contents
- `__init__.py`: Package initialization for agent modules.
- `worker.py`: Standard task execution agent fulfilling user queries via MCP tool calls.
- `attacker.py`: Adversarial agent attempting prompt injections and security policy bypasses.
- `healer.py`: Self-healing agent attempting to safely rewrite blocked or failed queries.
- `prompts/worker.md`: Prompt template for worker agent.
- `prompts/attacker.md`: Prompt template for adversarial attacker agent.
- `prompts/healer.md`: Prompt template for self-healing agent.
- `prompts/judge.md`: Prompt template for Layer 4 LLM judge.

## Constraints
- The self-healer must re-enter the full firewall pipeline and never call downstream directly.
- Fix temperature at 0 for all agent and judge LLM invocations.
- No direct database access; all actions must occur through MCP tool calls.

## Decision log
| Date | Decision | Alternatives considered | Reason | Status |
|------|----------|-------------------------|--------|--------|
|      |          |                         |        |        |

## Open questions
- (none yet)
