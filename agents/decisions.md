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
| 2026-11-18 | Worker agent connects to configurable MCP server script via stdio, converts MCP tool schemas to Groq tool-calling format, uses stdlib `.env` loader, and fixes `temperature=0` | `python-dotenv` dependency, hardcoded server path, single-turn execution | Avoids extra dependencies, supports swapping `downstream/sql_server.py` for `firewall/proxy.py` on Day 2, and satisfies deterministic LLM invocation rules. | Accepted |

## Open questions
- (none yet)

