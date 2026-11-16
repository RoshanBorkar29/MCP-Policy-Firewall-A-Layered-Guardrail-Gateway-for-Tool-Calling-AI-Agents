# Architecture Decisions: MCP Policy Firewall

This document records project-wide architectural decisions, rationale, alternatives considered, and adoption status.

## Decision log

| Date | Decision | Alternatives considered | Reason | Status |
|------|----------|-------------------------|--------|--------|
| 2026-11-16 | Python + FastMCP for both downstream and proxy servers | Low-level MCP SDK, TypeScript MCP SDK, raw HTTP/SSE JSON-RPC | FastMCP provides clean decorator-based tool definitions, robust stdio/SSE protocol handling, and seamless proxy forwarding in Python 3.11+. | Accepted |
| 2026-11-16 | sqlglot AST parsing over regex for SQL rules | Regular expressions, sqlparse, sqlite3 explain query plan | Regex is fragile against obfuscation, dialect differences, and comments; sqlglot provides full AST inspection, dialect transpilation, and reliable statement/clause isolation. | Accepted |
| 2026-11-16 | Policy lives in `firewall/policy.yaml`, never hardcoded | Python constants, environment variables, SQLite database | Declarative YAML configuration decouples security policies from engine code, enabling dynamic reload and transparent policy auditing without code modification. | Accepted |
| 2026-11-16 | Layers are toggleable via config to enable ablation studies | Monolithic pipeline, hardcoded boolean flags, separate proxy branches | Configurable layer toggling enables empirical ablation experiments (C0 through C5) to isolate the precision, recall, and latency contribution of each guardrail. | Accepted |
| 2026-11-16 | Two eval modes: direct-call (no LLM) and end-to-end (LLM) | End-to-end only, direct-call only | Direct-call enables fast, deterministic, cost-free regression testing of firewall layers; end-to-end verifies realistic multi-turn agent interactions and adversarial resilience. | Accepted |
| 2026-11-16 | Canary PII values (SSNs `900-00-xxxx`) for exact leak measurement | Synthetic generic SSNs, pattern-only regex checking, fuzzy text matching | Known canary SSN prefixes (`900-00-xxxx`) never collide with real US SSNs and enable exact, binary string-matching oracles to detect PII leakage without false positives. | Accepted |
| 2026-11-16 | Ground truth labels are written by a human, never by an LLM | LLM-as-a-judge labeling, heuristic regex labeling, hybrid labeling | Eliminates LLM evaluator bias, circular reasoning, and hallucinated security verdicts; guarantees gold-standard benchmarks for evaluation. | Accepted |
| 2026-11-16 | Dev/held-out split 70/30, held-out run only once | 50/50 split, k-fold cross-validation, continuous held-out testing | 70% dev set allows iterative rule tuning and prompt refinement; running the 30% held-out set strictly once prevents overfitting and benchmark data contamination. | Accepted |
| 2026-11-16 | The self-healer must re-enter the full firewall pipeline and never bypass it | Direct downstream execution on rewrite, bypass flag, relaxed layer subset | Defense-in-depth requires every generated tool call to be verified; allowing bypass would create a catastrophic privilege escalation vulnerability. | Accepted |
| 2026-11-16 | BLOCK is the positive class for metrics | ALLOW as positive class, multi-class confusion matrix only | The primary security objective is detecting and stopping malicious/unsafe tool calls; treating BLOCK as positive aligns standard True Positive, Precision, and Recall definitions with threat detection. | Accepted |
| 2026-11-16 | Groq API (`groq` SDK) for LLM agents and Layer 4 judge | Anthropic Claude API, OpenAI API, local Ollama | High-speed inference and low latency critical for real-time proxy interception overhead; cost-efficient model execution for eval runs. | Accepted |

## Open questions
- (none yet)

