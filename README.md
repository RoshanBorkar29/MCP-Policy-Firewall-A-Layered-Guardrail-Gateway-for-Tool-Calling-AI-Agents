# MCP Policy Firewall: A Layered Guardrail Gateway for Tool-Calling AI Agents

A drop-in proxy for MCP tool servers that intercepts every agent tool call and decides whether to allow, modify, or block it. Five guardrail layers (AST rules, PII masking, rate limits, LLM judge, approval gate) are evaluated by a 200-case harness with canary-based oracles. A multi-agent setup (worker, judge, attacker, self-healer) measures block rate, false positives, PII leaks, and attack success rate per layer.

## Architecture
TODO: Document system architecture, proxy intercept mechanics, and five-layer evaluation pipeline.

## Quickstart
TODO: Provide setup instructions, environment variable configuration, and step-by-step proxy launch command.

## Guardrail Layers
TODO: Detail individual layers (L1 SQL AST, L2 PII masking, L3 rate/budget limits, L4 LLM judge, L5 human approval).

## Evaluation
TODO: Explain the 200-case evaluation harness, test case categorization, and canary-based oracle verification.

## Ablation Results
TODO: Present comparison tables across ablation configurations C0 through C5.

## Known Bypasses
TODO: Document discovered bypass vectors, root cause analyses, and mitigation strategies.

## Limitations
TODO: Outline current operational constraints, throughput ceilings, and edge-case limitations.
