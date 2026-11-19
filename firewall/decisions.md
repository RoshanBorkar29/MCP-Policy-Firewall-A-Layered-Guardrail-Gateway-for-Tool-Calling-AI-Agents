# Decisions: firewall

## Purpose
Implements the core MCP proxy gateway, orchestration pipeline, request context, and structured audit logging. It acts as the central security mediator between client agents and downstream tool servers.

## Planned contents
- `__init__.py`: Package initialization for the firewall core.
- `proxy.py`: FastMCP proxy server intercepting client tool calls and forwarding decisions.
- `pipeline.py`: Sequential guardrail pipeline evaluating incoming requests across layers L1 to L5.
- `audit.py`: Structured JSONL audit logger recording every tool invocation and firewall decision.
- `context.py`: Request context and state tracking passing metadata between layers.
- `policy.yaml`: Declarative policy configuration defining rules, thresholds, and limits.

## Constraints
- Never hardcode policy values or thresholds; read them from `policy.yaml`.
- All tool calls must pass through configured pipeline layers without bypass paths.
- Audit logging must be non-blocking and fail-safe.

## Decision log
| Date | Decision | Alternatives considered | Reason | Status |
|------|----------|-------------------------|--------|--------|
| 2026-11-19 | In-process downstream execution with RequestContext metadata propagation and fail-safe JSONL audit logging | Subprocess stdio proxying to downstream, synchronous HTTP calls | In-process execution prevents Windows stdio subprocess deadlocks, ensures sub-millisecond proxy routing, and simplifies unit/integration testing while maintaining strict layer isolation. | Accepted |

## Open questions
- (none yet)

