# Decisions: downstream

## Purpose
Hosts the downstream mock tool servers providing SQL database operations, CSV export, and simulated email transmission. It serves as the target execution environment intercepted by the firewall proxy.

## Planned contents
- `__init__.py`: Package initialization for downstream server modules.
- `sql_server.py`: FastMCP server exposing SQLite database execution, export, and email tools.

## Constraints
- Downstream servers must not enforce firewall policies or perform security filtering.
- Downstream tools must accept all valid MCP invocations directly without policy checks.
- Execution state mutations must remain local to the synthetic test database.

## Decision log
| Date | Decision | Alternatives considered | Reason | Status |
|------|----------|-------------------------|--------|--------|
|      |          |                         |        |        |

## Open questions
- (none yet)
