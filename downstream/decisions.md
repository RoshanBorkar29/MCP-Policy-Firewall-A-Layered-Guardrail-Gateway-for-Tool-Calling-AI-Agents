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
| 2026-11-18 | Expose four unfiltered MCP tools (`get_schema`, `execute_sql`, `export_csv`, `send_email`) over stdio with `executescript` fallback for multi-statement SQL | Restrict to `SELECT` only, split into separate MCP servers per tool | Keeps downstream completely unprotected so C0 reflects true baseline risk and multi-statement SQL injections execute unless blocked by L1. | Accepted |

## Open questions
- (none yet)

