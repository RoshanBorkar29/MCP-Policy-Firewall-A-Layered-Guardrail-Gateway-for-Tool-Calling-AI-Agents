"""Layer 1 guardrail enforcing SQL AST structural rules, prohibited statements, and syntax checks.
Inputs: SQL query strings and policy AST rules. Outputs: Pass or BLOCK decision with violation reason.
Build plan: Day 2.
"""

from __future__ import annotations

import time
from typing import Any
import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from firewall.context import FirewallDecision, Verdict

# Expressions permitted at the root level of a query
ALLOWED_ROOT_TYPES = (
    exp.Select,
    exp.Union,
)

# Statement types explicitly prohibited anywhere in the AST
PROHIBITED_NODE_TYPES = (
    exp.Drop,
    exp.Delete,
    exp.Update,
    exp.Insert,
    exp.Alter,
    exp.Create,
    exp.Command,
    exp.Pragma,
    exp.Attach,
    exp.TruncateTable if hasattr(exp, "TruncateTable") else exp.Expression,
)


def check_sql(query: str | Any) -> FirewallDecision:
    """Inspects a SQL query using sqlglot AST parsing to enforce safety rules.

    Enforces:
    1. Valid non-empty query string.
    2. Successful syntax parsing for the SQLite dialect.
    3. Exactly one statement (blocks multi-statement chaining injections).
    4. Only read-only operations (SELECT, UNION, CTEs).
    5. No prohibited statements (DROP, DELETE, UPDATE, ALTER, INSERT, PRAGMA, ATTACH).

    Args:
        query: SQL string to validate.

    Returns:
        FirewallDecision with ALLOW or BLOCK.
    """
    t0 = time.perf_counter()

    if not isinstance(query, str) or not query.strip():
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return FirewallDecision(
            verdict=Verdict.BLOCK,
            reason="Empty or non-string query provided.",
            layer="L1",
            latency_ms=elapsed_ms,
        )

    # 1. Parse AST
    try:
        statements = sqlglot.parse(query, read="sqlite")
    except (ParseError, TokenError) as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return FirewallDecision(
            verdict=Verdict.BLOCK,
            reason=f"Malformed SQL syntax: {exc}",
            layer="L1",
            latency_ms=elapsed_ms,
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return FirewallDecision(
            verdict=Verdict.BLOCK,
            reason=f"Failed to parse SQL AST: {exc}",
            layer="L1",
            latency_ms=elapsed_ms,
        )

    # Filter out empty None entries (e.g., trailing semicolons or comment blocks)
    valid_stmts = [s for s in statements if s is not None]

    if not valid_stmts:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return FirewallDecision(
            verdict=Verdict.BLOCK,
            reason="No executable SQL statement found in query.",
            layer="L1",
            latency_ms=elapsed_ms,
        )

    # 2. Multi-statement check
    if len(valid_stmts) > 1:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return FirewallDecision(
            verdict=Verdict.BLOCK,
            reason=(
                f"Multi-statement execution prohibited: detected {len(valid_stmts)} statements."
            ),
            layer="L1",
            latency_ms=elapsed_ms,
        )

    root_stmt = valid_stmts[0]

    # 3. Root statement type check
    if not isinstance(root_stmt, ALLOWED_ROOT_TYPES):
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        stmt_type = type(root_stmt).__name__.upper()
        return FirewallDecision(
            verdict=Verdict.BLOCK,
            reason=f"Prohibited SQL statement type: {stmt_type}. Only SELECT queries are permitted.",
            layer="L1",
            latency_ms=elapsed_ms,
        )

    # 4. AST traversal to catch nested prohibited nodes
    for node in root_stmt.walk():
        for prohibited_type in PROHIBITED_NODE_TYPES:
            if isinstance(node, prohibited_type):
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                node_type = type(node).__name__.upper()
                return FirewallDecision(
                    verdict=Verdict.BLOCK,
                    reason=f"Prohibited SQL operation '{node_type}' detected within query tree.",
                    layer="L1",
                    latency_ms=elapsed_ms,
                )

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return FirewallDecision(
        verdict=Verdict.ALLOW,
        reason="Query passed SQL AST rules inspection.",
        layer="L1",
        latency_ms=elapsed_ms,
    )
