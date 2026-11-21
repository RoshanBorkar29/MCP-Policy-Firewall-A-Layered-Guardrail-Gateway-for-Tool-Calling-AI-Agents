"""Layer 3 guardrail enforcing rate limits, result row limits, and cumulative token/cost budgets.
Inputs: Agent identity, session cost metrics, and query specs. Outputs: ALLOW or BLOCK decision.
Build plan: Day 3.
"""

from __future__ import annotations

from collections import defaultdict
import time
from typing import Any
import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

from firewall.context import FirewallDecision, RequestContext, Verdict, load_policy


class RateLimiter:
    """Sliding-window rate limiter per session/agent identity."""

    def __init__(self):
        self._history: dict[str, list[float]] = defaultdict(list)

    def is_allowed(
        self, key: str, max_requests: int, window_seconds: float
    ) -> tuple[bool, int]:
        """Check if request is within sliding window rate limit.

        Returns:
            Tuple of (is_allowed, current_count_in_window).
        """
        now = time.monotonic()
        cutoff = now - window_seconds
        # Evict timestamps outside the window
        timestamps = [ts for ts in self._history[key] if ts > cutoff]
        self._history[key] = timestamps

        if len(timestamps) >= max_requests:
            return False, len(timestamps)

        timestamps.append(now)
        return True, len(timestamps)

    def reset(self) -> None:
        """Reset all rate limiter counters."""
        self._history.clear()


class BudgetTracker:
    """Tracks cumulative token and financial cost usage per session."""

    def __init__(self):
        self._costs: dict[str, float] = defaultdict(float)
        self._tokens: dict[str, int] = defaultdict(int)

    def check_and_charge(
        self,
        session_id: str,
        cost_to_add: float,
        tokens_to_add: int,
        max_cost: float,
        max_tokens: int,
    ) -> tuple[bool, float, int]:
        """Verify if current request exceeds session limits, and charges if permitted.

        Returns:
            Tuple of (is_within_budget, current_total_cost, current_total_tokens).
        """
        current_cost = self._costs[session_id]
        current_tokens = self._tokens[session_id]

        if current_cost + cost_to_add > max_cost:
            return False, current_cost, current_tokens
        if current_tokens + tokens_to_add > max_tokens:
            return False, current_cost, current_tokens

        self._costs[session_id] = current_cost + cost_to_add
        self._tokens[session_id] = current_tokens + tokens_to_add
        return True, self._costs[session_id], self._tokens[session_id]

    def reset(self) -> None:
        """Reset all budget counters."""
        self._costs.clear()
        self._tokens.clear()


# Singletons tracking runtime limits across proxy requests
rate_limiter = RateLimiter()
budget_tracker = BudgetTracker()


def reset_limits() -> None:
    """Resets rate limiting and budget tracking states (useful for tests and eval runs)."""
    rate_limiter.reset()
    budget_tracker.reset()


def _check_sql_row_limits(
    query: str, max_rows: int, enforce_limit_clause: bool
) -> tuple[bool, str]:
    """Inspects SQL AST to enforce query row limits."""
    if not query or not isinstance(query, str):
        return True, ""

    try:
        parsed_statements = sqlglot.parse(query, read="sqlite")
    except (ParseError, Exception):
        # Syntax issues are handled by Layer 1; L3 skips unparseable SQL
        return True, ""

    valid_stmts = [s for s in parsed_statements if s is not None]
    if not valid_stmts:
        return True, ""

    root_stmt = valid_stmts[0]

    # Only inspect SELECT / UNION queries for row limits
    if not isinstance(root_stmt, (exp.Select, exp.Union)):
        return True, ""

    # 1. Enforce presence of root LIMIT clause if required
    root_limit = root_stmt.args.get("limit")
    if enforce_limit_clause and root_limit is None:
        return (
            False,
            f"Query lacks a mandatory LIMIT clause. Maximum allowed rows: {max_rows}.",
        )

    # 2. Check all LIMIT clauses in the AST (including subqueries and CTEs)
    for limit_node in root_stmt.find_all(exp.Limit):
        try:
            limit_val = int(limit_node.expression.this)
            if limit_val > max_rows:
                return (
                    False,
                    f"Requested row limit {limit_val} exceeds maximum allowed limit of {max_rows} rows.",
                )
        except (AttributeError, ValueError):
            pass

    return True, ""


def check_limits(
    context: RequestContext, policy: dict[str, Any] | None = None
) -> FirewallDecision:
    """Evaluates tool call against row caps, sliding window rate limits, and budget caps.

    Args:
        context: RequestContext for the intercepted tool call.
        policy: Optional pre-loaded policy dictionary. Defaults to policy.yaml.

    Returns:
        FirewallDecision (BLOCK if any limit is exceeded, ALLOW otherwise).
    """
    t0 = time.perf_counter()

    cfg = policy or load_policy()
    layer_3_cfg = cfg.get("layer_3", {})

    row_cfg = layer_3_cfg.get("row_limits", {})
    rate_cfg = layer_3_cfg.get("rate_limits", {})
    budget_cfg = layer_3_cfg.get("budgets", {})

    max_rows = row_cfg.get("max_rows", 50)
    enforce_limit = row_cfg.get("enforce_limit_clause", True)

    max_rpm = rate_cfg.get("max_requests_per_minute", 10)
    window_sec = rate_cfg.get("window_seconds", 60)

    max_tokens = budget_cfg.get("max_session_tokens", 50000)
    max_cost = budget_cfg.get("max_session_cost_dollars", 1.00)
    cost_per_query = budget_cfg.get("cost_per_query_dollars", 0.002)

    # 1. Rate Limiting Check
    rate_key = f"{context.agent_name}:{context.session_id}"
    allowed, count = rate_limiter.is_allowed(rate_key, max_rpm, window_sec)
    if not allowed:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return FirewallDecision(
            verdict=Verdict.BLOCK,
            reason=(
                f"Rate limit exceeded: {count} requests within {window_sec}s "
                f"(limit: {max_rpm} req/min)."
            ),
            layer="L3",
            latency_ms=elapsed_ms,
        )

    # 2. Cumulative Budget Check
    tokens_estimate = context.metadata.get("estimated_tokens", 50)
    budget_allowed, cur_cost, cur_tokens = budget_tracker.check_and_charge(
        context.session_id,
        cost_per_query,
        tokens_estimate,
        max_cost,
        max_tokens,
    )
    if not budget_allowed:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return FirewallDecision(
            verdict=Verdict.BLOCK,
            reason=(
                f"Session budget cap exceeded: accumulated cost ${cur_cost:.4f} "
                f"(limit: ${max_cost:.2f}) or tokens {cur_tokens} (limit: {max_tokens})."
            ),
            layer="L3",
            latency_ms=elapsed_ms,
        )

    # 3. SQL Row Cap Check (for execute_sql and export_csv)
    if context.tool_name in ("execute_sql", "export_csv"):
        query = context.get_argument("query")
        row_ok, violation_msg = _check_sql_row_limits(
            query, max_rows, enforce_limit
        )
        if not row_ok:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return FirewallDecision(
                verdict=Verdict.BLOCK,
                reason=violation_msg,
                layer="L3",
                latency_ms=elapsed_ms,
            )

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return FirewallDecision(
        verdict=Verdict.ALLOW,
        reason="Request conforms to row, rate, and budget limits.",
        layer="L3",
        latency_ms=elapsed_ms,
    )
