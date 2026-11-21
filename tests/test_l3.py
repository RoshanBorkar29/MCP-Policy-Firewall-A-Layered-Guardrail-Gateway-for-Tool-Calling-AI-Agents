"""Unit test suite for Layer 3 rate limiting, row caps, and cumulative budget tracking.
Inputs: Simulated request streams and token counters. Outputs: Pytest test assertion results.
Build plan: Day 3.
"""

from __future__ import annotations

import pytest

from firewall.context import RequestContext, Verdict
from firewall.layers.l3_limits import (
    RateLimiter,
    BudgetTracker,
    check_limits,
    reset_limits,
)


@pytest.fixture(autouse=True)
def clean_limits_state():
    """Reset rate limiter and budget tracker counters before and after each test."""
    reset_limits()
    yield
    reset_limits()


# --- 1. SQL Query Row Limits Tests ---


def test_l3_sql_valid_limit_allowed():
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM customers LIMIT 10"},
    )
    decision = check_limits(ctx)
    assert decision.verdict == Verdict.ALLOW
    assert decision.is_allowed


def test_l3_sql_limit_at_exact_threshold_allowed():
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM accounts LIMIT 50"},
    )
    decision = check_limits(ctx)
    assert decision.verdict == Verdict.ALLOW


def test_l3_sql_limit_exceeds_threshold_blocked():
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM customers LIMIT 51"},
    )
    decision = check_limits(ctx)
    assert decision.verdict == Verdict.BLOCK
    assert decision.layer == "L3"
    assert "exceeds maximum" in decision.reason


def test_l3_sql_large_limit_blocked():
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM customers LIMIT 1000"},
    )
    decision = check_limits(ctx)
    assert decision.verdict == Verdict.BLOCK
    assert "1000" in decision.reason


def test_l3_sql_missing_limit_blocked():
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM customers"},
    )
    decision = check_limits(ctx)
    assert decision.verdict == Verdict.BLOCK
    assert "mandatory LIMIT" in decision.reason


def test_l3_sql_scalar_agg_count_allowed_without_limit():
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT COUNT(*) FROM customers"},
    )
    decision = check_limits(ctx)
    assert decision.verdict == Verdict.ALLOW


def test_l3_sql_scalar_agg_multiple_functions_allowed():
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT SUM(balance), AVG(balance) FROM accounts"},
    )
    decision = check_limits(ctx)
    assert decision.verdict == Verdict.ALLOW


def test_l3_sql_grouped_agg_requires_limit():
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={
            "query": "SELECT customer_id, COUNT(*) FROM accounts GROUP BY customer_id"
        },
    )
    decision = check_limits(ctx)
    assert decision.verdict == Verdict.BLOCK
    assert "mandatory LIMIT" in decision.reason


def test_l3_sql_subquery_limit_exceeded_blocked():
    # Outer limit is 10, but inner subquery requests 200 rows
    query = "SELECT * FROM (SELECT * FROM customers LIMIT 200) LIMIT 10"
    ctx = RequestContext(tool_name="execute_sql", arguments={"query": query})
    decision = check_limits(ctx)
    assert decision.verdict == Verdict.BLOCK
    assert "200" in decision.reason


# --- 2. Rate Limiting Tests ---


def test_l3_rate_limiter_under_threshold_allowed():
    ctx = RequestContext(
        tool_name="get_schema",
        arguments={},
        agent_name="worker",
        session_id="s_rate_ok",
    )
    for _ in range(10):
        decision = check_limits(ctx)
        assert decision.verdict == Verdict.ALLOW


def test_l3_rate_limiter_blocks_on_11th_request():
    ctx = RequestContext(
        tool_name="get_schema",
        arguments={},
        agent_name="spammer",
        session_id="s_rate_flood",
    )
    for _ in range(10):
        check_limits(ctx)

    # 11th request within window exceeds 10 req/min
    d_blocked = check_limits(ctx)
    assert d_blocked.verdict == Verdict.BLOCK
    assert d_blocked.layer == "L3"
    assert "Rate limit exceeded" in d_blocked.reason


def test_l3_rate_limiter_session_isolation():
    ctx_agent1 = RequestContext(
        tool_name="get_schema",
        arguments={},
        agent_name="worker1",
        session_id="sess1",
    )
    ctx_agent2 = RequestContext(
        tool_name="get_schema",
        arguments={},
        agent_name="worker2",
        session_id="sess2",
    )

    # Exhaust agent1
    for _ in range(10):
        check_limits(ctx_agent1)
    assert check_limits(ctx_agent1).verdict == Verdict.BLOCK

    # Agent2 should still be allowed
    assert check_limits(ctx_agent2).verdict == Verdict.ALLOW


# --- 3. Cumulative Budget Tests ---


def test_l3_budget_blocks_on_cost_cap():
    ctx = RequestContext(
        tool_name="get_schema",
        arguments={},
        session_id="budget_cost_test",
    )
    # Policy with small cost cap ($0.005, cost_per_query=$0.002)
    tight_policy = {
        "layer_3": {
            "budgets": {
                "max_session_cost_dollars": 0.005,
                "cost_per_query_dollars": 0.002,
                "max_session_tokens": 50000,
            },
            "rate_limits": {
                "max_requests_per_minute": 100,
                "window_seconds": 60,
            },
        }
    }
    # 1st call: $0.002 (<= $0.005) -> ALLOW
    assert check_limits(ctx, policy=tight_policy).verdict == Verdict.ALLOW
    # 2nd call: $0.004 (<= $0.005) -> ALLOW
    assert check_limits(ctx, policy=tight_policy).verdict == Verdict.ALLOW
    # 3rd call: $0.006 (> $0.005) -> BLOCK
    d_blocked = check_limits(ctx, policy=tight_policy)
    assert d_blocked.verdict == Verdict.BLOCK
    assert "budget cap exceeded" in d_blocked.reason.lower()


def test_l3_budget_blocks_on_token_cap():
    ctx = RequestContext(
        tool_name="get_schema",
        arguments={},
        session_id="budget_token_test",
        metadata={"estimated_tokens": 600},
    )
    tight_policy = {
        "layer_3": {
            "budgets": {
                "max_session_cost_dollars": 100.0,
                "cost_per_query_dollars": 0.001,
                "max_session_tokens": 1000,
            },
            "rate_limits": {
                "max_requests_per_minute": 100,
                "window_seconds": 60,
            },
        }
    }
    # 1st call: 600 tokens (<= 1000) -> ALLOW
    assert check_limits(ctx, policy=tight_policy).verdict == Verdict.ALLOW
    # 2nd call: 1200 tokens (> 1000) -> BLOCK
    d_blocked = check_limits(ctx, policy=tight_policy)
    assert d_blocked.verdict == Verdict.BLOCK
    assert "budget cap exceeded" in d_blocked.reason.lower()


# --- 4. Non-SQL Tools Interaction ---


def test_l3_non_sql_tool_skips_row_limit():
    ctx_email = RequestContext(
        tool_name="send_email",
        arguments={
            "to": "test@test.com",
            "subject": "Greetings",
            "body": "Hello",
        },
    )
    # Email has no SQL query, so row limits are skipped, but rate/budget check succeeds
    decision = check_limits(ctx_email)
    assert decision.verdict == Verdict.ALLOW
