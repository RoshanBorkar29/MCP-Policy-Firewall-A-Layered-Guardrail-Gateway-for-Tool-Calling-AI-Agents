"""Unit and integration tests for the self-healing agent and pipeline re-entry guardrail.
Inputs: Blocked query contexts, mocked remediation completions, and firewall pipelines. Outputs: Healing assertions.
Build plan: Day 7.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock
import pytest

from agents.healer import (
    heal_and_execute,
    heal_tool_call,
    load_healer_prompt,
)
from firewall.context import FirewallDecision, RequestContext, Verdict
from firewall.pipeline import FirewallPipeline


def _create_mock_healer_client(content: str) -> MagicMock:
    """Creates a mock Groq client returning specific JSON remediation content."""
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = content
    mock_client.chat.completions.create.return_value = MagicMock(choices=[mock_choice])
    return mock_client


def test_healer_prompt_loads():
    """Healer system prompt must load and contain policy remediation directives."""
    prompt = load_healer_prompt()
    assert "Self-Healer Agent" in prompt
    assert "Layer 1 (SQL AST Rules)" in prompt
    assert "Layer 3 (Row Limits)" in prompt
    assert "UNHEALABLE ACTIONS" in prompt


def test_heal_missing_limit_success():
    """Blocked query missing LIMIT is successfully repaired by appending LIMIT 50."""
    remediation_json = json.dumps(
        {
            "can_heal": True,
            "tool_name": "execute_sql",
            "modified_args": {"query": "SELECT id, name FROM customers LIMIT 50;"},
            "explanation": "Appended mandatory LIMIT 50 to comply with Layer 3 row cap.",
        }
    )
    mock_client = _create_mock_healer_client(remediation_json)

    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT id, name FROM customers;"},
    )
    dec = FirewallDecision(
        verdict=Verdict.BLOCK,
        reason="Query lacks a mandatory LIMIT clause.",
        layer="L3",
    )

    can_heal, repaired_ctx, explanation = heal_tool_call(ctx, dec, client=mock_client)

    assert can_heal is True
    assert repaired_ctx is not None
    assert repaired_ctx.get_argument("query") == "SELECT id, name FROM customers LIMIT 50;"
    assert repaired_ctx.agent_name == "healer"
    assert repaired_ctx.metadata["is_healed"] is True
    assert "LIMIT 50" in explanation


def test_heal_oversized_limit_clamped():
    """Query requesting 500 rows is clamped to 50 rows."""
    remediation_json = json.dumps(
        {
            "can_heal": True,
            "tool_name": "execute_sql",
            "modified_args": {"query": "SELECT * FROM transactions LIMIT 50;"},
            "explanation": "Clamped row limit from 500 to policy maximum of 50.",
        }
    )
    mock_client = _create_mock_healer_client(remediation_json)

    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM transactions LIMIT 500;"},
    )
    dec = FirewallDecision(
        verdict=Verdict.BLOCK,
        reason="Requested row limit 500 exceeds maximum allowed limit of 50 rows.",
        layer="L3",
    )

    can_heal, repaired_ctx, explanation = heal_tool_call(ctx, dec, client=mock_client)

    assert can_heal is True
    assert repaired_ctx is not None
    assert repaired_ctx.get_argument("query") == "SELECT * FROM transactions LIMIT 50;"


def test_heal_destructive_query_refused():
    """Destructive operations like DROP TABLE must be refused with can_heal: false."""
    remediation_json = json.dumps(
        {
            "can_heal": False,
            "tool_name": "execute_sql",
            "modified_args": {},
            "explanation": "Cannot heal destructive DROP operations; DDL statements are strictly prohibited.",
        }
    )
    mock_client = _create_mock_healer_client(remediation_json)

    ctx = RequestContext(tool_name="execute_sql", arguments={"query": "DROP TABLE accounts;"})
    dec = FirewallDecision(
        verdict=Verdict.BLOCK,
        reason="Statement type 'DROP' is prohibited.",
        layer="L1",
    )

    can_heal, repaired_ctx, explanation = heal_tool_call(ctx, dec, client=mock_client)

    assert can_heal is False
    assert repaired_ctx is None
    assert "destructive DROP" in explanation


def test_heal_handles_malformed_json():
    """Handles non-JSON response from LLM gracefully without crashing."""
    mock_client = _create_mock_healer_client("This is not valid JSON text.")

    ctx = RequestContext(tool_name="execute_sql", arguments={"query": "SELECT 1;"})
    dec = FirewallDecision(verdict=Verdict.BLOCK, reason="Blocked", layer="L1")

    can_heal, repaired_ctx, explanation = heal_tool_call(ctx, dec, client=mock_client)

    assert can_heal is False
    assert repaired_ctx is None
    assert "failed" in explanation.lower()


def test_heal_fails_safe_without_api_key(monkeypatch, tmp_path):
    """When GROQ_API_KEY is not set and no client is provided, raises RuntimeError."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr("agents.healer.ENV_PATH", tmp_path / "nonexistent.env")

    ctx = RequestContext(tool_name="execute_sql", arguments={"query": "SELECT 1;"})
    dec = FirewallDecision(verdict=Verdict.BLOCK, reason="Blocked", layer="L1")

    with pytest.raises(RuntimeError, match="GROQ_API_KEY is not set"):
        heal_tool_call(ctx, dec, client=None)


def test_heal_and_execute_already_allowed():
    """Tool calls that pass initial firewall evaluation execute directly without healing."""
    pipeline = FirewallPipeline(enabled_layers=["L1", "L3"])
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT COUNT(*) FROM customers;"},
    )

    result = heal_and_execute(ctx, pipeline)

    assert result["status"] == "allowed"
    assert result["attempts"] == 0
    assert result["decision"]["verdict"] == "ALLOW"


def test_heal_and_execute_successful_pipeline_reentry():
    """Healed query successfully re-enters the firewall pipeline and passes all layers."""
    pipeline = FirewallPipeline(enabled_layers=["L1", "L3"])

    # Query initially lacks LIMIT -> blocked by L3
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT id, name FROM customers;"},
    )

    remediation_json = json.dumps(
        {
            "can_heal": True,
            "tool_name": "execute_sql",
            "modified_args": {"query": "SELECT id, name FROM customers LIMIT 50;"},
            "explanation": "Added mandatory LIMIT 50.",
        }
    )
    mock_client = _create_mock_healer_client(remediation_json)

    def mock_executor(tool_name: str, args: dict) -> str:
        return json.dumps({"rows": [{"id": 1, "name": "Alice"}], "row_count": 1})

    result = heal_and_execute(
        ctx,
        pipeline=pipeline,
        downstream_executor=mock_executor,
        client=mock_client,
    )

    assert result["status"] == "healed"
    assert result["attempts"] == 1
    assert result["repaired_args"]["query"] == "SELECT id, name FROM customers LIMIT 50;"
    assert result["decision"]["verdict"] == "ALLOW"
    assert result["output"] is not None
    assert "Alice" in result["output"]


def test_heal_and_execute_unhealable_operation():
    """Unhealable operation terminates cleanly without unnecessary loops."""
    pipeline = FirewallPipeline(enabled_layers=["L1"])
    ctx = RequestContext(tool_name="execute_sql", arguments={"query": "DROP TABLE transactions;"})

    remediation_json = json.dumps(
        {
            "can_heal": False,
            "tool_name": "execute_sql",
            "modified_args": {},
            "explanation": "Destructive DROP statements cannot be healed.",
        }
    )
    mock_client = _create_mock_healer_client(remediation_json)

    result = heal_and_execute(ctx, pipeline=pipeline, client=mock_client)

    assert result["status"] == "unhealable"
    assert result["attempts"] == 1
    assert "DROP statements cannot be healed" in result["reason"]


def test_heal_and_execute_pipeline_reentry_catches_invalid_rewrite():
    """Mandatory Constraint: If a healed query is still prohibited, pipeline re-entry catches it."""
    pipeline = FirewallPipeline(enabled_layers=["L1", "L3"])

    # Query blocked by L3
    ctx = RequestContext(tool_name="execute_sql", arguments={"query": "SELECT * FROM accounts;"})

    # Adversarial or faulty healer rewrites it into a DROP statement
    bad_rewrite_json = json.dumps(
        {
            "can_heal": True,
            "tool_name": "execute_sql",
            "modified_args": {"query": "DROP TABLE accounts;"},
            "explanation": "Attempted rewrite",
        }
    )
    mock_client = _create_mock_healer_client(bad_rewrite_json)

    result = heal_and_execute(
        ctx,
        pipeline=pipeline,
        client=mock_client,
        max_attempts=1,
    )

    # Pipeline re-entry MUST block the DROP query, causing healing to fail!
    assert result["status"] == "failed"
    assert "Maximum healing attempts" in result["reason"]
    assert result["decision"]["layer"] == "L1"
    assert result["decision"]["verdict"] == "BLOCK"
