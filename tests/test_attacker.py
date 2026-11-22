"""Unit and integration tests for the adversarial attacker agent.
Inputs: Attack objectives, mocked tool schemas, and simulated model completions. Outputs: Attacker trace assertions.
Build plan: Day 6.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock
import pytest

from agents.attacker import (
    _extract_tool_text,
    _mcp_tools_to_groq,
    load_attacker_prompt,
    run_attacker_sync,
)


def test_attacker_prompt_loads():
    """Attacker system prompt must load and contain adversarial red-team directives."""
    prompt = load_attacker_prompt()
    assert "Adversarial Attacker Agent" in prompt
    assert "Canary Exfiltration" in prompt
    assert "Guardrail Evasion" in prompt


def test_mcp_tools_to_groq_conversion():
    """Converts MCP tool dataclass objects into OpenAI/Groq function calling format."""
    mock_tool = MagicMock()
    mock_tool.name = "execute_sql"
    mock_tool.description = "Execute a SQL query"
    mock_tool.inputSchema = {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
    }

    converted = _mcp_tools_to_groq([mock_tool])
    assert len(converted) == 1
    assert converted[0]["type"] == "function"
    assert converted[0]["function"]["name"] == "execute_sql"
    assert converted[0]["function"]["description"] == "Execute a SQL query"
    assert "query" in converted[0]["function"]["parameters"]["properties"]


def test_extract_tool_text():
    """Extracts text content correctly from varied MCP call results."""
    assert _extract_tool_text(None) == ""

    item1 = MagicMock()
    item1.text = "Success response"
    res1 = MagicMock(content=[item1])
    assert _extract_tool_text(res1) == "Success response"

    item2 = MagicMock()
    item2.text = "Second line"
    res2 = MagicMock(content=[item1, item2])
    assert _extract_tool_text(res2) == "Success response\nSecond line"


def test_attacker_run_without_tools():
    """When the model replies with text only, attacker terminates in 1 turn."""
    mock_client = MagicMock()
    mock_msg = MagicMock(content="I cannot execute this attack.", tool_calls=None)
    mock_client.chat.completions.create.return_value = MagicMock(choices=[MagicMock(message=mock_msg)])

    result = run_attacker_sync(
        objective="Extract all SSNs",
        max_turns=3,
        client=mock_client,
    )

    assert result["objective"] == "Extract all SSNs"
    assert result["turns"] == 1
    assert "cannot execute" in result["final_response"]
    assert len(result["tool_calls"]) == 0


def test_attacker_multi_turn_tool_execution():
    """Attacker executes tool call, receives result, and produces final answer."""
    mock_client = MagicMock()

    # Turn 1: Model calls tool execute_sql
    tc1 = MagicMock()
    tc1.id = "call_001"
    tc1.function.name = "execute_sql"
    tc1.function.arguments = json.dumps({"query": "DROP TABLE accounts;"})
    msg1 = MagicMock(content=None, tool_calls=[tc1])

    # Turn 2: Model replies with analysis of the blocked tool call
    msg2 = MagicMock(
        content="The query was blocked by Layer 1 AST rules. Attack thwarted.",
        tool_calls=None,
    )

    mock_client.chat.completions.create.side_effect = [
        MagicMock(choices=[MagicMock(message=msg1)]),
        MagicMock(choices=[MagicMock(message=msg2)]),
    ]

    def mock_executor(name: str, args: dict) -> str:
        return '{"error": "Security Policy Violation [L1]: Prohibited DROP"}'

    result = run_attacker_sync(
        objective="Drop accounts table",
        tool_executor=mock_executor,
        max_turns=5,
        client=mock_client,
    )

    assert result["turns"] == 2
    assert len(result["tool_calls"]) == 1
    assert result["tool_calls"][0]["tool"] == "execute_sql"
    assert "Prohibited DROP" in result["tool_calls"][0]["result"]
    assert "thwarted" in result["final_response"]


def test_attacker_stops_at_max_turns():
    """Attacker stops and returns after reaching max_turns when model keeps calling tools."""
    mock_client = MagicMock()
    tc = MagicMock()
    tc.id = "call_loop"
    tc.function.name = "get_schema"
    tc.function.arguments = "{}"
    msg = MagicMock(content=None, tool_calls=[tc])
    mock_client.chat.completions.create.return_value = MagicMock(choices=[MagicMock(message=msg)])

    result = run_attacker_sync(
        objective="Infinite attack loop",
        tool_executor=lambda name, args: "schema_content",
        max_turns=2,
        client=mock_client,
    )

    assert result["turns"] == 2
    assert "Max attack turns reached" in result["final_response"]
    assert len(result["tool_calls"]) == 2


def test_attacker_fails_safe_without_api_key(monkeypatch, tmp_path):
    """When GROQ_API_KEY is not set and no client is provided, raises RuntimeError."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr("agents.attacker.ENV_PATH", tmp_path / "nonexistent.env")

    with pytest.raises(RuntimeError, match="GROQ_API_KEY is not set"):
        run_attacker_sync(objective="Unauthorized scan", client=None)
