"""Unit and integration tests for Layer 5 Human Approval Gate guardrail.
Inputs: Intercepted tool contexts, operator prompts, and simulation handlers. Outputs: Approval assertions.
Build plan: Day 5.
"""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from firewall.context import RequestContext, Verdict
from firewall.layers.l5_approval import (
    check_approval,
    cli_approval_prompt,
    is_high_risk_operation,
    mock_approval_handler,
)
from firewall.pipeline import FirewallPipeline


def test_l5_low_risk_tool_auto_allowed():
    """Low-risk tool calls (execute_sql, get_schema) do not require operator sign-off."""
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT COUNT(*) FROM customers;"},
    )
    decision = check_approval(ctx)

    assert decision.verdict == Verdict.ALLOW
    assert decision.is_allowed is True
    assert decision.layer == "L5"
    assert "not classified as high-risk" in decision.reason


def test_l5_high_risk_tools_identified():
    """export_csv and send_email must be identified as high-risk by default."""
    ctx_email = RequestContext(tool_name="send_email", arguments={"to": "user@example.com"})
    ctx_export = RequestContext(tool_name="export_csv", arguments={"filename": "out.csv"})
    ctx_sql = RequestContext(tool_name="execute_sql", arguments={"query": "SELECT 1;"})

    assert is_high_risk_operation(ctx_email) is True
    assert is_high_risk_operation(ctx_export) is True
    assert is_high_risk_operation(ctx_sql) is False


def test_l5_high_risk_requires_approval_when_no_handler():
    """High-risk operations without an approval handler return APPROVAL_REQUIRED."""
    ctx = RequestContext(
        tool_name="send_email",
        arguments={"to": "admin@example.com", "subject": "Alert", "body": "Disk full"},
    )
    decision = check_approval(ctx, approval_handler=None)

    assert decision.verdict == Verdict.APPROVAL_REQUIRED
    assert decision.is_allowed is False
    assert decision.requires_approval is True
    assert decision.layer == "L5"


def test_l5_high_risk_approved_by_handler():
    """When the approval handler returns True, the decision is ALLOW."""
    ctx = RequestContext(
        tool_name="export_csv",
        arguments={"query": "SELECT id FROM accounts LIMIT 10;", "filename": "acc.csv"},
    )
    decision = check_approval(ctx, approval_handler=mock_approval_handler(True))

    assert decision.verdict == Verdict.ALLOW
    assert decision.is_allowed is True
    assert "approved by operator" in decision.reason


def test_l5_high_risk_rejected_by_handler():
    """When the approval handler returns False, the decision is BLOCK."""
    ctx = RequestContext(
        tool_name="export_csv",
        arguments={"query": "SELECT id FROM accounts LIMIT 10;", "filename": "acc.csv"},
    )
    decision = check_approval(ctx, approval_handler=mock_approval_handler(False))

    assert decision.verdict == Verdict.BLOCK
    assert decision.is_blocked is True
    assert "rejected by operator" in decision.reason


def test_l5_handler_exception_fails_safe():
    """Exceptions raised by the approval handler result in a fail-safe BLOCK."""
    def _faulty_handler(ctx: RequestContext) -> bool:
        raise ConnectionResetError("Lost connection to operator console")

    ctx = RequestContext(tool_name="send_email", arguments={"to": "ceo@example.com"})
    decision = check_approval(ctx, approval_handler=_faulty_handler)

    assert decision.verdict == Verdict.BLOCK
    assert "error" in decision.reason


def test_l5_cli_approval_prompt_accept(monkeypatch):
    """Operator typing 'y' or 'yes' grants approval."""
    monkeypatch.setattr("builtins.input", lambda _: "y")
    ctx = RequestContext(tool_name="export_csv", arguments={"filename": "dump.csv"})
    assert cli_approval_prompt(ctx) is True

    monkeypatch.setattr("builtins.input", lambda _: "YES")
    assert cli_approval_prompt(ctx) is True


def test_l5_cli_approval_prompt_reject(monkeypatch):
    """Operator typing 'n' or anything other than yes rejects execution."""
    monkeypatch.setattr("builtins.input", lambda _: "n")
    ctx = RequestContext(tool_name="export_csv", arguments={"filename": "dump.csv"})
    assert cli_approval_prompt(ctx) is False

    monkeypatch.setattr("builtins.input", lambda _: "")
    assert cli_approval_prompt(ctx) is False


def test_l5_cli_approval_prompt_keyboard_interrupt(monkeypatch):
    """KeyboardInterrupt during prompt cleanly returns False."""
    def _raise_interrupt(_: str) -> str:
        raise KeyboardInterrupt()

    monkeypatch.setattr("builtins.input", _raise_interrupt)
    ctx = RequestContext(tool_name="export_csv", arguments={})
    assert cli_approval_prompt(ctx) is False


def test_l5_custom_policy_configuration():
    """Custom high_risk_tools configuration in policy.yaml is respected."""
    policy = {
        "layer_5": {
            "high_risk_tools": ["custom_backup_tool"],
            "require_approval_on_modify": False,
        }
    }
    ctx_custom = RequestContext(tool_name="custom_backup_tool", arguments={})
    ctx_email = RequestContext(tool_name="send_email", arguments={})

    assert is_high_risk_operation(ctx_custom, policy=policy) is True
    assert is_high_risk_operation(ctx_email, policy=policy) is False


def test_l5_pipeline_integration_workflow():
    """FirewallPipeline with L5 enforces approval gate semantics."""
    # 1. Without handler -> APPROVAL_REQUIRED
    p_pending = FirewallPipeline(enabled_layers=["L5"], approval_handler=None)
    ctx_email = RequestContext(tool_name="send_email", arguments={"to": "audit@example.com"})
    dec_pending = p_pending.evaluate_request(ctx_email)
    assert dec_pending.verdict == Verdict.APPROVAL_REQUIRED

    # 2. With approving handler -> ALLOW
    p_approved = FirewallPipeline(
        enabled_layers=["L5"],
        approval_handler=mock_approval_handler(True),
    )
    dec_approved = p_approved.evaluate_request(ctx_email)
    assert dec_approved.verdict == Verdict.ALLOW

    # 3. With rejecting handler -> BLOCK
    p_rejected = FirewallPipeline(
        enabled_layers=["L5"],
        approval_handler=mock_approval_handler(False),
    )
    dec_rejected = p_rejected.evaluate_request(ctx_email)
    assert dec_rejected.verdict == Verdict.BLOCK


def test_full_pipeline_ordering_l3_l1_l4_l5():
    """Pipeline evaluates pre-execution layers in cost/safety order: L3 -> L1 -> L4 -> L5."""
    mock_l4_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = '{"risk_level": "LOW", "verdict": "ALLOW", "reason": "Safe"}'
    mock_l4_client.chat.completions.create.return_value = MagicMock(choices=[mock_choice])

    pipeline = FirewallPipeline(
        enabled_layers=["L1", "L3", "L4", "L5"],
        judge_client=mock_l4_client,
        approval_handler=mock_approval_handler(True),
    )

    # 1. L3 short-circuits on missing LIMIT
    ctx_l3 = RequestContext(tool_name="execute_sql", arguments={"query": "SELECT * FROM customers;"})
    dec_l3 = pipeline.evaluate_request(ctx_l3)
    assert dec_l3.verdict == Verdict.BLOCK
    assert dec_l3.layer == "L3"

    # 2. L1 short-circuits on DROP TABLE
    ctx_l1 = RequestContext(tool_name="execute_sql", arguments={"query": "DROP TABLE accounts;"})
    dec_l1 = pipeline.evaluate_request(ctx_l1)
    assert dec_l1.verdict == Verdict.BLOCK
    assert dec_l1.layer == "L1"

    # 3. Safe execute_sql passes L3, L1, L4, and L5 (not high-risk)
    ctx_safe = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT id FROM accounts LIMIT 5;"},
    )
    dec_safe = pipeline.evaluate_request(ctx_safe)
    assert dec_safe.verdict == Verdict.ALLOW
    assert dec_safe.layer == "PIPELINE"
