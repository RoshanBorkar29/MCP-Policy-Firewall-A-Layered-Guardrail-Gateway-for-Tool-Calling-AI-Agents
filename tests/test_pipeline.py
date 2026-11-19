"""Integration test suite for the end-to-end firewall pipeline and layer decision routing.
Inputs: Mock tool calls dispatched across various layer configs. Outputs: Pytest test assertion results.
Build plan: Day 2.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import pytest

from firewall.audit import AuditLogger
from firewall.context import FirewallDecision, RequestContext, Verdict
from firewall.pipeline import FirewallPipeline
from firewall import proxy


def test_request_context_defaults_and_helpers():
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT 1"},
    )
    assert ctx.agent_name == "worker"
    assert ctx.session_id == "default"
    assert ctx.get_argument("query") == "SELECT 1"
    assert ctx.get_argument("missing", "default_val") == "default_val"


def test_pipeline_allows_safe_sql():
    pipeline = FirewallPipeline(enabled_layers=["L1"])
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT COUNT(*) FROM customers"},
    )
    decision = pipeline.evaluate_request(ctx)
    assert decision.verdict == Verdict.ALLOW
    assert decision.is_allowed


def test_pipeline_blocks_destructive_sql():
    pipeline = FirewallPipeline(enabled_layers=["L1"])
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "DROP TABLE customers"},
    )
    decision = pipeline.evaluate_request(ctx)
    assert decision.verdict == Verdict.BLOCK
    assert decision.is_blocked
    assert decision.layer == "L1"


def test_pipeline_export_csv_inspects_sql():
    pipeline = FirewallPipeline(enabled_layers=["L1"])
    ctx = RequestContext(
        tool_name="export_csv",
        arguments={"query": "DELETE FROM accounts", "filename": "leak.csv"},
    )
    decision = pipeline.evaluate_request(ctx)
    assert decision.verdict == Verdict.BLOCK
    assert decision.layer == "L1"


def test_pipeline_allows_non_sql_tools():
    pipeline = FirewallPipeline(enabled_layers=["L1"])
    ctx_schema = RequestContext(tool_name="get_schema", arguments={})
    ctx_email = RequestContext(
        tool_name="send_email",
        arguments={"to": "test@test.com", "subject": "Hi", "body": "Body"},
    )

    dec_schema = pipeline.evaluate_request(ctx_schema)
    dec_email = pipeline.evaluate_request(ctx_email)

    assert dec_schema.verdict == Verdict.ALLOW
    assert dec_email.verdict == Verdict.ALLOW


def test_pipeline_layer_toggle_c0_baseline():
    # Ablation C0: no layers enabled (passthrough mode)
    pipeline = FirewallPipeline(enabled_layers=[])
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "DROP TABLE accounts"},
    )
    decision = pipeline.evaluate_request(ctx)
    assert decision.verdict == Verdict.ALLOW
    assert not pipeline.is_layer_enabled("L1")


def test_pipeline_layer_toggle_c1_l1_only():
    # Ablation C1: L1 enabled
    pipeline = FirewallPipeline(enabled_layers=["L1"])
    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "DROP TABLE accounts"},
    )
    decision = pipeline.evaluate_request(ctx)
    assert decision.verdict == Verdict.BLOCK
    assert pipeline.is_layer_enabled("L1")


def test_audit_logger_records_event(tmp_path: Path):
    log_file = tmp_path / "test_audit.jsonl"
    logger = AuditLogger(log_path=log_file)

    ctx = RequestContext(
        tool_name="execute_sql",
        arguments={"query": "DROP TABLE customers"},
        agent_name="attacker",
    )
    decision = FirewallDecision(
        verdict=Verdict.BLOCK,
        reason="DROP prohibited",
        layer="L1",
        latency_ms=1.25,
    )

    logger.log_event(ctx, decision, final_response="BLOCKED")

    assert log_file.exists()
    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    entry = json.loads(lines[0])
    assert entry["agent_name"] == "attacker"
    assert entry["tool_name"] == "execute_sql"
    assert entry["verdict"] == "BLOCK"
    assert entry["layer"] == "L1"
    assert entry["reason"] == "DROP prohibited"


def test_proxy_handle_tool_call_blocked():
    result = proxy._handle_tool_call(
        "execute_sql",
        {"query": "DROP TABLE customers"},
    )
    parsed = json.loads(result)
    assert "error" in parsed
    assert parsed["verdict"] == "BLOCK"
    assert parsed["layer"] == "L1"


def test_proxy_handle_tool_call_allowed():
    result = proxy._handle_tool_call(
        "execute_sql",
        {"query": "SELECT COUNT(*) AS total FROM customers"},
    )
    parsed = json.loads(result)
    assert "rows" in parsed
    assert parsed["rows"][0]["total"] == 100
