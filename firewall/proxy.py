"""FastMCP proxy server intercepting agent tool calls and dispatching to the inspection pipeline.
Inputs: Incoming client tool requests. Outputs: Proxied or blocked tool execution responses.
Build plan: Day 2.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from downstream import sql_server
from firewall.audit import audit_logger
from firewall.context import RequestContext, Verdict
from firewall.pipeline import FirewallPipeline

mcp = FastMCP("mcp-policy-firewall")
pipeline = FirewallPipeline()


def _handle_tool_call(tool_name: str, arguments: dict[str, Any]) -> str:
    """Core proxy interception handler evaluating and routing a tool call."""
    context = RequestContext(tool_name=tool_name, arguments=arguments)

    t0 = time.perf_counter()
    decision = pipeline.evaluate_request(context)
    decision.latency_ms = (time.perf_counter() - t0) * 1000.0

    if not decision.is_allowed:
        err_msg = json.dumps(
            {
                "error": f"Security Policy Violation [{decision.layer}]: {decision.reason}",
                "verdict": decision.verdict.value,
                "layer": decision.layer,
            }
        )
        audit_logger.log_event(context, decision, final_response=err_msg)
        return err_msg

    # Execute allowed call against downstream implementation
    try:
        if tool_name == "get_schema":
            raw_result = sql_server.get_schema()
        elif tool_name == "execute_sql":
            target_query = (decision.modified_args or arguments).get("query", "")
            raw_result = sql_server.execute_sql(target_query)
        elif tool_name == "export_csv":
            target_args = decision.modified_args or arguments
            raw_result = sql_server.export_csv(
                target_args.get("query", ""),
                target_args.get("filename", "export.csv"),
            )
        elif tool_name == "send_email":
            target_args = decision.modified_args or arguments
            raw_result = sql_server.send_email(
                target_args.get("to", ""),
                target_args.get("subject", ""),
                target_args.get("body", ""),
            )
        else:
            raw_result = json.dumps({"error": f"Unknown tool: {tool_name}"})
    except Exception as exc:
        raw_result = json.dumps({"error": f"Downstream execution error: {exc}"})

    # Post-execution evaluation (e.g., L2 PII masking on Day 3)
    resp_decision, sanitized_result = pipeline.evaluate_response(context, raw_result)
    audit_logger.log_event(context, decision, final_response=sanitized_result)

    return sanitized_result


@mcp.tool()
def get_schema() -> str:
    """Return the CREATE TABLE statements for all database tables."""
    return _handle_tool_call("get_schema", {})


@mcp.tool()
def execute_sql(query: str) -> str:
    """Execute a SQL query against the database via policy inspection."""
    return _handle_tool_call("execute_sql", {"query": query})


@mcp.tool()
def export_csv(query: str, filename: str) -> str:
    """Export query results to a CSV file via policy inspection."""
    return _handle_tool_call("export_csv", {"query": query, "filename": filename})


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an outbound email via policy inspection."""
    return _handle_tool_call(
        "send_email", {"to": to, "subject": subject, "body": body}
    )


if __name__ == "__main__":
    mcp.run()
