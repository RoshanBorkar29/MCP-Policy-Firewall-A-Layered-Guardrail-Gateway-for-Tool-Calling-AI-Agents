"""Structured audit logging service recording all tool call events, verdicts, and transformations.
Inputs: Evaluation contexts, layer decisions, and tool outputs. Outputs: Append-only JSONL audit records.
Build plan: Day 2.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from firewall.context import FirewallDecision, RequestContext

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_AUDIT_LOG_PATH = ROOT_DIR / "results" / "audit.jsonl"


class AuditLogger:
    """Non-blocking, fail-safe JSONL audit logger for firewall events."""

    def __init__(self, log_path: Path | str = DEFAULT_AUDIT_LOG_PATH):
        self.log_path = Path(log_path).resolve()

    def log_event(
        self,
        context: RequestContext,
        decision: FirewallDecision,
        final_response: str | None = None,
    ) -> dict[str, Any]:
        """Appends a structured audit event to the JSONL log file.

        Args:
            context: The tool call request context.
            decision: The firewall decision outcome.
            final_response: The response returned to the client (or error string).

        Returns:
            The recorded event dictionary.
        """
        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_name": context.agent_name,
            "session_id": context.session_id,
            "tool_name": context.tool_name,
            "arguments": context.arguments,
            "verdict": decision.verdict.value,
            "layer": decision.layer,
            "reason": decision.reason,
            "latency_ms": round(decision.latency_ms, 3),
            "final_response": final_response,
        }

        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:
            # Audit logging must be fail-safe and never crash proxy operations
            pass

        return record


# Global default logger instance
audit_logger = AuditLogger()
