"""Sequential guardrail execution engine evaluating tool calls through configured layers.
Inputs: Tool call context and payload. Outputs: Verdict (ALLOW, MODIFY, BLOCK, APPROVAL_REQUIRED).
Build plan: Day 2.
"""

from __future__ import annotations

import time
from typing import Any

from firewall.context import FirewallDecision, RequestContext, Verdict
from firewall.layers import l1_sql_rules


class FirewallPipeline:
    """Sequential multi-layer guardrail inspection pipeline."""

    def __init__(self, enabled_layers: list[str] | None = None):
        """Initializes pipeline with specified active guardrail layers.

        Args:
            enabled_layers: List of active layer identifiers (e.g., ['L1']).
                           Defaults to ['L1'] on Day 2.
        """
        if enabled_layers is None:
            self.enabled_layers = ["L1"]
        else:
            self.enabled_layers = list(enabled_layers)

    def is_layer_enabled(self, layer_id: str) -> bool:
        """Check if a specific layer is active."""
        return layer_id.upper() in [l.upper() for l in self.enabled_layers]

    def evaluate_request(self, context: RequestContext) -> FirewallDecision:
        """Evaluates an incoming tool call across all active pre-execution layers.

        Short-circuits immediately upon receiving a BLOCK or APPROVAL_REQUIRED verdict.

        Args:
            context: Request context containing tool name and arguments.

        Returns:
            FirewallDecision indicating whether to allow, modify, or block the call.
        """
        t0 = time.perf_counter()

        # Tools that execute SQL queries
        sql_tools = ("execute_sql", "export_csv")

        # Layer 1: SQL AST rules
        if self.is_layer_enabled("L1") and context.tool_name in sql_tools:
            query = context.get_argument("query")
            l1_decision = l1_sql_rules.check_sql(query)
            if l1_decision.is_blocked:
                l1_decision.latency_ms = (time.perf_counter() - t0) * 1000.0
                return l1_decision

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return FirewallDecision(
            verdict=Verdict.ALLOW,
            reason="All active firewall layers passed.",
            layer="PIPELINE",
            latency_ms=elapsed_ms,
        )

    def evaluate_response(
        self, context: RequestContext, raw_response: str
    ) -> tuple[FirewallDecision, str]:
        """Evaluates and transforms a downstream tool response across post-execution layers.

        (Placeholder for Layer 2 PII Masking on Day 3).

        Args:
            context: Request context for the completed tool call.
            raw_response: Output text returned from the downstream service.

        Returns:
            Tuple of (FirewallDecision, sanitized_response_string).
        """
        return (
            FirewallDecision(
                verdict=Verdict.ALLOW,
                reason="Response passed post-execution inspection.",
                layer="PIPELINE",
            ),
            raw_response,
        )
