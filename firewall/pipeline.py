"""Sequential guardrail execution engine evaluating tool calls through configured layers.
Inputs: Tool call context and payload. Outputs: Verdict (ALLOW, MODIFY, BLOCK, APPROVAL_REQUIRED).
Build plan: Day 2.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from firewall.context import FirewallDecision, RequestContext, Verdict, load_policy
from firewall.layers import l1_sql_rules, l2_pii, l3_limits, l4_judge, l5_approval


class FirewallPipeline:
    """Sequential multi-layer guardrail inspection pipeline."""

    def __init__(
        self,
        enabled_layers: list[str] | None = None,
        policy: dict[str, Any] | None = None,
        judge_client: Any | None = None,
        approval_handler: Callable[[RequestContext], bool] | None = None,
    ):
        """Initializes pipeline with specified active guardrail layers.

        Args:
            enabled_layers: List of active layer identifiers (e.g., ['L1', 'L2', 'L3']).
                           Defaults to ['L1', 'L2', 'L3'] on Day 3.
            policy: Optional pre-loaded policy dictionary. Defaults to policy.yaml.
            judge_client: Optional pre-initialized Groq client or test mock for Layer 4.
            approval_handler: Optional human approval callback for Layer 5.
        """
        self.policy = policy or load_policy()
        if enabled_layers is None:
            self.enabled_layers = ["L1", "L2", "L3"]
        else:
            self.enabled_layers = list(enabled_layers)
        self.judge_client = judge_client
        self.approval_handler = approval_handler

    def is_layer_enabled(self, layer_id: str) -> bool:
        """Check if a specific layer is active."""
        return layer_id.upper() in [l.upper() for l in self.enabled_layers]

    def evaluate_request(
        self,
        context: RequestContext,
        approval_handler: Callable[[RequestContext], bool] | None = None,
    ) -> FirewallDecision:
        """Evaluates an incoming tool call across all active pre-execution layers.

        Short-circuits immediately upon receiving a BLOCK or APPROVAL_REQUIRED verdict.

        Order of evaluation:
        1. Layer 3: Rate limits, row limits, and budgets (stops runaway requests early)
        2. Layer 1: SQL AST rules (fast syntactic validation)
        3. Layer 4: LLM Judge (semantic intent and prompt injection inspection)
        4. Layer 5: Human Approval Gate (operator verification for high-risk operations)

        Args:
            context: Request context containing tool name and arguments.
            approval_handler: Optional per-request human approval callback for Layer 5.

        Returns:
            FirewallDecision indicating whether to allow, modify, block, or require approval.
        """
        t0 = time.perf_counter()
        sql_tools = ("execute_sql", "export_csv")

        # Layer 3: Pre-execution limits (Rate limits, session budget, row caps)
        if self.is_layer_enabled("L3"):
            l3_decision = l3_limits.check_limits(context, policy=self.policy)
            if l3_decision.is_blocked:
                l3_decision.latency_ms = (time.perf_counter() - t0) * 1000.0
                return l3_decision

        # Layer 1: SQL AST rules
        if self.is_layer_enabled("L1") and context.tool_name in sql_tools:
            query = context.get_argument("query")
            l1_decision = l1_sql_rules.check_sql(query)
            if l1_decision.is_blocked:
                l1_decision.latency_ms = (time.perf_counter() - t0) * 1000.0
                return l1_decision

        # Layer 4: LLM Semantic Judge
        if self.is_layer_enabled("L4"):
            l4_decision = l4_judge.evaluate_semantic_risk(
                context, policy=self.policy, client=self.judge_client
            )
            if l4_decision.is_blocked:
                l4_decision.latency_ms = (time.perf_counter() - t0) * 1000.0
                return l4_decision

        # Layer 5: Human Approval Gate
        if self.is_layer_enabled("L5"):
            active_handler = approval_handler or self.approval_handler
            l5_decision = l5_approval.check_approval(
                context, policy=self.policy, approval_handler=active_handler
            )
            if not l5_decision.is_allowed:
                l5_decision.latency_ms = (time.perf_counter() - t0) * 1000.0
                return l5_decision

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return FirewallDecision(
            verdict=Verdict.ALLOW,
            reason="All active pre-execution firewall layers passed.",
            layer="PIPELINE",
            latency_ms=elapsed_ms,
        )

    def evaluate_response(
        self, context: RequestContext, raw_response: str
    ) -> tuple[FirewallDecision, str]:
        """Evaluates and transforms a downstream tool response across post-execution layers.

        Evaluates Layer 2 PII Masking to sanitize return payloads before client sees them.

        Args:
            context: Request context for the completed tool call.
            raw_response: Output text returned from the downstream service.

        Returns:
            Tuple of (FirewallDecision, sanitized_response_string).
        """
        t0 = time.perf_counter()

        # Layer 2: PII Masking & Canary detection
        if self.is_layer_enabled("L2"):
            l2_decision, sanitized = l2_pii.mask_pii(raw_response, policy=self.policy)
            l2_decision.latency_ms = (time.perf_counter() - t0) * 1000.0
            return l2_decision, sanitized

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return (
            FirewallDecision(
                verdict=Verdict.ALLOW,
                reason="Response passed post-execution inspection (L2 disabled).",
                layer="PIPELINE",
                latency_ms=elapsed_ms,
            ),
            raw_response,
        )
