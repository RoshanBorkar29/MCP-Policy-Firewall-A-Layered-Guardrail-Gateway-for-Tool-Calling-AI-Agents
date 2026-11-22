"""Layer 5 guardrail requiring explicit human-in-the-loop approval for high-risk operations.
Inputs: Tool call context and risk classification. Outputs: APPROVAL_REQUIRED or operator verdict.
Build plan: Day 5.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from firewall.context import FirewallDecision, RequestContext, Verdict, load_policy

# Type alias for human approval callbacks
ApprovalHandler = Callable[[RequestContext], bool]


def mock_approval_handler(approved: bool = True) -> ApprovalHandler:
    """Returns a deterministic approval handler for automated testing and evaluation."""
    def _handler(ctx: RequestContext) -> bool:
        return approved
    return _handler


def cli_approval_prompt(context: RequestContext) -> bool:
    """Prompts a human operator via standard input for approval of a tool execution.

    Args:
        context: RequestContext containing tool name and arguments.

    Returns:
        True if the operator inputs 'y' or 'yes' (case-insensitive), False otherwise.
    """
    print("\n" + "=" * 60)
    print(" [SECURITY GATE] HUMAN-IN-THE-LOOP APPROVAL REQUIRED")
    print("=" * 60)
    print(f" Tool:        {context.tool_name}")
    print(f" Agent:       {context.agent_name}")
    print(f" Session ID:  {context.session_id}")
    print(" Arguments:")
    print(json.dumps(context.arguments, indent=2))
    print("-" * 60)

    try:
        response = input("Approve tool execution? [y/N]: ").strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print("\nApproval aborted by operator.")
        return False


def is_high_risk_operation(
    context: RequestContext, policy: dict[str, Any] | None = None
) -> bool:
    """Determines whether a tool call is subject to Layer 5 approval requirements.

    Args:
        context: Intercepted RequestContext.
        policy: Optional policy dictionary.

    Returns:
        True if the tool call requires operator sign-off, False otherwise.
    """
    cfg = policy or load_policy()
    l5_cfg = cfg.get("layer_5", {})

    high_risk_tools = l5_cfg.get("high_risk_tools", ["export_csv", "send_email"])
    require_on_modify = l5_cfg.get("require_approval_on_modify", False)

    if context.tool_name in high_risk_tools:
        return True

    if require_on_modify and context.metadata.get("is_modified", False):
        return True

    if context.metadata.get("requires_human_approval", False):
        return True

    return False


def check_approval(
    context: RequestContext,
    policy: dict[str, Any] | None = None,
    approval_handler: ApprovalHandler | None = None,
) -> FirewallDecision:
    """Evaluates whether a tool call requires or receives human operator approval.

    Args:
        context: RequestContext for the intercepted tool call.
        policy: Optional pre-loaded policy dictionary.
        approval_handler: Optional callback function prompting an operator or simulating input.

    Returns:
        FirewallDecision (ALLOW if safe/approved, BLOCK if rejected, APPROVAL_REQUIRED if unhandled).
    """
    t0 = time.perf_counter()

    if not is_high_risk_operation(context, policy=policy):
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return FirewallDecision(
            verdict=Verdict.ALLOW,
            reason=f"Tool '{context.tool_name}' is not classified as high-risk.",
            layer="L5",
            latency_ms=elapsed_ms,
        )

    # High-risk operation detected
    if approval_handler is not None:
        try:
            approved = approval_handler(context)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return FirewallDecision(
                verdict=Verdict.BLOCK,
                reason=f"Human approval handler encountered an error: {str(exc)}",
                layer="L5",
                latency_ms=elapsed_ms,
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if approved:
            return FirewallDecision(
                verdict=Verdict.ALLOW,
                reason=f"High-risk operation '{context.tool_name}' approved by operator.",
                layer="L5",
                latency_ms=elapsed_ms,
            )
        else:
            return FirewallDecision(
                verdict=Verdict.BLOCK,
                reason=f"High-risk operation '{context.tool_name}' rejected by operator.",
                layer="L5",
                latency_ms=elapsed_ms,
            )

    # No handler supplied; request cannot proceed without explicit operator sign-off
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return FirewallDecision(
        verdict=Verdict.APPROVAL_REQUIRED,
        reason=(
            f"Tool '{context.tool_name}' is classified as high-risk and requires "
            f"explicit human-in-the-loop approval before execution."
        ),
        layer="L5",
        latency_ms=elapsed_ms,
    )
