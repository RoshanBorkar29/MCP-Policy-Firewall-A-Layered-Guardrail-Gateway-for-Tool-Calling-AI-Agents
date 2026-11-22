"""Self-healing agent repairing blocked or rejected queries to conform with firewall policy.
Inputs: Blocked tool request, error feedback, and policy rules. Outputs: Compliant rewritten tool call.
Build plan: Day 7.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Callable

from firewall.context import FirewallDecision, RequestContext, Verdict, load_policy
from firewall.pipeline import FirewallPipeline

ROOT_DIR = Path(__file__).resolve().parent.parent
PROMPT_PATH = ROOT_DIR / "agents" / "prompts" / "healer.md"
ENV_PATH = ROOT_DIR / ".env"


def _load_env() -> dict[str, str]:
    """Load key-value pairs from .env without overriding existing environment variables."""
    env_vars: dict[str, str] = {}
    if ENV_PATH.is_file():
        for raw_line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env_vars[key.strip()] = value.strip().strip('"').strip("'")

    for key, value in env_vars.items():
        os.environ.setdefault(key, value)
    return env_vars


def load_healer_prompt(prompt_path: Path | str | None = None) -> str:
    """Reads the self-healer system prompt from disk."""
    target = Path(prompt_path or PROMPT_PATH).resolve()
    if target.is_file():
        return target.read_text(encoding="utf-8")
    return (
        "You are an expert remediation agent. Analyze blocked tool calls and produce compliant "
        "rewrites that conform to security policies. Respond strictly with JSON: "
        '{"can_heal": true|false, "tool_name": "...", "modified_args": {...}, "explanation": "..."}'
    )


def heal_tool_call(
    context: RequestContext,
    decision: FirewallDecision,
    policy: dict[str, Any] | None = None,
    client: Any | None = None,
    prompt_path: Path | str | None = None,
) -> tuple[bool, RequestContext | None, str]:
    """Generates a policy-compliant rewrite for a blocked tool call using the healer LLM.

    Args:
        context: The original RequestContext that was blocked.
        decision: The blocking FirewallDecision detailing the layer and violation reason.
        policy: Optional policy dictionary.
        client: Optional pre-initialized Groq client or test mock.
        prompt_path: Optional custom path to healer system prompt.

    Returns:
        Tuple of (can_heal: bool, repaired_context: RequestContext | None, explanation: str).
    """
    _load_env()
    api_key = os.environ.get("GROQ_API_KEY")
    cfg = policy or load_policy()
    model_name = cfg.get("layer_4", {}).get("model", "openai/gpt-oss-120b")

    if client is None:
        if not api_key:
            raise RuntimeError("GROQ_API_KEY is not set in environment or .env")
        from groq import Groq

        client = Groq(api_key=api_key)

    system_prompt = load_healer_prompt(prompt_path)

    payload = {
        "original_tool": context.tool_name,
        "original_arguments": context.arguments,
        "blocked_by_layer": decision.layer,
        "violation_reason": decision.reason,
        "agent_name": context.agent_name,
        "user_prompt": context.metadata.get("user_prompt", ""),
    }

    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": f"Blocked Tool Call Information:\n{json.dumps(payload, indent=2)}",
                },
            ],
            temperature=0,
            response_format={"type": "json_object"},
        )
        raw_content = response.choices[0].message.content.strip()
        parsed = json.loads(raw_content)

        can_heal = bool(parsed.get("can_heal", False))
        explanation = str(parsed.get("explanation", "No explanation provided."))

        if not can_heal:
            return False, None, explanation

        repaired_tool = parsed.get("tool_name", context.tool_name)
        repaired_args = parsed.get("modified_args", context.arguments)

        repaired_context = RequestContext(
            tool_name=repaired_tool,
            arguments=repaired_args,
            agent_name="healer",
            session_id=context.session_id,
            metadata={
                **context.metadata,
                "is_healed": True,
                "original_tool": context.tool_name,
                "original_arguments": context.arguments,
                "healing_explanation": explanation,
            },
        )
        return True, repaired_context, explanation

    except Exception as exc:
        return False, None, f"Self-healing generation failed: {type(exc).__name__}: {str(exc)}"


def heal_and_execute(
    context: RequestContext,
    pipeline: FirewallPipeline,
    downstream_executor: Callable[[str, dict[str, Any]], str] | None = None,
    client: Any | None = None,
    max_attempts: int = 2,
) -> dict[str, Any]:
    """Full remediation workflow: inspects initial call, rewrites upon block, and re-enters pipeline.

    MANDATORY CONSTRAINT:
    Rewritten queries MUST re-enter the full firewall pipeline and never bypass it.

    Args:
        context: RequestContext to evaluate and potentially remediate.
        pipeline: FirewallPipeline instance enforcing security layers.
        downstream_executor: Optional tool execution function for allowed/repaired calls.
        client: Optional Groq client or test mock for the healer agent.
        max_attempts: Maximum healing cycles before failing.

    Returns:
        Dictionary detailing healing status, attempts, decision, and output.
    """
    # 1. Initial firewall inspection
    initial_decision = pipeline.evaluate_request(context)
    if initial_decision.is_allowed:
        raw_output = ""
        sanitized_output = ""
        post_dec = initial_decision
        if downstream_executor:
            raw_output = downstream_executor(context.tool_name, context.arguments)
            post_dec, sanitized_output = pipeline.evaluate_response(context, raw_output)
        return {
            "status": "allowed",
            "attempts": 0,
            "decision": post_dec.to_dict(),
            "output": sanitized_output if downstream_executor else None,
        }

    # 2. Tool call was blocked; initiate remediation loop
    current_context = context
    current_decision = initial_decision

    for attempt in range(1, max_attempts + 1):
        can_heal, repaired_ctx, explanation = heal_tool_call(
            context=current_context,
            decision=current_decision,
            policy=pipeline.policy,
            client=client,
        )

        if not can_heal or repaired_ctx is None:
            return {
                "status": "unhealable",
                "attempts": attempt,
                "reason": explanation,
                "decision": current_decision.to_dict(),
            }

        # 3. RE-ENTER THE FULL FIREWALL PIPELINE (Never bypass!)
        new_decision = pipeline.evaluate_request(repaired_ctx)

        if new_decision.is_allowed:
            # Successfully healed and passed all active guardrail layers
            raw_output = ""
            sanitized_output = ""
            post_dec = new_decision
            if downstream_executor:
                raw_output = downstream_executor(repaired_ctx.tool_name, repaired_ctx.arguments)
                post_dec, sanitized_output = pipeline.evaluate_response(repaired_ctx, raw_output)

            return {
                "status": "healed",
                "attempts": attempt,
                "explanation": explanation,
                "repaired_tool": repaired_ctx.tool_name,
                "repaired_args": repaired_ctx.arguments,
                "decision": post_dec.to_dict(),
                "output": sanitized_output if downstream_executor else None,
            }

        # Repaired query was still blocked by the firewall; try next attempt
        current_decision = new_decision
        current_context = repaired_ctx

    return {
        "status": "failed",
        "attempts": max_attempts,
        "reason": f"Maximum healing attempts ({max_attempts}) reached without satisfying policy.",
        "decision": current_decision.to_dict(),
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the self-healing query agent.")
    parser.add_argument(
        "--query",
        type=str,
        default="SELECT * FROM customers;",
        help="Blocked query to test self-healing remediation on.",
    )
    parser.add_argument(
        "--tool",
        type=str,
        default="execute_sql",
        help="Tool name being invoked.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    ctx = RequestContext(tool_name=args.tool, arguments={"query": args.query})
    p = FirewallPipeline()
    res = heal_and_execute(ctx, p)
    print(json.dumps(res, indent=2))
