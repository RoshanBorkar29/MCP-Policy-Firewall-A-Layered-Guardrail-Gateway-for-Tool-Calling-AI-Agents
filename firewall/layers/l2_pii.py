"""Layer 2 guardrail detecting and masking personally identifiable information (PII) and canary SSNs.
Inputs: Query text and tool return payloads. Outputs: Sanitized payload or MODIFY/BLOCK decision.
Build plan: Day 3.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from firewall.context import FirewallDecision, Verdict, load_policy

# Default patterns if policy.yaml is missing or incomplete
DEFAULT_PATTERNS = [
    {
        "name": "canary_ssn",
        "regex": r"\b900-00-\d{4}\b",
        "mask": "[REDACTED_CANARY_SSN]",
    },
    {
        "name": "standard_ssn",
        "regex": r"\b\d{3}-\d{2}-\d{4}\b",
        "mask": "[REDACTED_SSN]",
    },
    {
        "name": "email",
        "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "mask": "[REDACTED_EMAIL]",
    },
    {
        "name": "phone",
        "regex": r"\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b",
        "mask": "[REDACTED_PHONE]",
    },
    {
        "name": "credit_card",
        "regex": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        "mask": "[REDACTED_CC]",
    },
]


def _compile_patterns(
    layer_2_cfg: dict[str, Any],
) -> list[tuple[str, re.Pattern, str]]:
    """Compiles regex patterns from policy configuration into compiled tuples."""
    pattern_defs = layer_2_cfg.get("patterns", DEFAULT_PATTERNS)
    compiled: list[tuple[str, re.Pattern, str]] = []

    for item in pattern_defs:
        name = item.get("name", "pii")
        raw_regex = item.get("regex", "")
        mask = item.get("mask", "[REDACTED]")
        if raw_regex:
            compiled.append((name, re.compile(raw_regex, re.IGNORECASE), mask))

    return compiled


def _redact_text(
    text: str, compiled_patterns: list[tuple[str, re.Pattern, str]]
) -> tuple[str, list[str]]:
    """Applies compiled regex patterns to a single string, returning sanitized text and detected types."""
    detected: list[str] = []
    sanitized = text

    for name, pattern, mask in compiled_patterns:
        if pattern.search(sanitized):
            detected.append(name)
            sanitized = pattern.sub(mask, sanitized)

    return sanitized, detected


def _redact_structure(
    node: Any,
    compiled_patterns: list[tuple[str, re.Pattern, str]],
    detected: list[str],
) -> Any:
    """Recursively walks nested JSON data structures and redacts matching strings."""
    if isinstance(node, str):
        sanitized_str, new_detected = _redact_text(node, compiled_patterns)
        detected.extend(new_detected)
        return sanitized_str
    if isinstance(node, list):
        return [
            _redact_structure(item, compiled_patterns, detected) for item in node
        ]
    if isinstance(node, dict):
        return {
            key: _redact_structure(val, compiled_patterns, detected)
            for key, val in node.items()
        }
    return node


def mask_pii(
    raw_payload: str | Any, policy: dict[str, Any] | None = None
) -> tuple[FirewallDecision, str]:
    """Scans and masks PII in tool return outputs or text payloads.

    Supports both JSON payloads (preserving document formatting) and plain strings.
    Canary SSNs (900-00-xxxx) are prioritized and masked with [REDACTED_CANARY_SSN].

    Args:
        raw_payload: The raw string or serializable payload to inspect.
        policy: Optional pre-loaded policy dict. If omitted, loads from policy.yaml.

    Returns:
        Tuple of (FirewallDecision, sanitized_string).
        Decision is MODIFY if PII was redacted, ALLOW otherwise.
    """
    t0 = time.perf_counter()

    cfg = policy or load_policy()
    layer_2_cfg = cfg.get("layer_2", {})
    compiled = _compile_patterns(layer_2_cfg)

    # Coerce input to string if not already
    text_input = (
        raw_payload if isinstance(raw_payload, str) else str(raw_payload)
    )

    detected_types: list[str] = []
    sanitized_output = text_input

    # 1. Try JSON-aware recursive scanning to preserve JSON schema integrity
    try:
        parsed_json = json.loads(text_input)
        sanitized_struct = _redact_structure(
            parsed_json, compiled, detected_types
        )
        if detected_types:
            sanitized_output = json.dumps(sanitized_struct)
    except (json.JSONDecodeError, TypeError):
        # 2. Fallback to direct string substitution for plain text
        sanitized_output, detected_types = _redact_text(text_input, compiled)

    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    if detected_types:
        unique_types = sorted(set(detected_types))
        decision = FirewallDecision(
            verdict=Verdict.MODIFY,
            reason=f"PII detected and redacted: {', '.join(unique_types)}",
            layer="L2",
            latency_ms=elapsed_ms,
        )
        return decision, sanitized_output

    decision = FirewallDecision(
        verdict=Verdict.ALLOW,
        reason="No PII detected in payload.",
        layer="L2",
        latency_ms=elapsed_ms,
    )
    return decision, sanitized_output
