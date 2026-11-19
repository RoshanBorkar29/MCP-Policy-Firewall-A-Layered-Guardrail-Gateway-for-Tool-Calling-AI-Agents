"""Request context management tracking metadata, user permissions, and state across firewall layers.
Inputs: Incoming tool call headers and parameters. Outputs: Immutable RequestContext instances.
Build plan: Day 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Firewall verdict classifications."""

    ALLOW = "ALLOW"
    MODIFY = "MODIFY"
    BLOCK = "BLOCK"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


@dataclass
class RequestContext:
    """Encapsulates context and metadata for an intercepted tool call."""

    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    agent_name: str = "worker"
    session_id: str = "default"
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def get_argument(self, key: str, default: Any = None) -> Any:
        """Helper to get a tool argument safely."""
        return self.arguments.get(key, default)


@dataclass
class FirewallDecision:
    """Result of an evaluation by an individual layer or the pipeline."""

    verdict: Verdict
    reason: str = ""
    layer: str = "PIPELINE"
    modified_args: dict[str, Any] | None = None
    latency_ms: float = 0.0

    @property
    def is_blocked(self) -> bool:
        """Check if the decision blocks execution."""
        return self.verdict == Verdict.BLOCK

    @property
    def is_allowed(self) -> bool:
        """Check if execution may proceed (either untouched or modified)."""
        return self.verdict in (Verdict.ALLOW, Verdict.MODIFY)

    def to_dict(self) -> dict[str, Any]:
        """Convert decision to a dictionary representation."""
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "layer": self.layer,
            "modified_args": self.modified_args,
            "latency_ms": round(self.latency_ms, 3),
        }
