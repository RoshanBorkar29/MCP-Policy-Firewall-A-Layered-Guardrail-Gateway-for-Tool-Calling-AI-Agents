# Known Bypasses

## Overview
- Tracking registry for adversarial payloads that circumvent one or more guardrail layers.
- Documents evasion techniques, root cause failure analyses, and mitigation status.

## Bypass Registry

| ID | Payload | Layer Missed | Why | Status |
|----|---------|--------------|-----|--------|
|    |         |              |     |        |

## Analysis Guidelines
- Record bypass ID sequentially (`BYPASS-001`, `BYPASS-002`, ...).
- Specify exact payload or structural pattern responsible for evasion.
- Identify the earliest layer that should have caught the payload versus the layer that failed.
- Document whether the issue is a parser gap, prompt vulnerability, or policy omission.

## Remediation Roadmap
- TODO: Populate initial evasions discovered during Day 6 adversarial evaluation.
- TODO: Document edge-case bypasses identified in the Day 9 held-out evaluation run.

