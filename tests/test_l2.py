"""Unit test suite for Layer 2 PII detection, masking functions, and canary pattern redaction.
Inputs: Sample data payloads containing real/canary PII. Outputs: Pytest test assertion results.
Build plan: Day 3.
"""

from __future__ import annotations

import json
import pytest

from firewall.context import Verdict
from firewall.layers.l2_pii import mask_pii


# --- 1. Canary SSN Redaction Tests ---


def test_l2_canary_ssn_masked_in_plain_text():
    raw = "The customer's canary SSN is 900-00-0042 in our records."
    decision, sanitized = mask_pii(raw)

    assert decision.verdict == Verdict.MODIFY
    assert decision.layer == "L2"
    assert "canary_ssn" in decision.reason
    assert "[REDACTED_CANARY_SSN]" in sanitized
    assert "900-00-0042" not in sanitized


def test_l2_canary_priority_over_standard_ssn():
    # 900-00-xxxx also matches standard SSN regex (\d{3}-\d{2}-\d{4})
    # It must be masked as CANARY, not generic SSN
    raw = "Canary token: 900-00-9999"
    decision, sanitized = mask_pii(raw)

    assert decision.verdict == Verdict.MODIFY
    assert "[REDACTED_CANARY_SSN]" in sanitized
    assert "[REDACTED_SSN]" not in sanitized


# --- 2. Standard PII Masking Tests ---


def test_l2_standard_ssn_masked():
    raw = "Real SSN found: 123-45-6789."
    decision, sanitized = mask_pii(raw)

    assert decision.verdict == Verdict.MODIFY
    assert "[REDACTED_SSN]" in sanitized
    assert "123-45-6789" not in sanitized


def test_l2_email_masked():
    raw = "Please contact alice.smith@example.org for verification."
    decision, sanitized = mask_pii(raw)

    assert decision.verdict == Verdict.MODIFY
    assert "[REDACTED_EMAIL]" in sanitized
    assert "alice.smith@example.org" not in sanitized


def test_l2_phone_masked():
    raw = "Call customer at 555-123-4567 or (800) 555-0199 today."
    decision, sanitized = mask_pii(raw)

    assert decision.verdict == Verdict.MODIFY
    assert "[REDACTED_PHONE]" in sanitized
    assert "555-123-4567" not in sanitized


def test_l2_credit_card_masked():
    raw = "Card number on file is 4111 2222 3333 4444."
    decision, sanitized = mask_pii(raw)

    assert decision.verdict == Verdict.MODIFY
    assert "[REDACTED_CC]" in sanitized
    assert "4111 2222 3333 4444" not in sanitized


def test_l2_multiple_pii_types_in_one_string():
    raw = "User bob@test.com with SSN 900-00-0005 called from 555-000-1111."
    decision, sanitized = mask_pii(raw)

    assert decision.verdict == Verdict.MODIFY
    assert "[REDACTED_EMAIL]" in sanitized
    assert "[REDACTED_CANARY_SSN]" in sanitized
    assert "[REDACTED_PHONE]" in sanitized


# --- 3. Structured JSON Payloads (MCP Tool Returns) ---


def test_l2_json_payload_redacted_and_valid():
    data = {
        "rows": [
            {
                "id": 1,
                "name": "Patrick Sanchez",
                "ssn": "900-00-0001",
                "email": "patrick@example.com",
            },
            {
                "id": 2,
                "name": "Kimberly Dudley",
                "ssn": "900-00-0002",
                "email": "kimberly@example.com",
            },
        ],
        "row_count": 2,
    }
    raw_json = json.dumps(data)
    decision, sanitized = mask_pii(raw_json)

    assert decision.verdict == Verdict.MODIFY
    parsed = json.loads(sanitized)

    # Check structural preservation
    assert parsed["row_count"] == 2
    assert len(parsed["rows"]) == 2
    assert parsed["rows"][0]["id"] == 1
    assert parsed["rows"][0]["name"] == "Patrick Sanchez"

    # Check values redacted
    assert parsed["rows"][0]["ssn"] == "[REDACTED_CANARY_SSN]"
    assert parsed["rows"][0]["email"] == "[REDACTED_EMAIL]"
    assert parsed["rows"][1]["ssn"] == "[REDACTED_CANARY_SSN]"
    assert parsed["rows"][1]["email"] == "[REDACTED_EMAIL]"


def test_l2_json_nested_lists():
    payload = {"data": [["clean", "900-00-0010"], ["john@test.com", 123]]}
    decision, sanitized = mask_pii(json.dumps(payload))

    assert decision.verdict == Verdict.MODIFY
    parsed = json.loads(sanitized)
    assert parsed["data"][0][1] == "[REDACTED_CANARY_SSN]"
    assert parsed["data"][1][0] == "[REDACTED_EMAIL]"
    assert parsed["data"][1][1] == 123


# --- 4. Benign & Edge Case Payloads ---


def test_l2_benign_text_unmodified():
    raw = "Total balance across accounts is 15420.50 with status active."
    decision, sanitized = mask_pii(raw)

    assert decision.verdict == Verdict.ALLOW
    assert sanitized == raw


def test_l2_benign_json_unmodified():
    data = {"status": "ok", "count": 100, "tables": ["customers", "accounts"]}
    raw_json = json.dumps(data)
    decision, sanitized = mask_pii(raw_json)

    assert decision.verdict == Verdict.ALLOW
    assert sanitized == raw_json


def test_l2_empty_payload():
    decision, sanitized = mask_pii("")
    assert decision.verdict == Verdict.ALLOW
    assert sanitized == ""


def test_l2_custom_policy_override():
    custom_policy = {
        "layer_2": {
            "patterns": [
                {
                    "name": "secret_code",
                    "regex": r"\bCONFIDENTIAL-\d+\b",
                    "mask": "[MASKED_CODE]",
                }
            ]
        }
    }
    raw = "Access code is CONFIDENTIAL-98765."
    decision, sanitized = mask_pii(raw, policy=custom_policy)

    assert decision.verdict == Verdict.MODIFY
    assert "[MASKED_CODE]" in sanitized
    assert "CONFIDENTIAL-98765" not in sanitized
