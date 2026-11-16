# Threat Model

## Target Assets
- **Confidential Customer Data**: PII records, financial history, and canary SSNs (`900-00-xxxx`).
- **Database Integrity**: SQLite schemas, business tables, transaction history, and indexes.
- **Resource Budgets**: Token consumption limits, computation quotas, and rate limits.
- **Downstream Tool Access**: File export paths, outbound email dispatchers, and shell execution.

## Attacker Goals
- **Data Exfiltration**: Unauthorized dumping or leaking of canary PII and customer records.
- **Destructive SQL Execution**: Executing `DROP`, `DELETE`, `UPDATE`, or `ALTER` statements.
- **Prompt Injection & Jailbreaking**: Tricking agent or LLM judge into bypassing safety filters.
- **Denial of Service & Resource Depletion**: Exhausting token budgets, row quotas, and rate limits.
- **Side-Channel Evasion**: Using SQL comments, dialect idiosyncrasies, or multi-statement injections.

## Attack Surface
- **Tool Call Arguments**: Arbitrary SQL strings passed to database querying tools.
- **Agent Prompts**: Direct and indirect prompt injection through user inputs or untrusted database content.
- **Downstream Result Payloads**: Data returns containing unsanitized sensitive strings or canary tokens.
- **Approval Gate Interactions**: Spoofing human approval signals or coercing bypass parameters.

## Scope
- **In-Scope**:
  - Malicious SQL AST manipulation and injection.
  - Exfiltration of canary PII patterns via tool outputs.
  - High-frequency tool flooding and query budget exhaustion.
  - Multi-turn adversarial prompt injections via worker agent.
  - Bypassing L1-L4 automated layers.
- **Out-of-Scope**:
  - Network-level eavesdropping or TLS man-in-the-middle on underlying OS sockets.
  - Compromise of host Python interpreter or operating system kernel.
  - Direct physical tampering with the SQLite database file on disk.
  - Compromised human operators approving malicious queries in Layer 5.

## Vulnerability Tracking
- TODO: Enumerate discovered attack vectors during adversarial testing on Day 6.
- TODO: Calibrate threat matrix against full 200 benchmark evaluation cases on Day 8.

