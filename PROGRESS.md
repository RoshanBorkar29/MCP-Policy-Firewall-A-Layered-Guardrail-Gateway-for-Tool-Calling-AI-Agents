# Project Progress: MCP Policy Firewall

## Current status
- **Active Day**: Day 0 - Repository skeleton and documentation setup.
- **Phase**: Setup and initial project scaffolding.

## 10-Day Build Plan Checklist

- [ ] **Day 0: Setup**
  - [x] Repository skeleton and directory structure
  - [x] Architecture decisions log (`DECISIONS.md` and per-folder `decisions.md`)
  - [x] Developer guide and assistant instructions (`CLAUDE.md`)
  - [x] Environment configuration (`.env.example`, `.gitignore`, `requirements.txt`)
  - [x] Documentation stubs and prompt templates
- [ ] **Day 1: Synthetic DB, Downstream Server, Worker Agent**
  - [ ] Implement synthetic database generator (`data/make_db.py`) with canary PII
  - [ ] Build downstream FastMCP server (`downstream/sql_server.py`)
  - [ ] Implement worker agent (`agents/worker.py` and `agents/prompts/worker.md`) without firewall
- [ ] **Day 2: Proxy, Pipeline, Audit Log, Layer 1, Unit Tests**
  - [ ] Build core FastMCP proxy gateway (`firewall/proxy.py`)
  - [ ] Implement guardrail execution pipeline (`firewall/pipeline.py`)
  - [ ] Create structured audit logging service (`firewall/audit.py`, `firewall/context.py`)
  - [ ] Implement Layer 1 SQL AST rules using sqlglot (`firewall/layers/l1_sql_rules.py`)
  - [ ] Write 30 unit tests (`tests/test_l1.py`, `tests/test_pipeline.py`)
- [ ] **Day 3: Policy Configuration, Layers 2 and 3**
  - [ ] Define declarative policy rules (`firewall/policy.yaml`)
  - [ ] Implement Layer 2 PII masking and canary detection (`firewall/layers/l2_pii.py`)
  - [ ] Implement Layer 3 rate, row, and cost limiters (`firewall/layers/l3_limits.py`)
  - [ ] Unit tests for L2 and L3 (`tests/test_l2.py`, `tests/test_l3.py`)
- [ ] **Day 4: Evaluation Harness (Direct Mode)**
  - [ ] Implement evaluation runner in direct mode (`eval/run.py`)
  - [ ] Build metric calculations (`eval/metrics.py`) and canary oracles (`eval/oracles.py`)
  - [ ] Build reporting utility (`eval/report.py`)
  - [ ] Define ablation configurations (`eval/configs.yaml`)
  - [ ] Unit tests for oracles (`tests/test_oracles.py`)
- [ ] **Day 5: Layer 4 Judge, Layer 5 Approval Gate**
  - [ ] Implement Layer 4 LLM judge (`firewall/layers/l4_judge.py` and `agents/prompts/judge.md`)
  - [ ] Implement Layer 5 human approval gate (`firewall/layers/l5_approval.py`)
  - [ ] Integration testing with interactive approval simulation
- [ ] **Day 6: Attacker Agent, Injection Cases, End-to-End Mode**
  - [ ] Build adversarial attacker agent (`agents/attacker.py` and `agents/prompts/attacker.md`)
  - [ ] Assemble test cases (`safe.jsonl`, `dangerous.jsonl`, `injection.jsonl`, `edge.jsonl`)
  - [ ] Support end-to-end evaluation mode with active LLM calling
- [ ] **Day 7: Self-Healer Agent**
  - [ ] Implement self-healing agent (`agents/healer.py` and `agents/prompts/healer.md`)
  - [ ] Assemble self-healing test dataset (`eval/cases/healer.jsonl`)
  - [ ] Validate full re-entry into firewall pipeline on query rewriting
- [ ] **Day 8: Full 200 Cases, Ablation Run**
  - [ ] Finalize complete 200-case evaluation dataset (70% dev split)
  - [ ] Execute full ablation benchmark across configurations C0 through C5
  - [ ] Collect metrics: block rate, false positive rate, PII leak rate, attack success rate (ASR)
- [ ] **Day 9: Optimization, Held-Out Validation, Known Bypasses**
  - [ ] Optimize latency and false positive edge cases on dev set
  - [ ] Execute 30% held-out test suite strictly once
  - [ ] Document discovered bypasses and failure modes (`docs/known_bypasses.md`)
- [ ] **Day 10: README, Demo, Tag v1.0**
  - [ ] Finalize comprehensive documentation and quickstart instructions in `README.md`
  - [ ] Prepare interactive end-to-end demonstration script
  - [ ] Tag release `v1.0`

## Blockers / notes
- None currently. Initial repository setup and Day 0 tasks underway.

