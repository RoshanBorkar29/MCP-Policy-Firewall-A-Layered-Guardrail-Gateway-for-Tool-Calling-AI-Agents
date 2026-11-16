# Evaluation Methodology

## Metric Definitions
- **Positive Class**: `BLOCK` (security violation detected and blocked).
- **Negative Class**: `ALLOW` or `MODIFY` (benign execution permitted).
- **Confusion Matrix**:
  - **True Positive (TP)**: Malicious tool call correctly blocked by firewall.
  - **False Positive (FP)**: Safe tool call incorrectly blocked by firewall (false alarm).
  - **False Negative (FN)**: Malicious tool call incorrectly allowed through (breach/miss).
  - **True Negative (TN)**: Safe tool call correctly allowed through.
- **Precision**: $\text{TP} / (\text{TP} + \text{FP})$ — ratio of correctly identified violations.
- **Recall**: $\text{TP} / (\text{TP} + \text{FN})$ — proportion of actual violations caught.
- **False Positive Rate (FPR)**: $\text{FP} / (\text{FP} + \text{TN})$ — disruption to legitimate workflows.
- **Attack Success Rate (ASR)**: $\text{FN} / (\text{Total Malicious Cases})$ — rate at which attacks succeed.
- **PII Leak Rate**: $\text{Leaked Canary Queries} / \text{Total Canary Queries Attempted}$.

## Oracle Definitions
- **Ground Truth Oracle**: Human-labeled gold standard tags for every benchmark test case.
- **Canary Oracle**: Exact substring matching for designated canary SSNs (`900-00-xxxx`) in outputs.
- **State Mutation Oracle**: Pre/post database hashing to detect unauthorized table state changes.
- **Budget Oracle**: Programmatic counter checking against active rate and row limits.

## Ablation Configurations
- **C0 (Baseline)**: Passthrough mode (no firewall layers active).
- **C1 (L1 Only)**: SQL AST rule validation via sqlglot.
- **C2 (L1 + L2)**: SQL AST rules + PII regex detection and masking.
- **C3 (L1 + L2 + L3)**: SQL AST rules + PII masking + rate/budget enforcement.
- **C4 (L1 to L4)**: SQL AST + PII masking + limits + LLM judge evaluation.
- **C5 (L1 to L5 + Healer)**: Full defense (approval gate enabled) + self-healing query repair.

## Dataset Partitioning
- **Total Test Cases**: 200 distinct test cases across 5 categories.
- **Development Split (70%)**: 140 cases used for tuning heuristics, thresholds, and prompts.
- **Held-Out Split (30%)**: 60 cases executed strictly once to validate generalization.
- **Data Contamination Rule**: No layer or prompt tuning permitted on the held-out split.

## Benchmarking Execution
- TODO: Implement direct-call harness running without LLM overhead on Day 4.
- TODO: Implement end-to-end multi-agent evaluation harness on Day 6.
- TODO: Execute held-out benchmark and populate comparative ablation report on Day 9.
