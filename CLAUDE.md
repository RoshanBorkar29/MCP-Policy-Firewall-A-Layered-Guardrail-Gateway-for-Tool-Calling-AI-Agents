# Assistant Guidelines for MCP Policy Firewall

This repository has strict development rules and architectural invariants that every AI assistant and developer must observe.

## Repository Invariants and Rules

1. **Check Decisions and Progress First**: Read the root `DECISIONS.md`, `PROGRESS.md`, and the `decisions.md` of the folder you are editing BEFORE writing code.
2. **Document Every Design Decision**: After making any design choice, append a row to that folder's `decisions.md` log (and to root `DECISIONS.md` if it affects multiple folders).
3. **Keep Progress Updated**: After finishing a task, update `PROGRESS.md`.
4. **No Hardcoded Policies**: Never hardcode policy values or thresholds. Always read them from `firewall/policy.yaml`.
5. **Enforce Defense-in-Depth for Healers**: The self-healer must never call downstream directly; all rewritten queries must re-enter the full firewall pipeline.
6. **Human-Only Ground Truth**: Never use an LLM to label ground truth. All test case labels must be verified by humans.
7. **Protect Held-Out Integrity**: Never tune prompts, policies, or heuristics on the held-out dataset (30% split). The held-out set is run only once on Day 9.
8. **Deterministic LLM Calls**: Fix `temperature=0` for all LLM calls (worker, attacker, healer, and Layer 4 judge).
9. **Minimal Dependencies**: Keep code minimal and readable. No UI components. Do not add external dependencies without logging the rationale in `DECISIONS.md`.
10. **Test and Eval Coverage**: Every function or change that alters firewall behavior needs a matching unit test or eval case.
11. **Commit Message Format**: Commit messages must follow the convention `day-N: short description` (e.g., `day-0: repo skeleton and documentation`).
