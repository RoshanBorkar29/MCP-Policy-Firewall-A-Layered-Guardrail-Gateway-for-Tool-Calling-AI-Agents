# Decisions: results

## Purpose
Stores evaluation run outputs, benchmark metrics, audit logs, and ablation analysis artifacts. It maintains historical outputs from benchmark runs and experiments.

## Planned contents
- `.gitkeep`: Tracks directory in version control while ignoring generated run artifacts.

## Constraints
- No checked-in raw benchmark run outputs, databases, or sensitive audit logs.
- All evaluation JSON metrics (`results/*.json`), outbox logs, and audit trails must be gitignored.
- Only summary documentation or curated tables should be committed.

## Decision log
| Date | Decision | Alternatives considered | Reason | Status |
|------|----------|-------------------------|--------|--------|
|      |          |                         |        |        |

## Open questions
- (none yet)
