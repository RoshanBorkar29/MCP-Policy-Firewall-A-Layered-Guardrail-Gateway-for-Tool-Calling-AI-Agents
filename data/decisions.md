# Decisions: data

## Purpose
Responsible for generating and storing synthetic test databases, canary records, and seed data. It provides realistic schemas and canary PII for firewall verification without using real-world sensitive data.

## Planned contents
- `make_db.py`: Script to generate SQLite database with mock business records and canary PII.
- `.gitkeep`: Retains data directory in git tracking while excluding raw SQLite databases.

## Constraints
- Synthetic data only; no real PII allowed under any circumstances.
- All SSNs must use designated canary prefixes (`900-00-xxxx`).
- Generated SQLite databases (`*.db`) must be gitignored and never committed.

## Decision log
| Date | Decision | Alternatives considered | Reason | Status |
|------|----------|-------------------------|--------|--------|
| 2026-11-16 | Relational schema (customers, accounts, transactions) with deterministic Faker seed (42) and canary SSNs (900-00-xxxx) | Single flat customer table, static CSV mocks, non-deterministic random seeding | Models real-world relational SQL queries while guaranteeing reproducible test state and deterministic canary leakage detection. | Accepted |

## Open questions
- (none yet)

