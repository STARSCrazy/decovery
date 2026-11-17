# SDD ledger — plan: docs/plans/2026-11-16-phase-3.md

Worktree: D:\Entwicklung\decovery\.worktrees\phase-3-build, branch phase-3-build (from phase-3-plan; plan PR #13).
Spec: docs/design/0001-decovery-design.md + ADR 0007, 0008 (reachable).

## Owner decisions (2026-11-16)
- Probe suite (Task 9): model Sonnet, max_tokens 400 000 per task, wall 15 min, max_total_tokens 2 500 000.
- Full suite baseline tools = core (no bridge); core+legacy at most a small extra run. Full budget set from probe numbers (owner gate before Task 15 step 2).

## Rulings
- Ruling: Task 8 step 1 (one-task spike) may spend tokens under the probe limits (Sonnet, ≤ 400 000 tokens) — owner agreed to those limits for the probe; the spike is one probe-sized task — if wrong: ≤ 400k tokens spent early.
- Ruling: commit trailer = plan trailer plus the session's `Claude-Session:` line — session attribution rule — cosmetic.
- Stop points (owner): Task 9 step 5 gate, Task 14 decision 5 (throughput criterion), Task 15 step 2 budget; merges/pushes.

## Preflight
(see preflight.md once written)

## Tasks
- Owner 2026-11-16: after phase 3 the next work is Aztec C86 + everything Wizardry 7 needs (ADR 0008 amended in this branch).

## Preflight rulings (2026-11-16)
Table: preflight.md (same dir), 31 findings (8 S, 15 M, 8 L).
- Ruling: adopt every "Proposed ruling" of preflight.md as binding, except the overrides below — the proposals resolve each conflict toward the spec (verdicts only by decovery, ADR 0007 read-only source, ADR 0003 no deps, Global Constraints) — if wrong: rework in the affected task.
- Ruling (P9 override): Task 9 run limit stays 2 500 000 (owner's number, not raised); tasks ordered smallest first; a probe stopped at the run limit is acceptable and reported as such — owner set the limit — if wrong: probe covers fewer than 8 tasks.
- Ruling (P20): Task 13 step 6 (probe re-run) is an owner gate like Task 9 step 5; ask before spending — Global Constraints list no exception for it — if wrong: one extra question.
- Ruling (B/T5 ToolSet id): ids `core` and `core-legacy` (kebab-case per Global), `core+legacy` accepted as alias on input — Global Constraints — cosmetic.
- Ruling (B/T4 time): migrated local times converted with the machine's UTC offset at migration, raw value kept in extra.decomp_time — Global "RFC 3339 UTC" — if wrong: off by DST hour on old records.
- Dispatch rule: every implementer brief is accompanied by the preflight rows for its task (section A rows naming the task, section B row, section C items) — the task-brief script extracts only plan text.
Task 1: dispatched (BASE 521291b, implementer ab8246e90cb7a1506, sonnet)
Task 1: implemented 006d8d2 (DONE_WITH_CONCERNS minor); review dispatched a69c00e7b67f48944 (sonnet)
Task 1: complete (commits 521291b..006d8d2, review clean; 7 Minor noted below)
- Minor notes T1 (carry to Task 3 dispatch): parked() true with limit 0 and no attempts; empty body_hash collapses; lock timeout error has pid 0; producers must always set actor; attempt.schema.json result/verdict enums may lack `other`; Task 3/4 must read [rebuild] attempt_budget.
Task 2: dispatched (BASE 006d8d2, implementer a60e447f49ab7ba5c, sonnet)
Task 2: implemented 505dd60 (DONE_WITH_CONCERNS: meta.file not enforced -> Task 3/4 must set it; no RED run)
Task 2: complete (commits 006d8d2..505dd60, review clean; Minor: canonical JSON relies on serde_json without preserve_order — no byte-form test; rename retries on non-transient errors; orphan .tmp dirs; archive_ids_for O(all))
- Ruling: Global Constraint "schema = 1 on every record" has one accepted exception: the archive manifest uses `format = "decovery-attempt-archive/1"` — Task 2 brief fixed the format — note it in Task 15 docs.
Task 3: dispatched (BASE 505dd60, implementer a619979cd1ea153b6, opus)
- Owner 2026-11-16 evening: stop after running subagents finish; start nothing new. Resume point: Task 3 review (BASE 505dd60) once implementer reported.
Task 3: implemented e1ae436 (DONE_WITH_CONCERNS: per-function archiving on first full build; --apply single record via key skip; default actor `library` -> Task 6 must set bench actor and budget rule check; refused detection via rmcp error prefix; last-line lookup reads whole shard; no CallRecord schema). NOT YET REVIEWED.
STOPPED here on owner's request. Resume: generate review package 505dd60..e1ae436, dispatch Task 3 reviewer, then Task 4.
2026-11-17: branch pushed to GitHub (origin/phase-3-build) with this SDD folder force-added, to continue on another machine. Proposal (not decided by owner): favour Tasks 1-4 and 12-13 for Wizardry 7 speed/cost, bench probe later.
