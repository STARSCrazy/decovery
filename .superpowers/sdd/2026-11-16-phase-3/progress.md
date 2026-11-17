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

## Continuation (2026-11-17, Codex)

- Owner override: Codex is the sole writer after duplicate sessions stopped; their correct uncommitted changes were handed over. Commit trailer is `Co-Authored-By: Codex <noreply@openai.com>`. No push/merge, no model driver. The current owner's explicit gates override older spike authorization: Task 8 step 1, Task 9 step 5, Task 13 step 6, Task 14 decision 5, Task 15 step 2.
- Task 3 ruling: only identical has distance zero; a non-identical result with zero differing instructions ranks at distance one, while raw metrics and history text retain zero. A judged identical search clears parking without spending an own attempt. Cost if wrong: zero-blocker and one-instruction differences tie in ranking.
- Task 3 review: `.superpowers/sdd/2026-11-16-phase-3/task-3-review.md`; four Important findings fixed with RED-to-GREEN coverage (three facade regressions, three core regressions including the carried bench-actor fix). No Critical finding. Full validation blocked: `shutdown_of_a_hung_plugin_kills_its_workers` fails because Windows `tasklist` returns Access denied; a focused rerun reproduces it. An isolated worker diagnosis also showed `taskkill /T /F /PID <owned worker>` denied, while `Get-Process` sees that worker. Test assertions were retained. Coordinator was asked to restore process access or provide external validation. Formatting and Clippy passed.
- Task 4 ruling (P2): port `eigene_fassung` literally: any nonempty transform other than `hand`, including `bauen`, is automatic (`variant`). The legacy dataclass documents empty transform as the build origin. This binding preflight rule takes precedence over the brief's `bauen -> build` shorthand. Cost if wrong: a historical explicitly labelled `bauen` attempt does not spend own budget.
- Task 4 ruling (B/T4): imported Decomp results remain evidence (`verdict = None`, `extra.decomp_result`); an unjudged imported identical result cannot have distance zero or clear native parking. Hash algorithm/version is preserved as `decomp-sha256[-text-v2]:<hex>`. Local timestamps use the current machine UTC offset at migration and retain raw time and offset in extras (historical DST can differ, as accepted in the prior ruling).
- Task 4: implementation ready, uncommitted; report `task-4-report.md`. Core 112/112 and CLI 1/1 public tests pass (private parity ignored because `DECOVERY_LOCAL_WORKSPACE` is unset). Final serial workspace check: 613 passed, 1 failed, 17 ignored; only failure is the unchanged Windows worker cleanup test under denied process access. Formatting and Clippy pass. Earlier overlapping-Cargo doctest artifacts disappeared in the final serial run. Task 5 has not started.
- Task 3/4 commit blocker: `git apply --cached` failed before any index change with `Unable to create D:/Entwicklung/decovery/.git/worktrees/phase-3-build/index.lock: Permission denied`, despite the coordinator's writable-root update. No commits created; HEAD remains `486beb8`. Both environment blockers were reported to the coordinator. Restore access, rerun full checks, commit Task 3 fixes/review and its separate progress line, then Task 4 implementation/report and its separate progress line. Resume Task 5 afterward. No owner/model-spending gate reached.

## Coordinator handoff update

Owner/coordinator confirmed external full-suite validation and committed Task 3 fixes as `af0f35d` and Task 4 as `a8edb28`; `4c571e9` removed accidentally committed build output. Those confirmations supersede the earlier uncommitted/blocker status above. Latest owner rule: do not attempt staging/commits in this sandbox; coordinator commits. Put build output/logs only in ignored `target/`. Per task, record exact files and a proposed commit message here. The unchanged Windows worker-cleanup failure may be recorded without stopping continuation.

## Task 5 — ready for coordinator commit

Status: DONE_WITH_CONCERNS, uncommitted. Report: `task-5-report.md`. Task 6 has not started; stopping at the remaining context budget after finishing this task and its verification. No owner/model-spending gate reached; no model driver run.

Implemented suite/default/task models, schema and isolated native/legacy task copies. Native identical verdicts are required. All archives are excluded (P7); ancillary solution text/hashes are redacted; targets/tool paths resolve to originals; target records, objects, history and generated/cache leak channels are excluded. Typed address matching, source/destination protection, effective ancestor checks, redirected Ghidra resources and safe cleanup have regression coverage. The bridge's explicit-link fix also preserves its linked-destination protection.

Rulings: use the binding P7 whole-archive exclusion; redact copied auxiliary text/structured string values rather than copy hidden definitions; reject leaking linked resources without modifying their targets. A generated stub/provider start point may equal a trivial solution, while surrounding copied text is still sanitized. P13 task-key/repeat parent isolation remains mandatory in Task 6; P14 checks run on its effective `into`; P15 adds no dead exemplar hook. Cost/tradeoff: reduced quoted context in task copies and absent historical archive payloads; originals are unchanged. These choices are described in `task-5-report.md`.

Verification: Task 5 Rust tests 15/15 pass; Python explicit-project-link regressions 2/2 pass; formatting and Clippy pass. Full Rust suite: **628 passed, 1 failed, 17 ignored**, only the accepted Windows worker-cleanup access failure. Full legacy Python suite: **32 run, 30 pass, 1 error, 1 skip**; the existing changed-source concurrency test misses reply 2. Focused reproduction takes 66.438 s; a separate process using the committed resolver reproduces in 66.435 s (`target/task-5-baseline-probe.log`). The unchanged denied tree-kill path's two 30 s waits exceed the harness's 60 s reply wait. Validate that Python suite outside the sandbox before commit. No tests were disabled or weakened. Build/test artifacts are only under `target/` and must not be staged.

Exact task files (including SDD records; the report is ignored and needs explicit force-add by coordinator):

- `Cargo.toml`
- `Cargo.lock`
- `crates/decovery-bench/Cargo.toml`
- `crates/decovery-bench/src/lib.rs`
- `crates/decovery-bench/src/suite.rs`
- `crates/decovery-bench/src/copy.rs`
- `crates/decovery-bench/src/legacy_view.rs`
- `crates/decovery-bench/tests/copy_synthetic.rs`
- `schemas/bench-suite.schema.json`
- `docs/design/0001-decovery-design.md`
- `plugins/decomp-legacy/decovery_decomp_legacy/shadow.py`
- `plugins/decomp-legacy/tests/test_plugin.py`
- `.superpowers/sdd/2026-11-16-phase-3/task-5-report.md`
- `.superpowers/sdd/2026-11-16-phase-3/progress.md`

Proposed commit message:

```text
feat(bench): suites and solution-free task copies

Add isolated native and legacy task views with checked start points,
artifact exclusions, source protection and streamed leak verification.
Preserve explicit Ghidra aliases so linked destinations remain protected.

Co-Authored-By: Codex <noreply@openai.com>
```
Task 6: implemented on 796e193 as `feat(bench): driver contract, limits and the bench run (task 6)` (DONE_WITH_CONCERNS: schema rewritten, fake-runner variant fix, call-limit exit, `bench run` CLI, ADR 0009; P19 left to Task 11; workspace 642 passed / 17 ignored). NOT YET REVIEWED.
Task 7: implemented (commit 'feat(bench): run report and compare'): stats (Wilson, Newcombe, bootstrap), report/compare with text and JSON, CLI `bench report|compare`; ruling: differences are B minus A, paired bootstrap when task sets match, not-run/quota left out; workspace tests all green. NOT YET REVIEWED.
Task 6+7 review: 0 Critical, 1 Important fixed (harness build ignored exit status -> stale verdict), 7 Minor listed; see task-6-7-review.md.
