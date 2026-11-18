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
Task 13: implemented (exemplar index, find similar, show exemplars/source; P15 no hook; perf test ignored + candidate-set assert); workspace 678 passed/18 ignored; step 5 local parity not run (env unset), step 6 owner gate open. NOT YET REVIEWED. Report task-13-report.md.
Task 12+13 review: 0 Critical, 3 Important fixed (index stale on changed range, show source outside budget, R4 test read `bytegleich` instead of `identisch`), 9 Minor listed; changed find_similar assertion judged legitimate; see task-12-13-review.md.

## Pause 2026-11-17 (resume here)
Done and reviewed: Tasks 1-7, 12, 13 (reviews: task-3-review.md, task-6-7-review.md, task-12-13-review.md). Owner chose order: 12/13 before 8-11 (for Wizardry 7); bench probe runs (8 step 1, 9, 13 step 6, 15 step 2) need owner go.
Local tests (env: DECOVERY_LOCAL_WORKSPACE = DECOVERY_DECOMP_WORKSPACE = Decomp ziele/syndicate-1993 (NOT ziele/syndicate), _MZ = ziele/sar, DECOVERY_TARGET_MZ = SAR.EXE, toolchains from the user config, DECOVERY_GOLDEN_DIR, DECOVERY_DECOMP_PYTHON = Decomp .venv). Run them one by one with `-j 2`: the machine ran out of memory twice.
- second_target_identical_functions: passed.
- exemplars_match_decomp_vorbilder (Task 13 step 5, R4): first run invalid (test passed `0x…`, Decomp needs `va:XXXXXXXX`; copy included the huge cache). Test fixed (commit "test(exemplars): …"), NOT yet run successfully — rerun first.
- first_target_identical_functions and all other ignored tests: not yet run.
2026-11-18: exemplars parity ran (46 min, mostly Decomp's Python start per case): top-1 6/20. Root cause R4: iced
prints `jmp short N`, capstone `jmp N`. Fixed in commit "fix(exemplars): drop short/near …" (index schema 2);
quick re-check against the stored Decomp answers: top-1 18/20, top-3 20/20 (the 2 misses: Decomp prints nothing for
begtext and audio_driver_call_b7, probably no function start in its engine). Official rerun: passed (18/20, 20/20) after the test asked for at most 30 (Decomp's preselection).
Codex cannot run the local tests: its sandbox denies reading Decomp's cache directories.
Task 16 (richer Ghidra decompile output) added to the plan, runs after Task 9.
Next: rerun local tests, then try `find similar` on Syndicate (no tokens), then Tasks 8-11, 14, 15. Open: 186 MB build output in branch history (force-push denied by the classifier; owner may run the strip script, needs updating to the new HEAD).

## 2026-11-18 Task 8 step 1
Run 20261118-063344-b04703, second target, one 126-byte C function: solved identical, start distance 57 -> 0, 12 builds, 20 tool calls, 21 turns, 218 s.
Tokens: input 38, output 18 272 (10 399 thinking), cache read 441 429, cache write 43 066. total_cost_usd 0.80 (estimate, costBasis "list"). Model claude-opus-5-5 (no --model), claude 2.1.327.
Isolation held: init offered only 13 mcp__decovery__* tools; only MCP server decovery (with --limits); skills and slash_commands empty; no hooks; apiKeySource "none" (subscription); rate_limit_event 5h 2 %, 7d 11 %.
Notes: init `agents` lists built-in types but the Agent tool is not offered; builtin plugin cc-plugin-agents-md would load an AGENTS.md above the copy (copies stay outside instruction trees). FIELDS all confirmed. Unmapped: rate_limit_event (now mapped: rejected/exhausted -> quota), system/thinking_tokens, output_tokens_details.thinking_tokens, result modelUsage.
Owner decision: per-task cap = estimated cost, default 3 USD (max_tokens ignores cache). Default changed in suite.rs; plan updated.

## 2026-11-18 Task 9 step 2 (probe run)
Run 20261118-075106-80e879 (suite phase-3-probe in the private golden dir, 3 second-target + 5 first-target tasks, Sonnet claude-sonnet-5-5, Claude Code 2.1.327, tools core, parallel 1, limits 3 USD / 400k tokens / 15 min per task, run 2.5M tokens): done in 11 min, 3 of 8 solved, 71 builds, 80 tool calls, input 150, output 62 767, cache read 1 258 902, cache write 156 805, estimated 1.38 USD, wall 660 s. Per-task table in docs/parity/phase-3.md.
Setup: first target copied (cache only nachbau, copy takes about 25 min because of 4000 archive dirs), migrated and built in Temp\bench-real (first-ws: 650 functions, 618 identical); second target reused (ws). User config in appdata2 with --model claude-sonnet-5-5; parent Claude env vars removed.
Problems for step 3: agents stop on their own after 5-19 builds with a nonidentical best (distance 1, 4, 20, 42, 105 for the five unsolved) although 40 builds / 80 calls / 15 min were allowed; prompt never says to continue until identical. Driver.log empty, no rate_limit_event kept, so window utilisation unknown. Step 3 and 4 not run (no extra tokens).

## 2026-11-18 Task 9 step 3 (probe re-run with the continue prompt)
Run 20261118-081457-2c2c8c (same private suite, tasks 3-7, Sonnet, parallel 1, same limits): done in 10.4 min, 1 of 5 solved (task 3: 71 -> 0), others best distance 103, 1, 1, 1 (before: 105, 1, 4, 42). 70 builds, 71 calls, input 150, output 68 412, cache read 1 936 310, cache write 149 195, estimated 1.475 USD, wall 626 s. Rate limit after run: 5 h 12 %, 7 d 12 %, no quota pause.
Agents still stop on their own inside the limits (4-28 of 40 builds); three stopped at distance 1. Prompt helped only partly; harness re-prompt (needs ADR 0009 change) remains the open candidate. Tables in docs/parity/phase-3.md. Step 4 (core+legacy) not run.

## 2026-11-18 Task 14 steps 1-4 (full-build throughput, R1)
Setup: copy Temp\bench-real\first-ws (first target, 49 files, 650 functions), object cache `cache/rebuild/objects`
deleted before every run, release build, `tools/measure/busy_cores.py` (machine-wide GetSystemTimes, 250 ms).
Machine now has 20 logical cores (slots = 20). First run after a fresh exe is discarded (virus scan of the new exe:
+2 s outside the build). Result unchanged in every run: 650 functions, 618 identical, 32 differ (function verdicts
and blockers equal before/after); cached objects differ only in the compiler's header time stamp (3 bytes + checksum).

Step 1, before (HEAD 74364b8; timeline from the instrumented build with the old scheduling, run tl2):
| run | wall | CPU (machine) | busy cores avg / peak | busy share | total_ms | compile | compare | record |
|---|---|---|---|---|---|---|---|---|
| before2 | 4.05 s | 34.5 s | 8.5 / 19.9 | 0.43 | 3 899 | 3 061 | 96 | 225 |
| before3 | 3.83 s | 33.6 s | 8.8 / 18.8 | 0.44 | 3 789 | 2 877 | 104 | 232 |
| tl2 (timeline) | 4.26 s | 33.9 s | 8.0 / 20.0 | 0.40 | 4 066 | 3 109 | 104 | 236 |
(before1 was 13.7 s wall with record 8 982 ms: first build on this copy after migration, rewrote outputs; not counted.)
Timeline tl2: stage 0-376 ms; compile 376-3486: request queued at 650 (274 ms plan + plugin start), jobs start
832-1074 (worker spawn), 33 jobs, longest 1 857 ms, sum of job wall 29.4 s, job CPU 18.4 s (wall > CPU: 20 workers on
20 logical cores), last job ends 2 785, then 700 ms until the compile phase ends (objects stored one after another
with fsync, plugin shutdown waiting for its pool); serial outside compile 957 ms.
Lower bound 2 814 ms = serial 957 + max(longest 1 857, 29 359 / 20 = 1 468); saturation 0.80; efficiency 0.69;
literal busy share 0.40-0.44.

Step 4 changes (each idle shown by the timeline): runners start in a thread while the sources are staged; runners
shut down in a thread, joined before the build answers; objects read and stored in the cache in parallel (rayon);
TMP dirs removed in parallel; affected output files written in parallel (same bytes, test). Not done, no idle
shown: longest-first by previous time (first start + longest job already = last end, ~2.4 s); streaming
`job_done` (remaining read/store tail ~170 ms). Remaining idle: worker spawn in unicorn-dos, request queued ->
first job start ~170-200 ms on all 20 slots (needs a warm pool before the request: protocol decision).

After (3 cold runs, c1-c3):
| run | wall | CPU | busy avg / peak | busy share | total_ms | compile | lower bound | saturation | efficiency |
|---|---|---|---|---|---|---|---|---|---|
| c1 | 3.27 s | 34.4 s | 10.5 / 18.5 | 0.53 | 3 172 | 2 386 | 2 696 | 0.813 | 0.850 |
| c2 | 3.23 s | 33.3 s | 10.3 / 19.8 | 0.52 | 3 184 | 2 412 | 2 707 | 0.798 | 0.850 |
| c3 | 3.23 s | 32.2 s | 10.0 / 19.1 | 0.50 | 3 130 | 2 386 | 2 654 | 0.795 | 0.848 |
Median: wall 3.23 s (before 3.8-4.3), saturation 0.80, efficiency 0.85 (before 0.69), busy share 0.52 (before 0.43).
Decision 5 (saturation >= 0.90 and efficiency >= 0.85) open with the owner: efficiency met at the edge, saturation
not (worker start-up). Step 5 not run.

## 2026-11-18 Task 14 steps 2, 5, 6
Owner decision 5: saturation excludes worker start-up (request sent until first job start); efficiency >= 0.85 stays.
Implemented in schedule.rs (intervals before the first job start skipped), synthetic test
`worker_start_up_is_not_counted_in_saturation`; plan decision 5 and Task 14 interface text updated.
Step 5 (release, plugin override to the worktree unicorn-dos in first-ws decovery.toml, restored afterwards; first run
after the new exe discarded; objects cache deleted before each cold run; 650 functions, 618 identical every run):
| run | wall | CPU | busy avg / peak | lower bound | saturation | efficiency |
|---|---|---|---|---|---|---|
| cold 1 | 3.25 s | 33.6 s | 10.3 / 19.8 | 2 713 | 0.919 | 0.857 |
| cold 2 | 3.66 s | 35.7 s | 9.8 / 19.9 | 2 787 | 0.884 | 0.813 |
| cold 3 | 3.23 s | 33.2 s | 10.3 / 19.4 | 2 650 | 0.904 | 0.832 |
| cold 4-6 | 3.44 / 3.44 / 3.65 s | 31-37 s | 9.1-10.2 | 2 722-2 867 | 0.797 / 0.894 / 0.878 | 0.814 / 0.856 / 0.821 |
| warm | 1.02 s | 5.3 s | 5.2 / 6.6 | 756 | none | 0.914 |
Median cold (runs 1-3): saturation 0.904 (met at the edge), efficiency 0.832 (below 0.85; six-run median 0.827).
Details in docs/parity/phase-3.md. Step 6 (commit) done as the two commits listed in the final report.

## 2026-11-18 Bridge, exemplar and line-mapping runs (Task 9 steps 4-5, Task 13 step 6, Task 16 step 4)
5 task runs of the 16 allowed (Sonnet claude-sonnet-5-5, `--parallel 1`, probe limits). No quota pause; 5 h window 57-62 %, 7 d 18-19 %.
A (run 20261118-141041): 1 task `core+legacy` (first target Q1): solved, 2 builds, 4 calls, 0.031 USD, 18 s, searches 0.
Bridge never called, so first-call time measured by hand in the kept copy: 45 s; copy 1 942 files 60.3 MB -> 2 145 files
75.4 MB after the shadow; no Ghidra project in the legacy source cache; leak scan of copy + legacy view + shadow: no hit.
B skipped: no bench switch hides exemplars (needs facade + bench setting).
C (run 20261118-141310): v2 metadata made first with `analyze --function` (ghidra plugin added to the private user
config, 1.5 + 0.9 min, no tokens); 4 unsolved probe tasks: 2 of 4 solved (before 0 of 4), builds 63 -> 104, calls 60 -> 97,
cost 1.32 -> 2.22 USD; confounded by the harness continuation. Step 5 extrapolation: core 28.9 USD for 60 task runs,
core+legacy about the same, both about 58 USD, about 6.5 h. Ticked: Task 9 steps 4, 5. Task 16 step 4 only partly; Task 13 step 6 open.

