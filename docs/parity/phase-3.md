# Parity phase 3: benchmark

Numbers only; no function names, no private paths. Private suite and run records stay outside the repository.

## Probe run (Task 9 step 2, 2026-11-18)

One run of 8 tasks with the reference driver (Claude Code 2.1.327 on the owner's subscription, model
`claude-sonnet-5-5`), `--parallel 1`, `tools = "core"`, start point stub, seed 0.
Limits per task: `max_cost_usd` 3.0, `max_tokens` 400 000, `max_builds` 40, `max_tool_calls` 80, `wall_minutes` 15.
Run limit: `--max-total-tokens 2 500 000`. Run state: done, 11 min wall. Not repeated; steps 3 and 4 not run yet.

Selection: first target (Watcom 9.5) from the identical, non-assembler rebuild records (347) sorted by size in bytes
(the record carries no instruction count; bytes stand in): one at the 3rd percentile plus one each at 12.5, 37.5, 62.5
and 87.5 % (the midpoints of the quartiles). Second target (Turbo C 2.0, 14 candidates): 25, 50, 75 %.

| Task | Class | Bytes | Solved | Start -> best distance | Builds | Calls | Calls by tool | Input | Output | Cache read | Cache write | Est. cost USD | Wall s | Turns | Exit |
| --- | --- | ---: | --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 0 | first, small | 32 | yes | 8 -> 0 | 1 | 3 | build 1, history 1, show 1 | 6 | 479 | 19 660 | 11 253 | 0.052 | 25.7 | 4 | ok |
| 1 | first, Q1 | 48 | yes | 10 -> 0 | 2 | 5 | build 1, find 1, history 1, show 2 | 8 | 745 | 38 095 | 5 754 | 0.034 | 27.0 | 6 | ok |
| 2 | first, Q2 | 112 | yes | 43 -> 0 | 14 | 17 | build 8, diagnose 1, find 5, history 1, show 2 | 30 | 8 358 | 288 986 | 24 504 | 0.211 | 105.5 | 18 | ok |
| 3 | first, Q3 | 224 | no | 71 -> 20 | 7 | 9 | build 6, diagnose 1, history 1, show 1 | 18 | 4 814 | 122 108 | 14 221 | 0.117 | 77.6 | 10 | ok |
| 4 | first, Q4 | 528 | no | 175 -> 105 | 5 | 8 | build 5, diagnose 1, history 1, show 1 | 16 | 6 770 | 118 059 | 16 669 | 0.146 | 92.1 | 9 | ok |
| 5 | second, Q1 | 126 | no | 57 -> 1 | 17 | 15 | build 8, diagnose 1, find 3, history 1, show 2 | 28 | 22 284 | 285 597 | 34 580 | 0.390 | 179.8 | 16 | ok |
| 6 | second, Q2 | 158 | no | 51 -> 4 | 19 | 12 | build 10, history 1, show 1 | 24 | 10 039 | 196 512 | 21 013 | 0.204 | 78.4 | 13 | ok |
| 7 | second, Q3 | 312 | no | 134 -> 42 | 6 | 11 | build 5, diagnose 2, find 1, history 1, show 2 | 20 | 9 278 | 189 885 | 28 811 | 0.227 | 73.7 | 12 | ok |
| Total | | | 3 of 8 | | 71 | 80 | | 150 | 62 767 | 1 258 902 | 156 805 | 1.381 | 659.8 | 88 | |

Means per task: 0.173 USD estimated, 82 s wall, 10 tool calls, 8.9 builds, 7.8k output tokens, 157k cache-read tokens.
Counted tokens (input + output) of the run: 62 917 against the run limit of 2 500 000; the largest task used 22 312
(limit 400 000). No task came near any limit. `searches` 0 (core tool set has no `search`).

The `builds` column is decovery's count (a build call with several variants counts each variant), so it can exceed
the build calls. Solved was decided by decovery's own comparison after the run.

Subscription window: no `rate_limit_event` is visible in the stored logs (the harness `driver.log` was empty for all
tasks and the driver keeps no stream), so the 5 h window utilisation after the run is not known. The step 1 sample
(one Opus task, 0.80 USD) showed 5 h 2 %, 7 d 11 %.

### Observations for step 3 (nothing fixed yet)

- Five of eight tasks ended with exit `ok` after only 5 to 19 builds of the 40 allowed and 8 to 15 tool calls of 80,
  well short of the wall and cost limits. The agent stopped on its own with a nonidentical best (distances 1, 4, 20, 42,
  105). The prompt names the limits but never says to continue until the verdict is identical or a limit is reached.
  This, not cost, is what limits the solve rate; the probe cost 1.38 USD of an allowance of 24 USD.
- The two near misses (best distance 1 and 4) stopped with budget left: a nudge in the prompt, or the harness
  re-prompting after a nonidentical end while limits remain, is the candidate fix.
- `driver.log` is empty and the driver keeps neither the stream nor the `rate_limit_event`; the run record has no
  window utilisation. Consider having the driver write the last `rate_limit_info` into `driver_extra`.
- Task prompt text lists the function name and file (private run directory only); expected, but remember it when
  sharing run directories.
- `max_builds` 40 and `max_tool_calls` 80 are suite defaults carried over from step 1; the plan fixes no probe value
  for them.
- Candidate pool of the second target is small (14), so three tasks span 25 to 75 % coarsely.

## Fixes after the probe (Task 9 step 3, 2026-11-18)

- **Prompt change** (`crates/decovery-bench/src/prompt.md`, the default task prompt): added after the limits
  paragraph:

  > The goal is a byte-identical build. Keep iterating (diagnose, adjust, rebuild) until the verdict is identical or
  > a limit is reached; do not stop while budget remains. When progress stalls, try a different approach, for example
  > find similar or diagnose.

  Results of runs before this change are not directly comparable with later ones.
- **Harness resume not added**: ADR 0009 defines `--resume <run-id>` only for runs paused on `quota`, and the Claude
  driver runs with `--no-session-persistence`, so re-prompting the same agent session after a nonidentical end would
  need a driver contract change (an ADR). Left open; the prompt change is tried first.
- **Quota data**: `tools/bench-drivers/claude_code.py` writes the last `rate_limit_event` `rate_limit_info`
  (`status`, `unifiedWindows`) as `rate_limit` into its result; the harness stores it under the task's
  `driver_extra`.
- **Run directories are private**: a run directory (including `prompt.md`, which names the function and file, and
  the logs) holds material derived from the private target and is never shared or committed.

## Re-run after the prompt fix (Task 9 step 3, 2026-11-18)

One re-run (run 20261118-081457-2c2c8c) of the five tasks left unsolved by the probe (3 to 7), same suite, driver
(Claude Code 2.1.327, `claude-sonnet-5-5`), start point, seed 0, `--parallel 1` and limits as the probe, with the
continue paragraph in the prompt. Run state: done, 10.4 min wall. Not repeated.

| Task | Solved | Start -> best distance | Builds | Calls | Calls by tool | Input | Output | Cache read | Cache write | Est. cost USD | Wall s | Turns | Exit | Rate limit 5 h / 7 d |
| --- | --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| 3 | yes | 71 -> 0 | 7 | 11 | build 6, diagnose 2, history 2, show 1 | 24 | 5 552 | 185 886 | 18 974 | 0.150 | 91.0 | 12 | ok | 9 % / 12 % |
| 4 | no | 175 -> 103 | 4 | 7 | build 4, find 1, history 1, show 1 | 14 | 5 131 | 92 950 | 13 548 | 0.115 | 81.5 | 8 | ok | 9 % / 12 % |
| 5 | no | 57 -> 1 | 10 | 10 | build 7, diagnose 1, find 1, show 1 | 22 | 12 327 | 173 044 | 21 382 | 0.226 | 103.3 | 11 | ok | 10 % / 12 % |
| 6 | no | 51 -> 1 | 21 | 16 | build 12, diagnose 1, history 2, show 1 | 34 | 13 372 | 313 909 | 26 041 | 0.269 | 103.6 | 17 | ok | 10 % / 12 % |
| 7 | no | 134 -> 1 | 28 | 27 | build 18, detail 1, diagnose 1, find 2, history 3, show 1, status 1 | 56 | 32 030 | 1 170 521 | 69 250 | 0.714 | 246.3 | 28 | ok | 12 % / 12 % |
| Total | 1 of 5 | | 70 | 71 | | 150 | 68 412 | 1 936 310 | 149 195 | 1.475 | 625.6 | 76 | | |

Before / after for the same five tasks (probe -> re-run):

| Task | Best distance | Builds | Calls | Est. cost USD |
| --- | --- | ---: | ---: | ---: |
| 3 | 20 -> 0 (solved) | 7 -> 7 | 9 -> 11 | 0.117 -> 0.150 |
| 4 | 105 -> 103 | 5 -> 4 | 8 -> 7 | 0.146 -> 0.115 |
| 5 | 1 -> 1 | 17 -> 10 | 15 -> 10 | 0.390 -> 0.226 |
| 6 | 4 -> 1 | 19 -> 21 | 12 -> 16 | 0.204 -> 0.269 |
| 7 | 42 -> 1 | 6 -> 28 | 11 -> 27 | 0.227 -> 0.714 |
| Total | 1 of 5 solved (was 0 of 5) | 54 -> 70 | 55 -> 71 | 1.084 -> 1.475 |

With the first run's three solved tasks the probe now stands at 4 of 8 (the three earlier solves were not repeated).
Subscription window after the run: 5 h utilisation 12 %, 7 d 12 % (status `allowed` throughout); no quota pause.

Observations:
- The prompt change helped on two tasks: task 7 went on for 28 builds (6 before) and ended one step from identical,
  task 3 was solved. Task 6 improved from distance 4 to 1.
- All five runs still ended with exit `ok` on their own and well inside the limits (4 to 28 of 40 builds, 7 to 27 of
  80 calls, at most 4.1 min of 15, at most 0.71 of 3 USD). Task 4 (distance 103) and task 5 (distance 1, fewer builds
  than before) stopped early again, so the prompt alone does not make the agent persist. The harness re-prompt that
  was left open in the fixes section is the remaining candidate.
- Three of the four unsolved tasks stopped at distance 1: a near-identical result is the usual stopping point.
- Cost per task rose from 0.22 to 0.30 USD estimated (mean over these five); the re-run used 1.47 USD of the 24 USD
  allowance. `rate_limit` is now recorded in `driver_extra`.

## Harness continuation (Task 9 step 3, 2026-11-18)

Because the prompt alone did not keep the agent going, the harness now continues an agent that ends with exit `ok`,
unsolved and with budget left (ADR 0009 decision 10): it starts the driver again in the same copy with a short
continuation prompt in front of the task prompt, at most `max_continuations` times per task (suite `[defaults]`,
default 1, 0 disables). Builds, tool calls, tokens, cost and wall time are totals over all sessions of a task and the
limits apply to those totals; the task record has `continuations`. Each continuation is a fresh Claude Code session
(`--no-session-persistence` stays); `tools/bench-drivers/claude_code.py` needed no change, it only receives a
different prompt file and the remaining token, cost and wall budget.

Results of runs after this change are not comparable with the probe and the re-run above (both were single-session
runs); compare later runs only with runs that use the same `max_continuations`.

## Build throughput (Task 14, 2026-11-18)

First target (49 source files, 650 functions, 618 identical, 32 differ; result unchanged in every run), release
build, object cache deleted before each cold run, 20 logical cores (20 job slots), machine-wide busy cores sampled
every 250 ms. The first run after a new executable is discarded (virus scan of the new exe).

Before the idle fixes (3 cold runs): wall 3.8-4.3 s, machine CPU 34 s, busy cores average 8.0-8.8 (share 0.40-0.44),
lower bound 2.81 s, saturation 0.80 (with worker start-up), efficiency 0.69.

After the idle fixes, rule of owner decision 5 (worker start-up, request sent until first job start, not counted in
saturation; efficiency >= 0.85):

| run | wall | CPU | busy avg / peak | busy share | lower bound | saturation | efficiency |
|---|---|---|---|---|---|---|---|
| cold 1 | 3.25 s | 33.6 s | 10.3 / 19.8 | 0.52 | 2 713 ms | 0.919 | 0.857 |
| cold 2 | 3.66 s | 35.7 s | 9.8 / 19.9 | 0.49 | 2 787 ms | 0.884 | 0.813 |
| cold 3 | 3.23 s | 33.2 s | 10.3 / 19.4 | 0.51 | 2 650 ms | 0.904 | 0.832 |
| cold 4 | 3.44 s | 31.3 s | 9.1 / 16.2 | 0.46 | 2 722 ms | 0.797 | 0.814 |
| cold 5 | 3.44 s | 34.6 s | 10.0 / 18.8 | 0.50 | 2 757 ms | 0.894 | 0.856 |
| cold 6 | 3.65 s | 37.2 s | 10.2 / 19.5 | 0.51 | 2 867 ms | 0.878 | 0.821 |
| warm | 1.02 s | 5.3 s | 5.2 / 6.6 | 0.26 | 756 ms | none (no job) | 0.914 |

Median of the first three cold runs: wall 3.25 s, saturation 0.904, efficiency 0.832 (busy share 0.51). Median of
all six: saturation 0.889, efficiency 0.827. Longest job about 1.9-2.0 s, job wall 29-32 s, job CPU 18-20 s.

Verdict: saturation >= 0.90 is met at the edge (0.904 over three runs, 0.889 over six; individual runs 0.80-0.92);
efficiency >= 0.85 is not met on the median (0.83; two of six runs reach 0.856, the 2026-11-18 morning runs
reached 0.85, so the figure sits on the criterion and moves with machine noise). The wall time is about 0.5 s above
the lower bound (first job starts 0.45-0.57 s after the build begins, objects stored after the last job).
Link times were not measured.

## Acceptance suite (Task 15, 2026-11-18)

Suite of 30 tasks (owner decision: 30, not 50): all 14 identical functions of the second target (size quartiles
of 4, 3, 4 and 3 tasks) and 16 of the first target (4 per size quartile, by bytes), no assembler sources. Two runs,
reference driver (Claude Code 2.1.327, `claude-sonnet-5-5`), `tools = "core"`, `--parallel 1`, seed 0, limits per
task 3 USD, 400 000 tokens, 15 min, 40 builds, 80 tool calls, `max_continuations` 1, run limit 3 000 000 tokens.
Both runs state done, no quota pause.

| | Run 1 | Run 2 |
| --- | ---: | ---: |
| Solved | 19 of 30 (0.633, CI 0.455-0.781) | 19 of 30 (0.633, CI 0.455-0.781) |
| First target | 10 of 16 | 10 of 16 |
| Second target | 9 of 14 | 9 of 14 |
| Median builds / tool calls | 12 / 13.5 | 13 / 14.5 |
| Median cost USD (est.) / mean | 0.29 / 0.44 | 0.27 / 0.52 |
| Median wall s / mean | 104 / 159 | 103 / 194 |
| Median output tokens | 13 059 | 11 823 |
| Total builds / tool calls | 498 / 560 | 531 / 594 |
| Total est. cost USD | 13.20 | 15.71 |
| Total wall | 80 min | 97 min |
| Exits | 26 ok, 4 call-limit | 25 ok, 5 call-limit |
| Continuations used | 11 | 11 |

Solved by size quartile (run 1 / run 2), first target: Q1 3 / 4, Q2 4 / 3, Q3 2 / 1, Q4 1 / 2; second target: Q1 4 / 3,
Q2 2 / 3, Q3 3 / 3, Q4 0 / 0. Calls over both runs by tool: build 678, show 123, find 131, history 101, diagnose 90,
detail 23, status 6, analyze 2.

`bench compare` (paired by task, B minus A): solved +0.000 [-0.167, +0.167]; builds +1.1 [-1.9, +3.7]; calls
+1.1 [-1.2, +3.5]; cost +0.084 USD [-0.015, +0.193]; wall +35 s [-0.4, +73.6]; output tokens +5 030 [+24, +10 764]
(the only interval that excludes 0). Verdict: the success rate is reproducible (same count, same groups); output
tokens differ slightly between runs, so "consistent within noise" holds for every metric except output tokens.
Four tasks per quartile make the per-quartile figures anecdotal.

## Exemplars in `show` (Task 15 step 3, 2026-11-18)

`decovery show` in the first-target workspace (release executable, 650 functions, 618 identical) on 10 functions: 8 of
the 16 first-target acceptance tasks that were unsolved in at least one of the two runs (4 unsolved in both runs, 4 in
one) and the 2 smallest of the 32 functions that still differ (355 and 414 bytes). The list of acceptance tasks that
no run solved has only 4 members, so the set is topped up with differing functions. Result: all 10 list exemplars,
3 of 3 requested in each case (summary line `exemplars: name (similarity), ...` and `data.exemplars`). Over the 8
bench-unsolved functions the top exemplar's window-coverage score ranges from 0.00 to 0.40 and its similarity from
0.27 to 0.67; no top exemplar is a twin. Six of the smallest differing functions were tried, all list 3 of 3. Low scores are normal for unsolved functions: the index holds only identical C
functions, and the exemplars shown are the nearest ones, not close matches.

Exemplar parity with Decomp's `nachbau vorbilder` (Task 13 step 5, local test, 20 not-identical functions of the
first target): top 1 equal in 18 of 20 and top-3 sets sharing at least 2 members in 20 of 20 (criterion 17 of 20 each).
A first run gave 6 of 20: iced-x86 prints `jmp short N` where capstone prints `jmp N`; after dropping the `short` and
`near` qualifiers (index schema 2) the figure is 18 of 20 and 20 of 20. In the 2 misses Decomp printed nothing, most
likely because its engine finds no function start there. R4 is met.

Task 13 step 6 (re-run of the probe suite with exemplars, `bench compare` against the Task-9 run) was **not run** (see "Bridge, exemplar and line-mapping runs" below):
it needs model tokens and the owner's go, and the acceptance runs spent the allowance. So this document does not say
whether exemplars changed success, builds or tokens. The acceptance runs cannot answer it either: they use another
suite, another prompt (continue paragraph, one harness continuation) and no exemplar-free control. The share of tasks
that called `find similar` is also unknown: the tool-call log records `find` without the question kind (only
`diagnose` carries an operation), and the drivers kept no stream (`driver.log` is empty for all tasks). In the
acceptance runs `find` made up 131 of 1 154 agent calls (11 %); `show` made 123.

## Migration of attempt memory (Task 4)

Decomp's attempt memory and archive of the first target were migrated into the workspace (`migrate` /
`migrate-attempts`, idempotent): **66 299 attempts** in one JSON Lines shard per function and **4 049 archive entries**
(content-addressed, SHA-256 verified, links rejected). The migrated workspace used for the acceptance runs holds
66 949 attempts in 650 shards and 4 699 archive entries; the differences (650 each, equal to the function count) are
consistent with one build attempt per function recorded after the migration, not checked further. Re-running the
import adds only new lines.

## Bridge use (tool-call logs, Task 3 and Task 15 step 4)

Source: `cache/calls/<yyyy-mm>.jsonl` of every task copy of the two acceptance runs, actor `bench:<run>` (1 154 calls;
a further 142 lines are the harness's own start and final builds and are not counted). All 60 task runs used
`tools = "core"`, so there is **no bridge call at all**: `search`, `verify` and `diagnose --deep` are refused in a
`core` copy and the 2 `diagnose` calls with a registers operation were refused and counted. The data therefore say nothing about which Decomp tools matter for the port order of ADR 0008
step 3. Task 9 step 4 (one `core+legacy` task) was run afterwards, see the next section.

Native tools over both runs (calls, total seconds, median / maximum seconds per call; refusals and errors included):

| Tool | Calls | Total s | Median s | Max s | Not ok |
| --- | ---: | ---: | ---: | ---: | ---: |
| build | 678 | 698.8 | 1.01 | 2.83 | 11 refused |
| show | 123 | 4.6 | 0.012 | 0.10 | 8 error |
| find | 131 | 2.2 | 0.008 | 0.07 | 0 |
| history | 101 | 1.3 | 0.010 | 0.13 | 0 |
| diagnose | 90 | 1.5 | 0.012 | 0.05 | 2 refused |
| detail | 23 | 0.1 | 0.004 | 0.05 | 1 error |
| status | 6 | 0.1 | 0.008 | 0.02 | 0 |
| analyze | 2 | 0.4 | 0.213 | 0.22 | 2 error |

Per task (60 task runs): 19 calls, of which 11 builds. `build` takes 99 % of the agent-visible tool time.

The owner's own workspaces hold almost nothing: the first-target copy's log has 57 CLI calls (29 build, 25 show,
3 find) and the second target's 2 (1 build, 1 link); the first-target figure includes the `show` checks above. Real work
with the bridge has not yet happened since Task 3, so the port order of ADR 0008 step 3 has no usage data; more will
come from `tools = "core+legacy"` runs and from the owner's own use.

## Bridge, exemplar and line-mapping runs (Task 9 steps 4 and 5, Task 13 step 6, Task 16 step 4, 2026-11-18)

Same driver, model, limits and start point as the probe (Claude Code 2.1.327, `claude-sonnet-5-5`, `--parallel 1`, seed 0,
`max_cost_usd` 3.0, `max_tokens` 400 000, 40 builds, 80 calls, 15 min). Runs used: 5 task runs (1 + 4) of the 16
allowed. No quota pause. Subscription window after the runs: 5 h utilisation 57 % (first run) to 62 % (last), 7 d 18-19 %,
status `allowed` throughout.

### R5: one `core+legacy` task (Task 9 step 4)

One probe task (first target, quartile 1; probe run: solved, 5 calls, 0.034 USD) with
`tools = "core+legacy"`, `--keep`. Result: solved, start -> best distance 10 -> 0, 2 builds, 4 calls (build 1, find 1,
history 1, show 1), `searches` 0, 8 input / 750 output / 37 825 cache-read / 4 963 cache-write tokens, 0.031 USD
estimated, 18.4 s wall, 5 turns, 0 continuations. The agent never touched the bridge (task too easy), so a real
first-call time was measured afterwards by calling `search --strategy forms` in the kept copy by hand (no tokens):

| Measure | Value |
| --- | --- |
| Copy before the first bridge call (task copy + legacy view) | 1 942 files, 60.3 MB |
| Same after the first bridge call (shadow created, Decomp server started) | 2 145 files, 75.4 MB |
| First bridge call, wall (server start included; the call itself ended in an error because the function is already identical) | 45 s |
| `core` copy of the same task (acceptance runs) | no bridge, no shadow |

The legacy source workspace of this target holds no Ghidra project in its `cache/`, so no ~825 MB project copy was
made; the shadow adds 15 MB. A source workspace with a cached Ghidra project would add its size per task copy.
Leak scan over the whole kept task directory (copy, legacy view, shadow; 2 145 files, 75.4 MB): the whitespace-
normalised original definition and the code hash of the function appear in no file outside the rebuild record and the
analysis export; the legacy view has no `nachbau/` directory and its `nachbau.toml` has no entry of the function.
Limits of this check: it ran after the agent solved the task (the copy's `src/` holds the agent's own text), so it
shows the view and the shadow's Decomp side carry no original text, not that a pristine shadow does; the pristine
check is the test `legacy_view_has_no_trace_of_the_solution` and the `bench_local` leak scan.

### Extrapolation of the full acceptance (Task 9 step 5, from existing numbers, no tokens)

Per task of the acceptance runs (60 task runs): mean 0.48 USD, median 0.28 USD, mean wall 177 s; the probe's first run
(one session, before the prompt and continuation changes) had a mean of 0.17 USD and is too low for planning.

| Plan (30 tasks) | Runs | Task runs | Est. cost USD | Wall |
| --- | ---: | ---: | ---: | ---: |
| `core` (done) | 2 | 60 | 28.9 | 177 min |
| `core+legacy` (same tokens; one measured task cost 0.031 vs 0.034 USD for `core`) | 2 | 60 | about 29 | about 177 min + up to 45 s per task that calls the bridge (at most 45 min) |
| both | 4 | 120 | about 58 | about 6.5 h |

Disk: 60 MB per `core+legacy` copy before and 75 MB after the first bridge call on this target, so 60 copies are about
4.5 GB if all are kept (copies are removed without `--keep`). The one measured task did not use the bridge, so the
token cost of tasks that search is not measured; `search` is limited to 2 per task and a Decomp search may run for
minutes, which is not in these figures.

### Exemplar effect (Task 13 step 6): skipped

The bench has no switch that hides exemplars: they come from the exemplar index that `show` and `build` refresh, there
is no suite, tool-set or workspace setting that turns them off (a removed index is rebuilt on the next call), and
the harness only removes the function's own entry. A control arm needs a new setting in the facade and the bench (an
interface change), so the 5 x 2 comparison was not run. No tokens were spent on it.

### Line mapping (Task 16 step 4)

Before the runs the workspaces held no v2 decompile metadata (no `ranges` in `knowledge/analysis`). `analyze` with the
new Ghidra plugin (Ghidra 12.1.4, `--function` for the 4 task functions; no tokens; 1.5 min and 0.9 min) wrote the
`lines`, `signature` and `variables` files for them; the second target's analysis gained 3 files and rewrote 2 pseudo-C
files, the first target's 1. The start build of 4 of 4 tasks printed `differs near C line N`.

The 4 tasks that no earlier run solved, same suite, limits and driver, `tools = "core"`; one run (20261118-141310)
with the harness continuation (`max_continuations` 1), which the earlier runs did not have:

| Task | Solved | Start -> best distance | Builds | Calls | Calls by tool | Input | Output | Cache read | Cache write | Est. cost USD | Wall s | Turns | Cont. | Exit |
| --- | --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 4 | no | 175 -> 88 | 13 | 18 | build 11, diagnose 2, history 3, show 2 | 36 | 17 094 | 296 683 | 40 664 | 0.363 | 133 | 10 | 1 | ok |
| 5 | yes | 57 -> 0 | 32 | 28 | build 14, diagnose 2, find 5, history 5, show 2 | 52 | 35 723 | 565 530 | 66 175 | 0.679 | 284 | 20 | 1 | ok |
| 6 | no | 51 -> 3 | 40 | 29 | build 24, find 1, history 2, show 2 | 58 | 25 889 | 666 964 | 51 237 | 0.531 | 198 | 7 | 1 | call-limit |
| 7 | yes | 134 -> 0 | 19 | 22 | build 15, diagnose 2, find 2, history 1, show 2 | 42 | 30 791 | 792 686 | 66 111 | 0.652 | 236 | 23 | 0 | ok |
| Total | 2 of 4 | | 104 | 97 | | 188 | 109 497 | 2 321 863 | 224 187 | 2.224 | 851 | 60 | 3 | |

Before (the re-run after the prompt fix, single session, same four tasks) -> now:

| Task | Best distance | Builds | Calls | Est. cost USD |
| --- | --- | ---: | ---: | ---: |
| 4 | 103 -> 88 | 4 -> 13 | 7 -> 18 | 0.115 -> 0.363 |
| 5 | 1 -> 0 (solved) | 10 -> 32 | 10 -> 28 | 0.226 -> 0.679 |
| 6 | 1 -> 3 | 21 -> 40 | 16 -> 29 | 0.269 -> 0.531 |
| 7 | 1 -> 0 (solved) | 28 -> 19 | 27 -> 22 | 0.714 -> 0.652 |
| Total | 0 of 4 -> 2 of 4 solved | 63 -> 104 | 60 -> 97 | 1.324 -> 2.224 |

Reading: 2 of 4 previously unsolved tasks are now solved, but three things changed at once (line mapping, the
harness continuation, and new exemplars since the re-run), the sample is 4 tasks and one run each, and the
acceptance runs showed that a single task's outcome moves between runs. The numbers do not isolate the effect of the
line mapping; they show no harm (cost per task up from 0.33 to 0.56 USD because the agent kept going). The agent's
tool calls are logged without the question kind, so whether it used the line text is not known.
