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
