# ADR 0009: The bench driver contract

Status: accepted · 2026-11-17 · amended 2026-11-18 (decision 10, continuations)

## Context

`decovery bench run` measures how well an agent recovers solved functions from solution-free workspace copies
(phase 3, Task 5). The agent is an external program (a "driver") that we do not control: it may hang, crash or
overspend, and it may claim success. The harness must stay agent-agnostic (no driver-specific code, no model SDK
linked, ADR 0003) and must be the only party that sets a verdict (design 4, ADR 0007 decision 5).

## Decision

1. **Drivers are argv lists from the user config**, `[bench.drivers.<name>] command = [...]`, `env = {...}`; never
   shell strings. Placeholders replaced in every argument: `{prompt}`, `{mcp_config}`, `{workdir}` (the copy),
   `{result}`, `{seed}`, `{max_tokens}`, `{max_cost_usd}`, `{wall_seconds}` (empty when no limit is set).
2. **Per task, the harness writes** into `<suite dir>/bench/<run-id>/<task-key>-<repeat>/attempt-<n>/`:
   `prompt.md` (the suite prompt or the built-in one with `{function}`, `{file}`, `{max_builds}`,
   `{max_tool_calls}`, `{max_searches}`, `{wall_minutes}`, `{tools}` filled), `limits.json`
   (`{schema, max_builds, max_tool_calls, max_searches, tools}`) and `mcp.json`
   (`{"mcpServers": {"decovery": {"command": <decovery exe>, "args": ["mcp", "--workspace", <copy>, "--limits",
   <limits.json>, "--jobs", <cores / parallel>]}}}`). The driver runs with the copy as working directory and
   `DECOVERY_ACTOR=bench:<run-id>`; the harness's own builds run as `bench-harness` and spend no budget.
3. **The driver writes `{result}`** as JSON `{schema: 1, model?, input_tokens?, output_tokens?, cache_read_tokens?,
   cache_write_tokens?, cost_usd?, cost_kind?, turns?, stop?}`. `cost_kind` says what `cost_usd` is (for example
   `estimate` on a subscription). `stop` is `token-limit`, `cost-limit` or `quota` when the driver ended the agent
   for that reason. A missing or malformed result is a warning; the task becomes `driver-error` unless it timed out.
4. **Wall limit**: after `wall_minutes` the harness kills the driver's process tree (`taskkill /T /F /PID` on
   Windows, a process-group `kill -KILL -- -<pgid>` elsewhere; the child is killed directly if that fails) and
   records `exit = "timeout"`.
5. **Endpoint limits** (`decovery mcp --limits`): every tool call counts one; `build` counts max(1, variants)
   builds; `search` counts one search and its judged build is not a build. With `tools = core`, `search`, `verify`
   and `diagnose` with `deep` answer "not available in this bench run (tools = core)" and count as calls. Past a
   limit, tools answer "limit reached: <used> of <max> builds used" (tool calls, searches alike). Usage is derived
   from the copy's call log and written atomically to `<copy>/cache/bench/usage.json` after each call.
6. **Evaluation after any exit** except `quota`: the best identical attempt's archived `function.c` is spliced
   into `src/` when it differs, then the harness builds the function's file; `solved` is decovery's verdict
   `identical`, never the driver's claim. `start_distance` comes from one harness build before the driver starts;
   `best_distance` is the minimum over attempts and the final build.
7. **Exit values** of a task: `ok`, `timeout`, `driver-error`, `call-limit` (the driver ended normally after the
   endpoint refused a call with a spent limit), `token-limit`, `cost-limit`, `quota`, `not-run`.
8. **Run limits and pauses**: before starting a task the harness sums the finished tasks' tokens (input + output +
   cache writes) and cost; at `--max-total-tokens` / `--max-total-cost-usd` it starts no more tasks, leaves them
   `not-run` and ends `stopped-at-limit`. A `quota` stop pauses the run (`paused`); `--resume <run-id>` re-runs
   the quota and not-run tasks with the same run id and seed, keeps finished results, and keeps the replaced quota
   result under `previous_attempts`.
9. **Records**: `<suite dir>/bench/<run-id>.json` (`schemas/bench-run.schema.json`, `run-id` =
   `YYYYMMDD-HHMMSS-` + 6 hex), the copy's call log and usage copied beside the task's logs, copies under
   `<copies_dir>/<run-id>/` deleted unless `--keep`.
10. **Continuations** (amended 2026-11-18 after the phase-3 probe, where agents ended on their own with budget left
    and three tasks stopped at distance 1). When a driver session ends with exit `ok`, the harness judges the copy
    as in decision 6; if the verdict is not `identical`, fewer than `max_continuations` continuations ran (suite
    `[defaults]`, default 1, 0 disables) and the task's builds, tool calls, tokens (input + output), cost and wall
    time are all below their limits, it starts the same driver again in the same copy. The continuation gets
    `prompt-continuation-<n>.md` as `{prompt}`: a short note (continuation n of at most N, decovery's current
    verdict, best and start distance, builds and tool calls used, "keep going until identical or a limit") followed
    by the original task prompt. Its files are `driver-continuation-<n>.log`, `result-continuation-<n>.json` and
    `final-build-continuation-<n>.log`. Limits apply to the whole task: the endpoint keeps counting in the copy,
    and `{max_tokens}`, `{max_cost_usd}` and `{wall_seconds}` (and the harness's wall kill) carry what the earlier
    sessions left. Tokens and cost are summed over the sessions; the task's `exit` is the last session's;
    `continuations` in the task record counts the extra sessions and `session_logs` lists every driver log.
    A continuation is a **fresh agent session**, not a resumed one: drivers keep running without session
    persistence and see only the copy (its call log, attempts and archive) and the new prompt. Resuming would need
    a session id in the contract, driver-specific state outside the copy, and it replays the whole earlier
    conversation as input on every turn of the continuation, so it is not cheaper; the copy's history already
    carries what the next session needs. Runs with continuations are not comparable with runs before this
    amendment.

## Consequences

- Any agent that can speak MCP over stdio can be benchmarked through a small wrapper; the reference wrapper for
  Claude Code is Task 8's `tools/bench-drivers/claude_code.py`.
- Tokens and cost are only as good as the driver's report; the record keeps `cost_kind` so reports do not mix
  estimates with billed cost.
- Usage counting lives in one place (the call log), shared by the endpoint and the evaluation.
