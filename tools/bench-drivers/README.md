# Claude Code benchmark driver

`claude_code.py` implements ADR 0009 using Python 3.12+ standard-library modules
and an independently installed Claude Code CLI. It submits the harness prompt on
stdin, runs in the solution-free workspace copy, and writes an atomic schema-1
result. Only decovery determines whether the function was solved.

Task 8 is implemented and step 1 was run once by hand (2026-11-18, Claude Code
2.1.327, run 20261118-063344-b04703, one 126-byte C function: solved identical, 12
builds, 218 s, estimated 0.80 USD with `costBasis` "list"). Confirmed: the init event
offered only the 13 `mcp__decovery__*` tools, the only MCP server was `decovery`
(started with `--limits`), skills, slash commands and hooks were empty,
`apiKeySource` was "none" (subscription). All `FIELDS` names were confirmed. The
tests still use a Python fake CLI and never run the real one. Use Claude Code 2.1.325
or newer. Copies must stay outside instruction trees (the builtin plugin
`cc-plugin-agents-md` would load an `AGENTS.md` above the copy).

The per-task spending cap is the estimated cost (`max_cost_usd`, default 3 USD);
`max_tokens` is only a secondary guard because cache tokens are not counted (441k
cache-read vs 18k counted in step 1).

## One-time login (owner action)

Choose a dedicated bench profile, outside the repository. The Windows default is
`%LOCALAPPDATA%\decovery\claude-bench`. In PowerShell, log into that profile once
with the subscription account:

```powershell
$env:CLAUDE_CONFIG_DIR = Join-Path $env:LOCALAPPDATA 'decovery\claude-bench'
New-Item -ItemType Directory -Force $env:CLAUDE_CONFIG_DIR | Out-Null
claude
# Complete the interactive subscription login, then exit Claude Code.
Remove-Item Env:CLAUDE_CONFIG_DIR
```

These commands are documentation for the owner, not part of the test suite.
Use a fresh profile without user instructions, memory, hooks or plugins. Check
that inherited authentication settings do not select API-key billing during step
1. The driver does not use `--bare`, because the subscription login needs OAuth.
On other platforms the fallback profile is `~/.local/share/decovery/claude-bench`;
`--profile-dir` overrides either default.

## User configuration

Add an argv list to the decovery user TOML configuration (replace the executable
and script paths with absolute local paths). TOML literal strings preserve
Windows backslashes:

```toml
[bench.drivers.claude-code]
command = [
  'C:\Python314\python.exe',
  'D:\path\to\decovery\tools\bench-drivers\claude_code.py',
  '--prompt', '{prompt}',
  '--mcp-config', '{mcp_config}',
  '--workdir', '{workdir}',
  '--result', '{result}',
  '--seed', '{seed}',
  '--max-tokens', '{max_tokens}',
  '--max-cost-usd', '{max_cost_usd}',
  '--profile-dir', 'C:\path\to\dedicated\claude-bench',
]
env = {}
```

Optional command arguments: `--model MODEL`, `--claude PATH`. A `.py` CLI path
runs through the driver's Python interpreter, allowing the portable fake
executable in tests; otherwise it is launched directly without a shell. The
seed is accepted for contract compatibility but is not forwarded: no Claude
seed option is assumed. Empty limit placeholders mean unlimited. Zero is a
real limit. The harness owns `{wall_seconds}` and the wall-time process-tree kill;
there is no driver wall-time flag.

The child receives `CLAUDE_CONFIG_DIR` and retains the harness's `DECOVERY_ACTOR`.
The fixed system prompt is written to a temporary file. Isolation arguments are
`--strict-mcp-config`, `--tools ""`, `--allowedTools "mcp__decovery__*"`,
`--disable-slash-commands`, `--setting-sources project` and
`--no-session-persistence`. The harness must place copies outside instruction
trees and exclude project settings as specified by the plan. These flags are
covered by tests; effective isolation still needs step 1.

## Stream mapping (confirmed in step 1)

All field names and event selectors are centralized in `FIELDS` in
`claude_code.py`.

| Stream fields | Driver behavior |
| --- | --- |
| `type=system`, `subtype=init`, `model` | Model identification |
| Init `tools`, `mcp_servers` | Reserved names for the step-1 isolation inspection |
| `type=assistant`, `message.usage`, `message.id` | Sum observed usage for live token enforcement, once per message id |
| `type=result`, `usage` | Final cumulative totals replace observed totals per present field, without double counting |
| Usage `input_tokens`, `output_tokens` | Result fields with the same names |
| Usage `cache_creation_input_tokens`, `cache_read_input_tokens` | `cache_write_tokens`, `cache_read_tokens` |
| Result `total_cost_usd`, `num_turns`, optional `model` | `cost_usd`, `turns`, model override |
| Result `subtype=success` or `error_...`, `is_error`, `result`; error event `error` | Success, error diagnostics or quota classification |

Missing usage fields remain absent unless earlier assistant events supplied them;
zero-valued fields are retained. Cost is reported with `cost_kind = "estimate"`
because it is the API-equivalent estimate on a subscription.

The token limit is **input + output**, excluding cache counts, as specified by
Task 8. It is checked after each assistant event and the final result; a stop
occurs when the total **exceeds** the limit. Cache writes are still reported so
the harness can include them in its separate run-wide accounting. Cost is passed
through as `--max-budget-usd` and checked whenever a final result reports cost.
Limits depend on reported events and can overshoot by one event; the adapter
cannot estimate unreported usage or enforce cost between cost reports.

A `rate_limit_event` whose `rate_limit_info.status` is `rejected` or `exhausted` also
produces `stop = "quota"` (other statuses are ignored). Unmapped live events:
`system/thinking_tokens`, `usage.output_tokens_details.thinking_tokens`, result
`modelUsage` (the result schema has no field for thinking tokens). Usage/subscription-limit, quota and rate-limit error messages produce
`stop = "quota"`. Token and cost stops use `token-limit` and `cost-limit`.
Recognized stops exit zero so the harness can classify them from the result.
Other CLI failures, error events, malformed streams and missing final results
exit nonzero and print diagnostics to stderr; available usage is still written.
An agent's result text is never treated as a solved verdict.

On Windows, limit stops use `taskkill /T /F /PID`, with a standard-library
Toolhelp/TerminateProcess fallback for descendants when taskkill returns an
error, then direct-child termination as a last resort. POSIX uses a child
process group and `SIGKILL`. A test spawns a real fake-CLI child to verify that
limit cleanup kills descendants.

## Tests

With pytest available in the selected Python environment:

```powershell
python -m pytest tools/bench-drivers/tests -q
```

The suite uses only synthetic stream events and a small generated Python CLI.
It never searches for or runs the real `claude` executable.

Real quota wording is still unverified; the `rate_limit_event` shape was seen live only with
status `allowed` (5h window 2 %, 7d 11 %).
