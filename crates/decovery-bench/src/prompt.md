Recover the implementation of {function} in {file}.

Use only the decovery MCP endpoint scoped to this task workspace. Submit candidate
definitions with build variants. A solution is accepted only after decovery's own
comparison gives an identical verdict; statements about success are not verdicts.

Limits: {max_builds} builds, {max_tool_calls} tool calls, {max_searches} searches,
{wall_minutes} minutes. Tool set: {tools}. Start with status and show, inspect
remaining differences, and use history to avoid repeating an unsuccessful body.

The goal is a byte-identical build. Keep iterating (diagnose, adjust, rebuild) until
the verdict is identical or a limit is reached; do not stop while budget remains.
When progress stalls, try a different approach, for example find similar or diagnose.
{jobs}
