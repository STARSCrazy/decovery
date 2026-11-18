# ADR 0010: Persistent jobs and cooperative cancellation

Status: accepted · 2026-11-18

## Context

Design 5.13 makes every long operation a job with persistent state in `cache/jobs/<id>/` that survives a crash or
restart and can be polled and cancelled. Phase 3 needs this for the MCP server: a `search` runs minutes to hours,
longer than a client's tool timeout, and a dying server must not lose or half-record work (Review Focus 4). No new
dependency may be added (ADR 0003): no database, no process-inspection crate.

## Decision

1. **Store layout.** One directory per job, `cache/jobs/<id>/`:
   - `job.json`: the job record `{schema: 1, id, kind, spec, state, created, started?, finished?, resumed,
     progress? {done, total?, message?}, summary?, result?, error?}`, written atomically (`write_atomic`); unknown
     keys are kept on rewrite.
   - `cancel`: an empty file; its presence asks the job to stop.
   - `run.lock`: the run lease (point 3).

   `id` is `j_` and 12 hex digits: the creation time in milliseconds, counted up while that directory exists, so
   ids are unique across processes (the directory is created with `create_dir`) and sort by creation; `job_list`
   is newest first. `kind` is the operation (`build`, `link`, `analyze`, `diagnose-deep`, `search`, `verify`) and
   `spec` its request as JSON, enough to run it again. Times are RFC 3339 UTC to the second (`now_utc`).
2. **State machine.** `queued` → `running` → `done | failed | cancelled | interrupted`. Only the process that
   holds the lease moves a job out of `running`. `interrupted` is final: the job was lost twice (point 4).
3. **Lease, not pids.** The runner of a job holds an OS file lock on `run.lock` (`File::try_lock`) for as long as
   it runs the job. The OS releases it when the process dies, however it dies; a `running` job whose lease can be
   taken has lost its process. There are no pid checks: pids are reused, and a pid cannot tell a live runner from
   a stranger.
4. **Resume rule** (applied by the job runner of Task 11 at start). Every `queued` job, and every `running` job
   whose lease is free, is queued again. A `running` job is re-run from its `spec` with `resumed + 1`; when
   `resumed` would exceed 1 it ends `interrupted` with the error "the server stopped twice while the job ran", so a
   job that crashes its server cannot crash it forever. Resuming is cheap and does not change results:
   - builds and links take every unit they already compiled from the object cache, and their records are
     idempotent (a rebuild record is replaced, not appended to);
   - a resumed `search` is cheap because Decomp keeps a logbook of what it tried in the shadow
     (`cache/legacy/decomp/cache/nachbau/`, ADR 0007): the second run continues from it instead of starting over.
     A resumed `search --apply` applies only when its own judged candidate is better than the source at that time.
5. **Results are handles.** A finished job stores its full response as a handle (`result`) and a one-line
   `summary`; `job.json` stays small, `detail` pages the result like any other handle, and a client that lost the
   call can still fetch it.
6. **Cooperative cancellation.** Every long facade operation (`build`, `link`, `analyze`, `diagnose` with `deep`,
   `search`, `verify`) takes a `Control {progress, cancel}`; `cancel` is the plugin host's `CancelToken`. The
   job runner turns the `cancel` file into that token. Cancellation points: before compiling; during each runner
   or bridge request (the token goes into the request, the plugin host sends `$/cancel`; the bridge plugin answers
   `-32002`, kills the Decomp subprocess and, when no other run uses it, its server); after compiling; before
   recording. **Recording is never interrupted** (rebuild records, kept objects, attempts, output files, the
   program record, `search --apply` writing into `src/` and its follow-up build): a cancel that arrives during it
   takes effect after it, a cancel before it leaves the workspace unchanged. The facade reports
   `FacadeError::Cancelled`; the CLI exits with 130 and logs the call as `cancelled`.

## Consequences

- A crash leaves at most one job per process in `running` with a free lease; the next server start finds it
  without guessing from pids or timestamps.
- Cancellation is only as prompt as the next cancellation point: a runner that ignores `$/cancel` holds the
  request until its own timeout, and the compare and record steps run to the end.
- Job directories accumulate under `cache/jobs/`; like the rest of `cache/` they may be deleted when no server
  runs. Pruning old jobs is left to Task 11 or later.
- The bench copy excludes the job store (Review Focus 1): a job's spec and result may name the solution.
